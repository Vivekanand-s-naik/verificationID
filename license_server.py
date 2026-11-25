import base64
import hashlib
import hmac
import html
import json
import logging
import math
import os
import re
import secrets
import smtplib
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import bcrypt
import psycopg2
import psycopg2.extras
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
logger = logging.getLogger("license_server")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

DATABASE_URL = os.environ.get("DATABASE_URL")  # set on Render — Neon Postgres connection string
ADMIN_TOKEN = os.environ.get("LICENSE_ADMIN_TOKEN")

TRIAL_DAYS = 180
OFFLINE_LEASE_GRACE_HOURS = 72
SCREENSHOT_RATE_LIMIT_MINUTES = 10
MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024  # 5 MB
CONTACT_MESSAGE_RATE_LIMIT_MINUTES = 2
MAX_CONTACT_MESSAGE_CHARS = 1500
MAX_DIRECT_MESSAGE_CHARS = 2000
MAX_IDEMPOTENCY_KEY_CHARS = 128
CLIENT_MESSAGE_RATE_LIMIT_MAX = 20
CLIENT_MESSAGE_RATE_LIMIT_WINDOW_SECONDS = 60
_CLIENT_MESSAGE_ATTEMPTS: dict[str, list[float]] = {}
_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

ADMIN_UI_DIR = Path(__file__).resolve().parent / "admin_ui"
SESSION_COOKIE_NAME = "admin_session"
SESSION_TTL_SECONDS = int(os.environ.get("ADMIN_SESSION_TTL_SECONDS", str(4 * 3600)))
LOGIN_RATE_LIMIT_MAX_ATTEMPTS = 10
LOGIN_RATE_LIMIT_WINDOW_SECONDS = 15 * 60
_LOGIN_ATTEMPTS: dict[str, list[float]] = {}
UNKNOWN_KEY_RATE_LIMIT_MAX = 30
UNKNOWN_KEY_RATE_LIMIT_WINDOW_SECONDS = 5 * 60
_UNKNOWN_KEY_ATTEMPTS: dict[str, list[float]] = {}
EMAIL_RELAY_RATE_LIMIT_MAX = 5
EMAIL_RELAY_RATE_LIMIT_WINDOW_SECONDS = 15 * 60
_EMAIL_RELAY_ATTEMPTS: dict[str, list[float]] = {}
ACTIVATE_DEVICE_RATE_LIMIT_MAX = 30
ACTIVATE_DEVICE_RATE_LIMIT_WINDOW_SECONDS = 15 * 60
_ACTIVATE_DEVICE_ATTEMPTS: dict[str, list[float]] = {}
_KEY_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
_RESET_CODE_RE = re.compile(r"^[A-Za-z0-9-]{4,16}$")
ADMIN_PAGE_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)

DEFAULT_PLANS = {
    "monthly":   {"days": 30,  "price_inr": 150, "label": "Monthly",                "sort_order": 10},
    "quarterly": {"days": 90,  "price_inr": 300, "label": "Quarterly",              "sort_order": 20},
    "annual":    {"days": 365, "price_inr": 900, "label": "Annual",                 "sort_order": 30},
    "launch90":  {"days": 90,  "price_inr": 200, "label": "Launch Offer — 90 days", "sort_order": 5},
}
# Backward-compatible reference to initial seed plan definitions; runtime routes read `subscription_plans` DB table.
PLANS = {
    k: {"days": v["days"], "price_inr": v["price_inr"], "label": v["label"]}
    for k, v in DEFAULT_PLANS.items()
}
_PLAN_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,31}$")
VALID_BROADCAST_TONES = {"notice", "info", "warning"}

app = FastAPI(title="ANPR License & Subscription Server")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _iso_utc(dt: datetime | None) -> str | None:
    aware = _as_utc(dt)
    return aware.isoformat() if aware is not None else None


@contextmanager
def get_db():
    db_url = os.environ.get("DATABASE_URL") or DATABASE_URL
    if not db_url:
        raise RuntimeError("DATABASE_URL environment variable is not set.")
    connect_kwargs = {}
    if "sslmode=" not in db_url.lower():
        connect_kwargs["sslmode"] = "require"
    conn = psycopg2.connect(db_url, **connect_kwargs)
    conn.cursor_factory = psycopg2.extras.RealDictCursor
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS licenses (
                    license_key TEXT PRIMARY KEY,
                    status TEXT NOT NULL DEFAULT 'active',
                    device_id TEXT,
                    app_version TEXT,
                    last_seen TIMESTAMPTZ,
                    note TEXT,
                    label TEXT,
                    expires_at TIMESTAMPTZ,
                    plan TEXT NOT NULL DEFAULT 'trial',
                    has_paid_renewal BOOLEAN NOT NULL DEFAULT FALSE,
                    activated_at TIMESTAMPTZ,
                    trial_days INTEGER NOT NULL DEFAULT 180,
                    allow_repeat_trial BOOLEAN NOT NULL DEFAULT FALSE
                )
            """)
            # Idempotent column upgrades for existing Neon Postgres databases
            cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS label TEXT")
            cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ")
            cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS plan TEXT NOT NULL DEFAULT 'trial'")
            cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS has_paid_renewal BOOLEAN NOT NULL DEFAULT FALSE")
            cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ")
            cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS trial_days INTEGER NOT NULL DEFAULT 180")
            cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS allow_repeat_trial BOOLEAN NOT NULL DEFAULT FALSE")

            # Backfill NULL plan values on legacy rows (preserves all existing expires_at values)
            cur.execute("UPDATE licenses SET plan = 'trial' WHERE plan IS NULL")

            # One-time idempotent migration for VIVEK-ANPR-0001 (sets 180-day trial ONLY if expires_at is NULL)
            cur.execute(
                """
                UPDATE licenses
                SET expires_at = NOW() + INTERVAL '180 days',
                    plan = 'trial'
                WHERE license_key = 'VIVEK-ANPR-0001'
                  AND expires_at IS NULL
                """
            )

            # Persistent server-side device trial consumption history (one free trial per device)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS device_trials (
                    device_id TEXT PRIMARY KEY,
                    first_license_key TEXT NOT NULL,
                    first_activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    note TEXT
                )
            """)

            # Backward-compatible backfill for already-bound devices (never mutates existing expires_at)
            cur.execute("""
                UPDATE licenses
                SET activated_at = COALESCE(last_seen, NOW())
                WHERE device_id IS NOT NULL
                  AND activated_at IS NULL
            """)
            cur.execute("""
                INSERT INTO device_trials (device_id, first_license_key, first_activated_at, note)
                SELECT DISTINCT ON (device_id)
                    device_id,
                    license_key,
                    COALESCE(activated_at, last_seen, NOW()),
                    'Backfilled from existing bound license'
                FROM licenses
                WHERE device_id IS NOT NULL
                ORDER BY device_id, COALESCE(activated_at, last_seen, NOW()) ASC
                ON CONFLICT (device_id) DO NOTHING
            """)

            # Payment submissions stored as base64 in Postgres (Render free disk is ephemeral)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS payment_submissions (
                    id SERIAL PRIMARY KEY,
                    license_key TEXT NOT NULL REFERENCES licenses(license_key) ON DELETE CASCADE,
                    device_id TEXT NOT NULL,
                    claimed_plan TEXT NOT NULL,
                    image_data TEXT NOT NULL,
                    content_type TEXT NOT NULL DEFAULT 'image/png',
                    price_inr INTEGER,
                    days INTEGER,
                    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    status TEXT NOT NULL DEFAULT 'pending'
                )
            """)
            cur.execute("ALTER TABLE payment_submissions ADD COLUMN IF NOT EXISTS content_type TEXT NOT NULL DEFAULT 'image/png'")
            cur.execute("ALTER TABLE payment_submissions ADD COLUMN IF NOT EXISTS price_inr INTEGER")
            cur.execute("ALTER TABLE payment_submissions ADD COLUMN IF NOT EXISTS days INTEGER")
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_payment_submissions_key_time
                ON payment_submissions (license_key, submitted_at DESC)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_payment_submissions_status
                ON payment_submissions (status, submitted_at DESC)
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS admin_users (
                    id SERIAL PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    email TEXT,
                    role TEXT NOT NULL DEFAULT 'admin',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_users_lower_username
                ON admin_users (LOWER(username))
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS admin_sessions (
                    jti TEXT PRIMARY KEY,
                    user_id INTEGER,
                    username TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'owner',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    expires_at TIMESTAMPTZ NOT NULL,
                    revoked_at TIMESTAMPTZ
                )
            """)
            cur.execute("ALTER TABLE admin_sessions ADD COLUMN IF NOT EXISTS user_id INTEGER")
            cur.execute("ALTER TABLE admin_sessions ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'owner'")
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires
                ON admin_sessions (expires_at)
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS license_audit_log (
                    id SERIAL PRIMARY KEY,
                    license_key TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    previous_plan TEXT,
                    new_plan TEXT,
                    previous_expires_at TIMESTAMPTZ,
                    new_expires_at TIMESTAMPTZ,
                    previous_has_paid_renewal BOOLEAN,
                    new_has_paid_renewal BOOLEAN,
                    note TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_license_audit_log_time
                ON license_audit_log (created_at DESC)
            """)

            # Live-editable subscription plans (seeded once from DEFAULT_PLANS on first run)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS subscription_plans (
                    plan_key TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    days INTEGER NOT NULL,
                    price_inr INTEGER NOT NULL,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    sort_order INTEGER NOT NULL DEFAULT 100,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)

            # Server-to-client broadcast notifications + per-device acknowledgments
            cur.execute("""
                CREATE TABLE IF NOT EXISTS broadcast_messages (
                    id SERIAL PRIMARY KEY,
                    message TEXT NOT NULL,
                    tone TEXT NOT NULL DEFAULT 'notice',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_by TEXT NOT NULL DEFAULT 'owner'
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_broadcast_messages_active_time
                ON broadcast_messages (active, created_at DESC)
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS broadcast_acknowledgments (
                    broadcast_id INTEGER NOT NULL REFERENCES broadcast_messages(id) ON DELETE CASCADE,
                    device_id TEXT NOT NULL,
                    acknowledged_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (broadcast_id, device_id)
                )
            """)

            # Dynamic server settings (e.g. trial_days for newly auto-provisioned devices)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS system_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_by TEXT NOT NULL DEFAULT 'system'
                )
            """)

            # Two-way client-to-owner support/contact messages (separate from payment_submissions)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS contact_messages (
                    id SERIAL PRIMARY KEY,
                    license_key TEXT,
                    device_id TEXT NOT NULL,
                    message TEXT NOT NULL,
                    client_timestamp TIMESTAMPTZ,
                    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    telegram_notified BOOLEAN NOT NULL DEFAULT FALSE
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_contact_messages_device_time
                ON contact_messages (device_id, received_at DESC)
            """)

            # One-shot SystemOwner remote emergency credential provisioning per device_id
            cur.execute("""
                CREATE TABLE IF NOT EXISTS remote_credential_provisions (
                    id SERIAL PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    email TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'ADMIN',
                    must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    consumed_at TIMESTAMPTZ,
                    created_by TEXT NOT NULL DEFAULT 'owner'
                )
            """)
            cur.execute("ALTER TABLE remote_credential_provisions ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT TRUE")
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_remote_cred_provisions_device_pending
                ON remote_credential_provisions (device_id, created_at ASC)
                WHERE consumed_at IS NULL
            """)

            # Non-sensitive directory of local RBAC accounts reported per device_id (NEVER stores passwords or hashes)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS device_rbac_accounts (
                    device_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    email TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'OPERATOR',
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
                    last_synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (device_id, username)
                )
            """)

            # Persistent two-way license-linked messaging (individual conversations, separate from broadcasts)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS license_messages (
                    id SERIAL PRIMARY KEY,
                    license_key TEXT NOT NULL REFERENCES licenses(license_key) ON DELETE CASCADE,
                    sender_type TEXT NOT NULL CHECK (sender_type IN ('client', 'admin')),
                    sender_identity TEXT NOT NULL,
                    target_device_id TEXT,
                    body TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'received',
                    idempotency_key TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    delivered_at TIMESTAMPTZ,
                    read_at TIMESTAMPTZ,
                    read_by TEXT,
                    retargeted_from_device_id TEXT,
                    retargeted_by TEXT,
                    retargeted_at TIMESTAMPTZ
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_license_messages_key_created
                ON license_messages (license_key, created_at ASC, id ASC)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_license_messages_status
                ON license_messages (license_key, sender_type, status)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_license_messages_target_dev
                ON license_messages (license_key, target_device_id, status)
            """)
            cur.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS uq_license_messages_idempotency
                ON license_messages (license_key, sender_type, idempotency_key)
                WHERE idempotency_key IS NOT NULL
            """)

            _seed_default_plans(cur)
            _seed_default_system_settings(cur)
            _seed_initial_owner_user(cur)


@app.middleware("http")
async def add_admin_security_headers(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    if path.startswith(("/admin", "/api/v1/admin")):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if path in ("/admin", "/admin/", "/admin/login") and "Content-Security-Policy" not in response.headers:
            response.headers["Content-Security-Policy"] = ADMIN_PAGE_CSP
    return response


def _get_admin_token() -> str | None:
    raw = os.environ["LICENSE_ADMIN_TOKEN"] if "LICENSE_ADMIN_TOKEN" in os.environ else ADMIN_TOKEN
    return (raw or "").strip() or None


def _check_admin(token: str | None):
    expected = _get_admin_token()
    if not expected or not token or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=403, detail="Forbidden")


def _hash_password(plain_password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain_password.encode("utf-8"), salt).decode("utf-8")


def _verify_password(plain_password: str, password_hash: str | None) -> bool:
    if not plain_password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


def _get_seed_owner_credentials() -> tuple[str | None, str | None, str | None]:
    username = (os.environ.get("ADMIN_USERNAME") or "").strip()
    password = os.environ.get("ADMIN_PASSWORD") or ""
    email = (os.environ.get("ADMIN_EMAIL") or os.environ.get("LICENSE_SUPPORT_CONTACT") or "").strip() or None
    if not username or not password:
        return None, None, email
    return username, password, email


def _seed_default_plans(cur) -> bool:
    """Seed initial subscription_plans rows from DEFAULT_PLANS ONLY when the table is empty."""
    cur.execute("SELECT COUNT(*) AS cnt FROM subscription_plans")
    row = cur.fetchone()
    if int((row or {}).get("cnt", 0)) > 0:
        return False
    now = _utc_now()
    for plan_key, meta in DEFAULT_PLANS.items():
        cur.execute(
            """
            INSERT INTO subscription_plans (plan_key, label, days, price_inr, active, sort_order, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (plan_key) DO NOTHING
            """,
            (
                plan_key,
                meta["label"],
                int(meta["days"]),
                int(meta["price_inr"]),
                True,
                int(meta.get("sort_order", 100)),
                now,
            ),
        )
    logger.info("Seeded %d default subscription plans into subscription_plans.", len(DEFAULT_PLANS))
    return True


def _seed_default_system_settings(cur) -> None:
    """Seed default system_settings keys once without ever overwriting owner-configured values."""
    cur.execute(
        """
        INSERT INTO system_settings (key, value, updated_at, updated_by)
        VALUES ('trial_days', %s, %s, 'system')
        ON CONFLICT (key) DO NOTHING
        """,
        (str(TRIAL_DAYS), _utc_now()),
    )


def _get_configured_trial_days(cur) -> int:
    """Read live trial duration (in days) from `system_settings`, falling back to TRIAL_DAYS."""
    cur.execute("SELECT value FROM system_settings WHERE key = 'trial_days'")
    row = cur.fetchone()
    if row is not None:
        try:
            val = int(str(row.get("value") or "").strip())
            if 1 <= val <= 3650:
                return val
        except (TypeError, ValueError):
            pass
    return TRIAL_DAYS


def _load_plans_map(cur, include_inactive: bool = False) -> dict[str, dict]:
    """Read subscription plans from DB (auto-seeding once on an empty table)."""
    _seed_default_plans(cur)
    if include_inactive:
        cur.execute(
            """
            SELECT plan_key, label, days, price_inr, active, sort_order, updated_at
            FROM subscription_plans
            ORDER BY sort_order ASC, plan_key ASC
            """
        )
    else:
        cur.execute(
            """
            SELECT plan_key, label, days, price_inr, active, sort_order, updated_at
            FROM subscription_plans
            WHERE active = TRUE
            ORDER BY sort_order ASC, plan_key ASC
            """
        )
    rows = cur.fetchall()
    result: dict[str, dict] = {}
    for r in rows:
        pk = str(r["plan_key"]).strip().lower()
        result[pk] = {
            "days": int(r["days"]),
            "price_inr": int(r["price_inr"]),
            "label": str(r["label"]),
            "active": bool(r.get("active", True)),
            "sort_order": int(r.get("sort_order", 100)),
            "updated_at": _iso_utc(r.get("updated_at")),
        }
    return result


def _public_plans_dict(plans_map: dict[str, dict]) -> dict[str, dict]:
    """Shape plan metadata for public /api/v1/plans and dashboard dropdowns."""
    return {
        pk: {
            "days": int(meta["days"]),
            "price_inr": int(meta["price_inr"]),
            "label": str(meta["label"]),
        }
        for pk, meta in plans_map.items()
    }


def _fetch_unacked_broadcasts(cur, device_id: str | None) -> list[dict]:
    """Return active broadcast messages not yet acknowledged by `device_id`."""
    dev = (device_id or "").strip()
    if not dev:
        return []
    cur.execute(
        """
        SELECT b.id, b.message, b.tone, b.created_at
        FROM broadcast_messages b
        LEFT JOIN broadcast_acknowledgments a
          ON a.broadcast_id = b.id AND a.device_id = %s
        WHERE b.active = TRUE AND a.broadcast_id IS NULL
        ORDER BY b.created_at ASC, b.id ASC
        """,
        (dev,),
    )
    rows = cur.fetchall()
    return [
        {
            "id": int(r["id"]),
            "message": str(r["message"]),
            "tone": str(r.get("tone") or "notice"),
            "created_at": _iso_utc(r.get("created_at")),
        }
        for r in rows
    ]


VALID_REMOTE_CREDENTIAL_ROLES = {"ADMIN", "OPERATOR", "AUDITOR"}


def _fetch_pending_credential_provisions(cur, device_id: str) -> list[dict]:
    """
    Return unconsumed one-shot remote credential provisions queued by SystemOwner for `device_id`,
    ordered oldest-first so sequential provisions apply deterministically.
    """
    dev = (device_id or "").strip()
    if not dev:
        return []
    cur.execute(
        """
        SELECT id, device_id, username, email, password_hash, role, must_change_password, created_at, created_by
        FROM remote_credential_provisions
        WHERE device_id = %s
          AND consumed_at IS NULL
        ORDER BY created_at ASC, id ASC
        """,
        (dev,),
    )
    rows = cur.fetchall()
    return [
        {
            "id": int(r["id"]),
            "device_id": str(r["device_id"]),
            "username": str(r["username"]),
            "email": str(r["email"]),
            "password_hash": str(r["password_hash"]),
            "role": str(r.get("role") or "ADMIN").strip().upper(),
            "must_change_password": bool(r.get("must_change_password", True)),
            "created_at": _iso_utc(r.get("created_at")),
            "created_by": str(r.get("created_by") or "owner"),
        }
        for r in rows
    ]


def _generate_one_time_password() -> str:
    """Generate a high-entropy human-typeable one-time recovery password (>= 14 chars)."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    parts = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)]
    return f"Tmp!{'-'.join(parts)}"


def _seed_initial_owner_user(cur) -> bool:
    """
    One-time bootstrap seed: if admin_users is completely empty and ADMIN_USERNAME /
    ADMIN_PASSWORD are provided in the environment, create the initial SystemOwner (`owner`)
    account with a bcrypt password hash. Never overwrites existing accounts.
    """
    cur.execute("SELECT COUNT(*) AS cnt FROM admin_users")
    row = cur.fetchone()
    existing_count = int((row or {}).get("cnt", 0))
    if existing_count > 0:
        return False

    seed_user, seed_pass, seed_email = _get_seed_owner_credentials()
    if not seed_user or not seed_pass:
        return False

    now = _utc_now()
    pw_hash = _hash_password(seed_pass)
    cur.execute(
        """
        INSERT INTO admin_users (username, password_hash, email, role, created_at, updated_at)
        VALUES (%s, %s, %s, 'owner', %s, %s)
        """,
        (seed_user, pw_hash, seed_email, now, now),
    )
    logger.info("Seeded initial SystemOwner account '%s' into admin_users.", seed_user)
    return True


def _get_session_signing_key() -> bytes:
    secret = (os.environ.get("ADMIN_SESSION_SECRET") or _get_admin_token() or "").strip()
    if not secret:
        raise HTTPException(status_code=503, detail="Admin authentication is not configured.")
    return hashlib.sha256(f"anpr-admin-session-v1:{secret}".encode("utf-8")).digest()


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(val: str) -> bytes:
    padded = val + ("=" * (-len(val) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _sign_session_token(
    username: str,
    jti: str,
    issued_at: datetime,
    expires_at: datetime,
    role: str = "owner",
    user_id: int | None = None,
) -> str:
    key = _get_session_signing_key()
    header_b64 = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode("utf-8"))
    payload = {
        "sub": username,
        "role": (role or "owner").strip().lower(),
        "jti": jti,
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    if user_id is not None:
        payload["uid"] = int(user_id)
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(sig)}"


def _decode_session_token(token: str, verify_exp: bool = True) -> dict | None:
    if not token or not isinstance(token, str) or token.count(".") != 2:
        return None
    header_b64, payload_b64, sig_b64 = token.split(".", 2)
    try:
        key = _get_session_signing_key()
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected_sig = hmac.new(key, signing_input, hashlib.sha256).digest()
        provided_sig = _b64url_decode(sig_b64)
        if not hmac.compare_digest(provided_sig, expected_sig):
            return None
        header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception:
        return None

    if not isinstance(header, dict) or header.get("alg") != "HS256" or header.get("typ") != "JWT":
        return None
    if not isinstance(payload, dict):
        return None

    sub = payload.get("sub")
    jti = payload.get("jti")
    iat = payload.get("iat")
    exp = payload.get("exp")
    if not isinstance(sub, str) or not sub or not isinstance(jti, str) or not jti:
        return None
    if not isinstance(iat, int) or isinstance(iat, bool) or not isinstance(exp, int) or isinstance(exp, bool):
        return None
    if verify_exp and int(_utc_now().timestamp()) >= exp:
        return None
    return payload


def _verify_active_session(token: str | None) -> dict | None:
    if not token:
        return None
    payload = _decode_session_token(token, verify_exp=True)
    if payload is None:
        return None

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT jti, user_id, username, role, expires_at, revoked_at FROM admin_sessions WHERE jti = %s",
                (payload["jti"],),
            )
            row = cur.fetchone()
            if row is None or row.get("revoked_at") is not None:
                return None
            expires_at = _as_utc(row.get("expires_at"))
            if expires_at is None or expires_at <= _utc_now():
                return None
            if not hmac.compare_digest(str(row.get("username") or ""), payload["sub"]):
                return None

            user_id = row.get("user_id") if row.get("user_id") is not None else payload.get("uid")
            email = None
            role = (row.get("role") or payload.get("role") or "owner").strip().lower()
            username = str(row["username"])
            if user_id is not None:
                cur.execute(
                    "SELECT id, username, email, role FROM admin_users WHERE id = %s",
                    (int(user_id),),
                )
                u_row = cur.fetchone()
                if u_row is None:
                    return None
                username = str(u_row["username"])
                email = u_row.get("email")
                role = (u_row.get("role") or role).strip().lower()
            else:
                cur.execute(
                    "SELECT id, username, email, role FROM admin_users WHERE LOWER(username) = LOWER(%s)",
                    (username,),
                )
                u_row = cur.fetchone()
                if u_row is not None:
                    user_id = int(u_row["id"])
                    username = str(u_row["username"])
                    email = u_row.get("email")
                    role = (u_row.get("role") or role).strip().lower()

    return {
        "jti": row["jti"],
        "user_id": int(user_id) if user_id is not None else None,
        "username": username,
        "email": email,
        "role": role,
        "expires_at": _iso_utc(expires_at),
    }


def _extract_session_token(request: Request) -> tuple[str | None, str | None]:
    auth_hdr = request.headers.get("authorization")
    if auth_hdr is not None:
        parts = auth_hdr.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1].strip():
            return parts[1].strip(), "header"
        return "", "header"
    cookie_val = request.cookies.get(SESSION_COOKIE_NAME)
    if cookie_val is not None:
        return cookie_val, "cookie"
    return None, None


def _is_https_request(request: Request) -> bool:
    forwarded_proto = (request.headers.get("x-forwarded-proto") or "").split(",", 1)[0].strip().lower()
    return request.url.scheme == "https" or forwarded_proto == "https"


def _client_ip(request: Request) -> str:
    forwarded_for = (request.headers.get("x-forwarded-for") or "").split(",", 1)[0].strip()
    if forwarded_for:
        return forwarded_for
    return request.client.host if request.client else "unknown"


def _prune_login_attempts(ip: str, now_ts: float) -> list[float]:
    cutoff = now_ts - LOGIN_RATE_LIMIT_WINDOW_SECONDS
    recent = [ts for ts in _LOGIN_ATTEMPTS.get(ip, []) if ts > cutoff]
    if recent:
        _LOGIN_ATTEMPTS[ip] = recent
    else:
        _LOGIN_ATTEMPTS.pop(ip, None)
    return recent


def _check_login_rate_limit(ip: str):
    recent = _prune_login_attempts(ip, time.monotonic())
    if len(recent) >= LOGIN_RATE_LIMIT_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts. Please try again later.",
        )


def _record_login_failure(ip: str):
    now_ts = time.monotonic()
    recent = _prune_login_attempts(ip, now_ts)
    recent.append(now_ts)
    _LOGIN_ATTEMPTS[ip] = recent


def _clear_login_failures(ip: str):
    _LOGIN_ATTEMPTS.pop(ip, None)


def _generate_secure_license_key() -> str:
    """Generate a high-entropy (80-bit) license key using OS CSPRNG."""
    groups = ["".join(secrets.choice(_KEY_ALPHABET) for _ in range(4)) for _ in range(4)]
    return "ANPR-" + "-".join(groups)


def _load_ed25519_private_key() -> Ed25519PrivateKey | None:
    """
    Load the Ed25519 offline-lease signing key from LICENSE_SIGNING_PRIVATE_KEY_B64
    (kept exclusively on the server / Render env vars — NEVER distributed to clients).
    Accepts either standard base64 of the raw 32-byte Ed25519 private seed or PEM.
    """
    raw_b64 = (os.environ.get("LICENSE_SIGNING_PRIVATE_KEY_B64") or "").strip()
    if not raw_b64:
        return None
    try:
        if raw_b64.startswith("-----BEGIN"):
            key_obj = serialization.load_pem_private_key(raw_b64.encode("utf-8"), password=None)
            if isinstance(key_obj, Ed25519PrivateKey):
                return key_obj
            return None
        raw_bytes = base64.b64decode(raw_b64)
        if len(raw_bytes) == 32:
            return Ed25519PrivateKey.from_private_bytes(raw_bytes)
        key_obj = serialization.load_der_private_key(raw_bytes, password=None)
        if isinstance(key_obj, Ed25519PrivateKey):
            return key_obj
    except Exception as exc:
        logger.error("Failed to load LICENSE_SIGNING_PRIVATE_KEY_B64: %s", exc)
    return None


def _sign_offline_lease(
    *,
    license_key: str,
    device_id: str,
    plan: str,
    expires_at: datetime | None,
    issued_at: datetime,
    grace_hours: float = OFFLINE_LEASE_GRACE_HOURS,
) -> dict | None:
    """
    Create an Ed25519-signed offline lease token bound to this exact device_id,
    license_key SHA-256 hash, plan, subscription expiry, issue timestamp, and
    offline grace expiry (capped at min(issued_at + grace_hours, expires_at)).
    """
    priv = _load_ed25519_private_key()
    if priv is None:
        logger.warning(
            "LICENSE_SIGNING_PRIVATE_KEY_B64 is not configured; returning active response without offline_lease."
        )
        return None

    issued_utc = _as_utc(issued_at) or _utc_now()
    issued_epoch = int(issued_utc.timestamp())
    exp_utc = _as_utc(expires_at)
    exp_epoch = int(exp_utc.timestamp()) if exp_utc is not None else None
    grace_cap = issued_epoch + int(max(1.0, float(grace_hours)) * 3600)
    grace_until_epoch = min(grace_cap, exp_epoch) if exp_epoch is not None else grace_cap
    grace_until_utc = datetime.fromtimestamp(grace_until_epoch, tz=timezone.utc)

    claims = {
        "v": 1,
        "device_id": device_id,
        "license_key_sha256": hashlib.sha256(license_key.strip().encode("utf-8")).hexdigest(),
        "plan": plan,
        "expires_at": exp_utc.isoformat() if exp_utc is not None else None,
        "expires_at_epoch": exp_epoch,
        "issued_at": issued_utc.isoformat(),
        "issued_at_epoch": issued_epoch,
        "grace_until": grace_until_utc.isoformat(),
        "grace_until_epoch": grace_until_epoch,
    }
    payload_bytes = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig_bytes = priv.sign(payload_bytes)
    return {
        "alg": "Ed25519",
        "payload_b64": base64.b64encode(payload_bytes).decode("ascii"),
        "signature_b64": base64.b64encode(sig_bytes).decode("ascii"),
    }


def _record_and_check_unknown_key_rate_limit(ip: str) -> None:
    """Rate-limit brute-force enumeration of unknown/invalid license keys per client IP."""
    now_ts = time.monotonic()
    cutoff = now_ts - UNKNOWN_KEY_RATE_LIMIT_WINDOW_SECONDS
    recent = [ts for ts in _UNKNOWN_KEY_ATTEMPTS.get(ip, []) if ts > cutoff]
    recent.append(now_ts)
    _UNKNOWN_KEY_ATTEMPTS[ip] = recent
    if len(recent) > UNKNOWN_KEY_RATE_LIMIT_MAX:
        raise HTTPException(
            status_code=429,
            detail="Too many invalid license validation attempts. Please try again later.",
        )


def _check_and_record_email_relay_rate_limit(license_key: str) -> None:
    """Rate-limit server-side password-reset email relay per activated license key."""
    now_ts = time.monotonic()
    cutoff = now_ts - EMAIL_RELAY_RATE_LIMIT_WINDOW_SECONDS
    recent = [ts for ts in _EMAIL_RELAY_ATTEMPTS.get(license_key, []) if ts > cutoff]
    if len(recent) >= EMAIL_RELAY_RATE_LIMIT_MAX:
        raise HTTPException(
            status_code=429,
            detail="Too many password reset emails sent recently. Please wait before trying again.",
        )
    recent.append(now_ts)
    _EMAIL_RELAY_ATTEMPTS[license_key] = recent


def _check_and_record_activate_device_rate_limit(ip: str) -> None:
    """Rate-limit newly auto-provisioned device activations per IP to prevent DB flooding."""
    now_ts = time.monotonic()
    cutoff = now_ts - ACTIVATE_DEVICE_RATE_LIMIT_WINDOW_SECONDS
    recent = [ts for ts in _ACTIVATE_DEVICE_ATTEMPTS.get(ip, []) if ts > cutoff]
    if len(recent) >= ACTIVATE_DEVICE_RATE_LIMIT_MAX:
        raise HTTPException(
            status_code=429,
            detail="Too many new device activations from this network recently. Please try again later.",
        )
    recent.append(now_ts)
    _ACTIVATE_DEVICE_ATTEMPTS[ip] = recent


def _check_and_record_client_message_rate_limit(bucket_key: str) -> None:
    """Rate-limit client message submissions per authenticated (license_key, device_id)."""
    now_ts = time.monotonic()
    cutoff = now_ts - CLIENT_MESSAGE_RATE_LIMIT_WINDOW_SECONDS
    recent = [ts for ts in _CLIENT_MESSAGE_ATTEMPTS.get(bucket_key, []) if ts > cutoff]
    if len(recent) >= CLIENT_MESSAGE_RATE_LIMIT_MAX:
        raise HTTPException(
            status_code=429,
            detail="Too many messages sent recently. Please wait a moment before sending another.",
        )
    recent.append(now_ts)
    _CLIENT_MESSAGE_ATTEMPTS[bucket_key] = recent


def _validate_message_body(raw_body: str | None) -> str:
    if raw_body is None or "\x00" in raw_body:
        raise HTTPException(status_code=400, detail="Invalid message content.")
    cleaned = raw_body.strip()
    if not cleaned:
        raise HTTPException(status_code=400, detail="Message body cannot be empty.")
    if len(cleaned) > MAX_DIRECT_MESSAGE_CHARS:
        raise HTTPException(
            status_code=400,
            detail=f"Message body exceeds maximum length of {MAX_DIRECT_MESSAGE_CHARS} characters.",
        )
    return cleaned


def _validate_idempotency_key(raw_key: str | None) -> str | None:
    if raw_key is None:
        return None
    cleaned = raw_key.strip()
    if not cleaned:
        return None
    if len(cleaned) > MAX_IDEMPOTENCY_KEY_CHARS or not _IDEMPOTENCY_KEY_RE.match(cleaned):
        raise HTTPException(status_code=400, detail="Invalid idempotency_key format.")
    return cleaned


def _sanitize_operator_name(raw_name: str | None) -> str | None:
    if not raw_name:
        return None
    cleaned = "".join(ch for ch in str(raw_name).strip() if ch.isprintable() and ch not in "\r\n\t")
    cleaned = " ".join(cleaned.split())
    return cleaned[:64] or None


def _serialize_license_message(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "license_key": str(row["license_key"]),
        "sender_type": str(row["sender_type"]),
        "sender_identity": str(row.get("sender_identity") or ""),
        "target_device_id": row.get("target_device_id"),
        "body": str(row.get("body") or ""),
        "status": str(row.get("status") or ""),
        "idempotency_key": row.get("idempotency_key"),
        "created_at": _iso_utc(row.get("created_at")),
        "delivered_at": _iso_utc(row.get("delivered_at")),
        "read_at": _iso_utc(row.get("read_at")),
        "read_by": row.get("read_by"),
        "retargeted_from_device_id": row.get("retargeted_from_device_id"),
        "retargeted_by": row.get("retargeted_by"),
        "retargeted_at": _iso_utc(row.get("retargeted_at")),
    }


def _resolve_client_auth_pair(
    request: Request,
    body_key: str | None = None,
    body_device_id: str | None = None,
    target_license_key: str | None = None,
) -> tuple[str, str]:
    """
    Extract authenticated client (license_key, device_id) from headers and/or payload.
    Rejects any conflicting identity headers vs payload or any cross-license targeting attempt.
    """
    hdr_key = (request.headers.get("x-license-key") or "").strip()
    hdr_dev = (request.headers.get("x-device-id") or "").strip()
    b_key = (body_key or "").strip()
    b_dev = (body_device_id or "").strip()

    if hdr_key and b_key and not hmac.compare_digest(hdr_key, b_key):
        raise HTTPException(status_code=403, detail="Conflicting license identity in request.")
    if hdr_dev and b_dev and not hmac.compare_digest(hdr_dev, b_dev):
        raise HTTPException(status_code=403, detail="Conflicting device identity in request.")

    eff_key = hdr_key or b_key
    eff_dev = hdr_dev or b_dev

    if target_license_key is not None:
        tgt = target_license_key.strip()
        if tgt and (not eff_key or not hmac.compare_digest(tgt, eff_key)):
            raise HTTPException(status_code=403, detail="Access denied: cannot access another license's conversation.")

    return eff_key, eff_dev


def _authenticate_client_messaging(cur, license_key: str, device_id: str, client_ip: str) -> dict:
    """
    Reuse the server's authoritative license & single-device binding model to authenticate
    client messaging requests. Enforces revoked, unbound, device-mismatch, and expired rules
    without bypassing or weakening license validation.
    """
    if not license_key or len(device_id) < 4:
        raise HTTPException(status_code=401, detail="Authenticated license_key and device_id are required.")

    cur.execute(
        """
        SELECT license_key, status, plan, expires_at, has_paid_renewal,
               device_id, label, note, app_version, last_seen
        FROM licenses
        WHERE license_key = %s
        """,
        (license_key,),
    )
    row = cur.fetchone()
    if row is None:
        _record_and_check_unknown_key_rate_limit(client_ip)
        raise HTTPException(status_code=401, detail="License key not recognized.")

    status = (row.get("status") or "").strip().lower()
    if status in {"revoked", "suspended", "disabled"}:
        raise HTTPException(status_code=403, detail="Revoked or inactive licenses cannot access messaging.")

    bound_dev = (row.get("device_id") or "").strip()
    if not bound_dev:
        raise HTTPException(status_code=403, detail="This license is not bound to an activated device.")
    if not hmac.compare_digest(bound_dev, device_id):
        raise HTTPException(status_code=403, detail="This license is bound to a different computer.")

    expires_at = _as_utc(row.get("expires_at"))
    if status == "expired" or (expires_at is not None and expires_at <= _utc_now()):
        raise HTTPException(status_code=403, detail="This license has expired. Renew to restore messaging access.")

    return row


def _effective_license_status_str(row: dict, now: datetime | None = None) -> str:
    raw = (row.get("status") or "").strip().lower()
    if raw == "revoked":
        return "revoked"
    if raw == "expired":
        return "expired"
    exp = _as_utc(row.get("expires_at"))
    ref_now = now or _utc_now()
    if exp is not None and exp <= ref_now:
        return "expired"
    return raw or "active"


def _fetch_client_scoped_messages(
    cur,
    *,
    license_key: str,
    device_id: str,
    since_id: int | None = None,
) -> list[dict]:
    """
    Fetch messages strictly scoped to this authenticated (license_key, device_id).
    Excludes held/cancelled messages and any messages bound to a prior device_id.
    """
    if since_id is not None and int(since_id) > 0:
        cur.execute(
            """
            SELECT id, license_key, sender_type, sender_identity, target_device_id,
                   body, status, idempotency_key, created_at, delivered_at, read_at, read_by,
                   retargeted_from_device_id, retargeted_by, retargeted_at
            FROM license_messages
            WHERE license_key = %s
              AND target_device_id = %s
              AND status NOT IN ('held_device_changed', 'cancelled')
              AND id > %s
            ORDER BY created_at ASC, id ASC
            """,
            (license_key, device_id, int(since_id)),
        )
    else:
        cur.execute(
            """
            SELECT id, license_key, sender_type, sender_identity, target_device_id,
                   body, status, idempotency_key, created_at, delivered_at, read_at, read_by,
                   retargeted_from_device_id, retargeted_by, retargeted_at
            FROM license_messages
            WHERE license_key = %s
              AND target_device_id = %s
              AND status NOT IN ('held_device_changed', 'cancelled')
            ORDER BY created_at ASC, id ASC
            """,
            (license_key, device_id),
        )
    return [_serialize_license_message(r) for r in cur.fetchall()]


def _send_password_reset_smtp(
    *,
    to_email: str,
    username: str,
    reset_code: str,
    ttl_minutes: int,
) -> None:
    """
    Send password-reset verification code via server-only SMTP credentials
    (SMTP_HOST, SMTP_PORT, SMTP_USE_TLS, SMTP_EMAIL, SMTP_APP_PASSWORD).
    Never logs credentials or reset codes.
    """
    host = (os.environ.get("SMTP_HOST") or "smtp.gmail.com").strip()
    port = int(os.environ.get("SMTP_PORT") or "587")
    use_tls = (os.environ.get("SMTP_USE_TLS") or "true").strip().lower() not in ("0", "false", "no")
    smtp_email = (os.environ.get("SMTP_EMAIL") or "").strip()
    smtp_password = "".join((os.environ.get("SMTP_APP_PASSWORD") or "").split())
    timeout = float(os.environ.get("SMTP_TIMEOUT_SECONDS") or "15")
    support_contact = (os.environ.get("LICENSE_SUPPORT_CONTACT") or "").strip() or "vivekanandnaik333@gmail.com"

    is_local_host = host.lower() in ("localhost", "127.0.0.1", "::1")
    if not is_local_host and (not smtp_email or not smtp_password):
        raise HTTPException(
            status_code=503,
            detail="Password reset email service is not configured on the licensing server.",
        )

    from_addr = smtp_email or "noreply@anpr.local"
    plain_body = (
        f"CodersParadiseSoftwares — ANPR Gate Console\n"
        f"Password Reset Verification Code\n\n"
        f"Hello {username},\n\n"
        f"A password reset was requested for account: {username}\n\n"
        f"Your 6-digit verification code:\n"
        f"{reset_code}\n\n"
        f"This code expires in {ttl_minutes} minutes and can only be used once.\n"
        f"If you did not request this, you can safely ignore this email.\n\n"
        f"Contact support: {support_contact}\n"
    )
    safe_user = html.escape(str(username))
    safe_code = html.escape(str(reset_code))
    safe_support = html.escape(support_contact)
    html_body = (
        f"<!DOCTYPE html><html lang='en'><body style='font-family:Segoe UI,Arial,sans-serif;background:#f3f4f6;padding:24px;'>"
        f"<div style='max-width:540px;margin:0 auto;background:#ffffff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;'>"
        f"<div style='height:4px;background:#f59e0b;'></div>"
        f"<div style='background:#15171a;color:#f8fafc;padding:20px 24px;'>"
        f"<div style='font-size:11px;letter-spacing:1.2px;color:#f59e0b;font-weight:700;'>CODERSPARADISESOFTWARES</div>"
        f"<div style='font-size:18px;font-weight:700;margin-top:4px;'>ANPR Gate Console &mdash; Password Reset</div>"
        f"</div><div style='padding:24px;color:#111827;'>"
        f"<p>Hello <strong>{safe_user}</strong>,</p>"
        f"<p>A password reset was requested for account <strong>{safe_user}</strong>.</p>"
        f"<div style='background:#f9fafb;border:1px solid #d1d5db;border-left:4px solid #f59e0b;border-radius:6px;padding:16px;text-align:center;margin:18px 0;'>"
        f"<div style='font-size:11px;letter-spacing:1px;color:#6b7280;font-weight:700;margin-bottom:6px;'>VERIFICATION CODE</div>"
        f"<div style='font-family:Consolas,monospace;font-size:30px;font-weight:700;letter-spacing:8px;'>{safe_code}</div>"
        f"</div>"
        f"<p style='font-size:13px;color:#374151;'>This code expires in <strong>{int(ttl_minutes)} minutes</strong> and can only be used once.</p>"
        f"<p style='font-size:12px;color:#6b7280;'>If you did not request this, ignore this email or contact {safe_support}.</p>"
        f"</div></div></body></html>"
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "CodersParadiseSoftwares — ANPR Gate Console Password Reset Code"
    msg["From"] = f"CodersParadiseSoftwares <{from_addr}>"
    msg["To"] = to_email
    msg.attach(MIMEText(plain_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=timeout) as server:
            server.ehlo()
            if smtp_email and smtp_password:
                server.login(smtp_email, smtp_password)
            server.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=timeout) as server:
            server.ehlo()
            if use_tls:
                server.starttls()
                server.ehlo()
            if smtp_email and smtp_password:
                server.login(smtp_email, smtp_password)
            server.send_message(msg)


def _require_admin_session(request: Request) -> dict:
    token, _ = _extract_session_token(request)
    session = _verify_active_session(token)
    if session is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    _check_admin(_get_admin_token())
    return session


def _require_owner_session(request: Request) -> dict:
    session = _require_admin_session(request)
    if (session.get("role") or "").strip().lower() != "owner":
        raise HTTPException(status_code=403, detail="SystemOwner (owner) privileges are required.")
    return session


def _require_owner_or_token(request: Request, x_admin_token: str | None = Header(default=None)) -> dict:
    """Allow SystemOwner dashboard sessions (role='owner') or server admin token."""
    token, source = _extract_session_token(request)
    if source is not None:
        session = _verify_active_session(token)
        if session is None:
            raise HTTPException(status_code=401, detail="Invalid or expired session.")
        _check_admin(_get_admin_token())
        if (session.get("role") or "").strip().lower() != "owner":
            raise HTTPException(status_code=403, detail="SystemOwner (owner) privileges are required for this action.")
        return session
    if x_admin_token is not None:
        _check_admin(x_admin_token)
        return {"auth_type": "admin_token", "username": "admin_token", "role": "owner"}
    raise HTTPException(status_code=401, detail="Authentication required.")


def _require_admin_api(request: Request, x_admin_token: str | None = Header(default=None)) -> dict:
    token, source = _extract_session_token(request)
    if source is not None:
        session = _verify_active_session(token)
        if session is None:
            raise HTTPException(status_code=401, detail="Invalid or expired session.")
        _check_admin(_get_admin_token())
        return session
    if x_admin_token is not None:
        _check_admin(x_admin_token)
        return {"auth_type": "admin_token"}
    raise HTTPException(status_code=401, detail="Authentication required.")


def _is_first_paid_renewal(row: dict | None) -> bool:
    """True only if the key exists and has never transitioned off its initial trial plan."""
    if row is None:
        return False
    plan = (row.get("plan") or "trial").strip().lower()
    has_paid = bool(row.get("has_paid_renewal", False))
    return plan == "trial" and not has_paid


def _detect_image_mime(raw: bytes) -> str | None:
    """Validate screenshot magic bytes to reject non-image uploads."""
    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if raw.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if len(raw) >= 12 and raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return "image/webp"
    return None


def _record_license_audit(
    cur,
    *,
    license_key: str,
    action: str,
    actor: str,
    previous_plan: str | None = None,
    new_plan: str | None = None,
    previous_expires_at: datetime | None = None,
    new_expires_at: datetime | None = None,
    previous_has_paid_renewal: bool | None = None,
    new_has_paid_renewal: bool | None = None,
    note: str | None = None,
) -> None:
    """Persist a structured entry to license_audit_log for renewals, handover resets, and status changes."""
    cur.execute(
        """
        INSERT INTO license_audit_log (
            license_key, action, actor,
            previous_plan, new_plan,
            previous_expires_at, new_expires_at,
            previous_has_paid_renewal, new_has_paid_renewal,
            note, created_at
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            license_key,
            action,
            actor,
            previous_plan,
            new_plan,
            previous_expires_at,
            new_expires_at,
            previous_has_paid_renewal,
            new_has_paid_renewal,
            note,
            _utc_now(),
        ),
    )


def _apply_renewal(
    cur,
    license_key: str,
    plan: str,
    actor: str = "admin",
    audit_action: str = "renew",
    audit_note: str | None = None,
) -> dict:
    """
    Core renewal logic shared by /api/v1/admin/renew and submission approval.
    Extends expires_at by PLANS[plan]['days'] from max(now, current expires_at).
    """
    plan_key = (plan or "").strip().lower()
    all_plans = _load_plans_map(cur, include_inactive=True)
    if plan_key not in all_plans:
        active_plans = {k for k, v in all_plans.items() if v.get("active", True)}
        raise HTTPException(
            status_code=400,
            detail=f"Invalid plan '{plan}'. Allowed plans: {', '.join(sorted(active_plans))}",
        )

    cur.execute(
        "SELECT license_key, status, expires_at, plan, has_paid_renewal FROM licenses WHERE license_key = %s FOR UPDATE",
        (license_key,),
    )
    row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Key not found")

    if (row.get("status") or "").strip().lower() == "revoked":
        raise HTTPException(
            status_code=409,
            detail="Cannot renew or approve payment for a revoked license. SystemOwner must explicitly reactivate it first.",
        )

    now = _utc_now()
    current_exp = _as_utc(row.get("expires_at"))
    prev_plan = (row.get("plan") or "trial").strip().lower()
    prev_paid = bool(row.get("has_paid_renewal", False))
    base_time = max(now, current_exp) if current_exp is not None else now
    days_to_add = int(all_plans[plan_key]["days"])
    new_expires_at = base_time + timedelta(days=days_to_add)

    cur.execute(
        """
        UPDATE licenses
        SET status = 'active',
            plan = %s,
            expires_at = %s,
            has_paid_renewal = TRUE
        WHERE license_key = %s
        """,
        (plan_key, new_expires_at, license_key),
    )

    _record_license_audit(
        cur,
        license_key=license_key,
        action=audit_action,
        actor=actor,
        previous_plan=prev_plan,
        new_plan=plan_key,
        previous_expires_at=current_exp,
        new_expires_at=new_expires_at,
        previous_has_paid_renewal=prev_paid,
        new_has_paid_renewal=True,
        note=audit_note or f"Extended license by {days_to_add}d ({plan_key})",
    )
    logger.info(
        "[LICENSE %s] actor=%s key=%s plan=%s->%s expires=%s->%s (+%sd)",
        audit_action.upper(),
        actor,
        license_key,
        prev_plan,
        plan_key,
        _iso_utc(current_exp),
        new_expires_at.isoformat(),
        days_to_add,
    )

    return {
        "ok": True,
        "action": audit_action,
        "license_key": license_key,
        "status": "active",
        "plan": plan_key,
        "days_added": days_to_add,
        "expires_at": new_expires_at.isoformat(),
    }


def _apply_plan_reset(cur, license_key: str, plan: str, actor: str = "owner") -> dict:
    """
    Handover / fresh-start plan reset.
    Unlike _apply_renewal (which extends from max(now, expires_at)), this discards any
    prior elapsed/remaining time and sets expires_at = now + duration_days.
    Resetting to 'trial' restores has_paid_renewal = FALSE so first-time launch90
    eligibility is available again for real customer handover.
    """
    plan_key = (plan or "").strip().lower()
    all_plans = _load_plans_map(cur, include_inactive=True)
    if plan_key != "trial" and plan_key not in all_plans:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid plan '{plan}'. Allowed plans: trial, {', '.join(all_plans.keys())}",
        )

    cur.execute(
        "SELECT license_key, status, expires_at, plan, has_paid_renewal FROM licenses WHERE license_key = %s FOR UPDATE",
        (license_key,),
    )
    row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Key not found")

    now = _utc_now()
    prev_exp = _as_utc(row.get("expires_at"))
    prev_plan = (row.get("plan") or "trial").strip().lower()
    prev_paid = bool(row.get("has_paid_renewal", False))

    reset_days = TRIAL_DAYS if plan_key == "trial" else int(all_plans[plan_key]["days"])
    new_expires_at = now + timedelta(days=reset_days)
    new_has_paid = False if plan_key == "trial" else True

    cur.execute(
        """
        UPDATE licenses
        SET status = 'active',
            plan = %s,
            expires_at = %s,
            has_paid_renewal = %s
        WHERE license_key = %s
        """,
        (plan_key, new_expires_at, new_has_paid, license_key),
    )

    _record_license_audit(
        cur,
        license_key=license_key,
        action="reset_plan",
        actor=actor,
        previous_plan=prev_plan,
        new_plan=plan_key,
        previous_expires_at=prev_exp,
        new_expires_at=new_expires_at,
        previous_has_paid_renewal=prev_paid,
        new_has_paid_renewal=new_has_paid,
        note=f"Handover clock reset: fresh {reset_days}d '{plan_key}' period started from now",
    )
    logger.info(
        "[LICENSE HANDOVER_RESET] actor=%s key=%s plan=%s->%s expires=%s->%s "
        "days=%s has_paid_renewal=%s->%s",
        actor,
        license_key,
        prev_plan,
        plan_key,
        _iso_utc(prev_exp),
        new_expires_at.isoformat(),
        reset_days,
        prev_paid,
        new_has_paid,
    )

    return {
        "ok": True,
        "action": "reset_plan",
        "license_key": license_key,
        "status": "active",
        "plan": plan_key,
        "days_reset": reset_days,
        "has_paid_renewal": new_has_paid,
        "previous_plan": prev_plan,
        "previous_expires_at": _iso_utc(prev_exp),
        "expires_at": new_expires_at.isoformat(),
    }


def _send_telegram_payment_notification(
    submission_id: int,
    license_key: str,
    device_id: str,
    claimed_plan: str,
    submitted_at: datetime,
    image_bytes: bytes,
    content_type: str,
    plan_info: dict | None = None,
) -> bool:
    """
    Forward uploaded UPI payment screenshot + details to the licensor's Telegram chat
    using TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID from environment variables only.
    """
    bot_token = (os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip()
    chat_id = (os.environ.get("TELEGRAM_CHAT_ID") or "").strip()
    if not bot_token or not chat_id:
        logger.warning("TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not configured; skipping Telegram notification.")
        return False

    plan_meta = plan_info or PLANS.get(claimed_plan, {})
    label = plan_meta.get("label", claimed_plan)
    price = plan_meta.get("price_inr", "?")
    days = plan_meta.get("days", "?")
    ext = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp"}.get(content_type, "png")

    base_url = (os.environ.get("PUBLIC_BASE_URL") or "https://verificationid.onrender.com").rstrip("/")
    caption = (
        f"ANPR Payment Verification Required (#{submission_id})\n"
        f"License Key: {license_key}\n"
        f"Device ID: {device_id}\n"
        f"Claimed Plan: {claimed_plan} ({label} — Rs.{price} / {days}d)\n"
        f"Submitted (UTC): {submitted_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
        f"Review in Admin Dashboard: {base_url}/admin"
    )
    url = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
    try:
        resp = requests.post(
            url,
            data={"chat_id": chat_id, "caption": caption},
            files={"photo": (f"payment_{submission_id}.{ext}", image_bytes, content_type)},
            timeout=15,
        )
        if resp.status_code == 200:
            return True
        logger.warning("Telegram sendPhoto returned HTTP %s: %s", resp.status_code, resp.text[:200])
        return False
    except Exception as exc:
        logger.warning("Telegram notification failed for submission #%s: %s", submission_id, exc)
        return False


def _send_telegram_contact_message(
    *,
    message_id: int,
    license_key: str | None,
    device_id: str,
    message_text: str,
    received_at: datetime,
) -> bool:
    """
    Relay a client "Contact Admin" support message immediately to the owner's Telegram chat ONLY
    (via TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID from server env vars — never broadcast to
    vehicle-alert subscribers).
    """
    bot_token = (os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip()
    chat_id = (os.environ.get("TELEGRAM_CHAT_ID") or "").strip()
    if not bot_token or not chat_id:
        logger.warning("TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not configured; skipping Telegram contact relay.")
        return False

    key_label = (license_key or "").strip() or "unregistered"
    text = (
        f"📩 Message from [{key_label} / {device_id}]:\n\n"
        f"{message_text}\n\n"
        f"Ref #{message_id} • {received_at.strftime('%Y-%m-%d %H:%M:%S UTC')}"
    )
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        resp = requests.post(
            url,
            data={"chat_id": chat_id, "text": text},
            timeout=15,
        )
        if resp.status_code == 200:
            return True
        logger.warning("Telegram sendMessage returned HTTP %s: %s", resp.status_code, resp.text[:200])
        return False
    except Exception as exc:
        logger.warning("Telegram contact relay failed for message #%s: %s", message_id, exc)
        return False


# ===================================================================== SCHEMAS
class ValidateRequest(BaseModel):
    license_key: str
    device_id: str
    app_version: str


class ValidateResponse(BaseModel):
    status: str  # "active" | "revoked" | "expired" | "unknown" | "device_mismatch" | "trial_already_used" | "invalid"
    message: str | None = None
    expires_at: str | None = None
    plan: str | None = None
    broadcasts: list[dict] = []
    offline_lease: dict | None = None
    pending_credential_provisions: list[dict] = []


class ActivateDeviceRequest(BaseModel):
    device_id: str
    app_version: str


class ActivateDeviceResponse(BaseModel):
    status: str  # "active" | "revoked" | "expired" | "trial_already_used" | "invalid"
    license_key: str | None = None
    message: str | None = None
    expires_at: str | None = None
    plan: str | None = None
    broadcasts: list[dict] = []
    offline_lease: dict | None = None
    newly_provisioned: bool = False
    pending_credential_provisions: list[dict] = []


class PasswordResetEmailRelayRequest(BaseModel):
    license_key: str
    device_id: str
    to_email: str
    username: str
    reset_code: str
    ttl_minutes: int = 10


class DeviceTrialOverrideRequest(BaseModel):
    device_id: str
    note: str | None = None


class BroadcastAckRequest(BaseModel):
    license_key: str
    device_id: str


class CreateBroadcastRequest(BaseModel):
    message: str
    tone: str = "notice"


class CreatePlanRequest(BaseModel):
    plan_key: str
    label: str
    days: int
    price_inr: int
    active: bool = True


class UpdatePlanRequest(BaseModel):
    label: str | None = None
    days: int | None = None
    price_inr: int | None = None
    active: bool | None = None


class CreateLicenseRequest(BaseModel):
    license_key: str | None = None
    note: str | None = None
    label: str | None = None
    plan: str = "trial"
    days: int | None = None
    allow_repeat_trial: bool = False


class AdminLoginRequest(BaseModel):
    username: str
    password: str


class UpdateOwnerAccountRequest(BaseModel):
    current_password: str
    username: str | None = None
    email: str | None = None
    new_password: str | None = None


class ContactMessageRequest(BaseModel):
    message: str
    license_key: str | None = None
    device_id: str
    timestamp: str | None = None


class UpdateSystemSettingsRequest(BaseModel):
    trial_days: int


class ProvisionCredentialsRequest(BaseModel):
    device_id: str
    username: str
    email: str
    password: str | None = None
    role: str = "ADMIN"
    must_change_password: bool = True


class ConsumeCredentialProvisionRequest(BaseModel):
    provision_id: int
    device_id: str
    license_key: str | None = None
    applied: bool = True
    outcome: str | None = None


class DeviceRbacAccountItem(BaseModel):
    username: str
    email: str
    role: str = "OPERATOR"
    is_active: bool = True
    must_change_password: bool = False


class SyncDeviceRbacRequest(BaseModel):
    license_key: str
    device_id: str
    accounts: list[DeviceRbacAccountItem] = []


class ClientMessageSendRequest(BaseModel):
    license_key: str | None = None
    device_id: str | None = None
    body: str
    idempotency_key: str | None = None
    operator_name: str | None = None
    target_license_key: str | None = None


class ClientMessageSyncRequest(BaseModel):
    license_key: str | None = None
    device_id: str | None = None
    since_id: int | None = None
    target_license_key: str | None = None


class ClientMessageAckRequest(BaseModel):
    license_key: str | None = None
    device_id: str | None = None
    message_ids: list[int]
    target_license_key: str | None = None


class AdminMessageSendRequest(BaseModel):
    license_key: str
    body: str
    idempotency_key: str | None = None


class AdminMessageRetargetRequest(BaseModel):
    action: str = "retarget"  # "retarget" | "cancel"


# ============================================================== PUBLIC ROUTES
@app.api_route("/health", methods=["GET", "HEAD"])
@app.api_route("/ping", methods=["GET", "HEAD"])
def health_ping():
    """
    Lightweight keep-alive & uptime probe endpoint (zero database queries).
    Used by external schedulers (e.g. cron-job.org / UptimeRobot) every 10–14 min
    to keep the Render service warm without burning database compute.
    """
    return {"status": "ok", "service": "anpr-license-server"}


@app.get("/api/v1/plans")
def get_plans(license_key: str | None = Query(default=None)):
    """
    Public endpoint returning active subscription plans from the `subscription_plans`
    database table plus whether the given license_key qualifies for first-time
    paid renewal Launch Offer (`launch90`).
    """
    first_paid = False
    with get_db() as conn:
        with conn.cursor() as cur:
            active_plans = _load_plans_map(cur, include_inactive=False)
            if license_key:
                cur.execute(
                    "SELECT license_key, plan, has_paid_renewal FROM licenses WHERE license_key = %s",
                    (license_key.strip(),),
                )
                row = cur.fetchone()
                first_paid = _is_first_paid_renewal(row)

    return {
        "plans": _public_plans_dict(active_plans),
        "is_first_paid_renewal": first_paid,
        "upi_vpa": (os.environ.get("UPI_VPA") or "").strip(),
        "upi_name": (os.environ.get("UPI_PAYEE_NAME") or "").strip(),
    }


@app.post("/api/v1/validate", response_model=ValidateResponse)
def validate(req: ValidateRequest, request: Request):
    now = _utc_now()
    req_key = (req.license_key or "").strip()
    req_device_id = (req.device_id or "").strip()
    if not req_device_id:
        return ValidateResponse(status="invalid", message="Device identifier is required.")

    client_ip = _client_ip(request)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM licenses WHERE license_key = %s FOR UPDATE", (req_key,))
            row = cur.fetchone()

            if row is None:
                _record_and_check_unknown_key_rate_limit(client_ip)
                return ValidateResponse(status="unknown", message="License key not recognized.")

            status = (row["status"] or "").strip().lower()
            plan = (row.get("plan") or "trial").strip().lower()
            has_paid = bool(row.get("has_paid_renewal", False))
            expires_at = _as_utc(row.get("expires_at"))
            expires_iso = _iso_utc(expires_at)
            bound_device = (row.get("device_id") or "").strip()
            allow_repeat_trial = bool(row.get("allow_repeat_trial", False))
            trial_days = max(1, int(row.get("trial_days") or TRIAL_DAYS))
            activated_at = _as_utc(row.get("activated_at"))

            # Revoked is an active licensor action and always takes precedence
            if status == "revoked":
                return ValidateResponse(
                    status="revoked",
                    message="This license has been revoked by the licensor.",
                    expires_at=expires_iso,
                    plan=plan,
                    broadcasts=[],
                )

            # Strict 1-License-Key = 1-Device enforcement:
            # Once bound to a machine's device_id, any different machine is rejected until
            # the SystemOwner explicitly unbinds/transfers the license in the Admin Dashboard.
            if bound_device and bound_device != req_device_id:
                logger.warning(
                    "[LICENSE DEVICE_MISMATCH] key=%s bound_device=%s attempted_device=%s",
                    req_key,
                    bound_device[:12],
                    req_device_id[:12],
                )
                return ValidateResponse(
                    status="device_mismatch",
                    message=(
                        "This license key is already activated on another computer. "
                        "Use a separate license key for this PC, or contact support to transfer it."
                    ),
                    expires_at=expires_iso,
                    plan=plan,
                    broadcasts=[],
                )

            first_bind = not bound_device
            if first_bind:
                # One 180-day free trial per device, starting at first successful activation.
                if plan == "trial" and not has_paid:
                    cur.execute(
                        """
                        INSERT INTO device_trials (device_id, first_license_key, first_activated_at, note)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (device_id) DO NOTHING
                        RETURNING device_id
                        """,
                        (req_device_id, req_key, now, "First free trial activation"),
                    )
                    inserted_trial = cur.fetchone()
                    if inserted_trial is None:
                        cur.execute(
                            """
                            SELECT device_id, first_license_key, first_activated_at
                            FROM device_trials
                            WHERE device_id = %s
                            """,
                            (req_device_id,),
                        )
                        existing_trial = cur.fetchone()
                        first_key = (existing_trial or {}).get("first_license_key")
                        if first_key and first_key != req_key and not allow_repeat_trial:
                            logger.warning(
                                "[LICENSE TRIAL_ALREADY_USED] key=%s device=%s first_key=%s",
                                req_key,
                                req_device_id[:12],
                                first_key,
                            )
                            return ValidateResponse(
                                status="trial_already_used",
                                message=(
                                    "This computer has already used its one-time 180-day free trial. "
                                    "Please activate your existing license key or renew with a paid subscription."
                                ),
                                expires_at=expires_iso,
                                plan=plan,
                                broadcasts=[],
                            )

                    # Start 180-day trial countdown ONLY on first activation (preserves legacy/transferred expires_at)
                    if expires_at is None:
                        expires_at = now + timedelta(days=trial_days)
                        expires_iso = _iso_utc(expires_at)

                new_activated_at = activated_at or now
                cur.execute(
                    """
                    UPDATE licenses
                    SET device_id = %s,
                        app_version = %s,
                        last_seen = %s,
                        activated_at = %s,
                        expires_at = %s
                    WHERE license_key = %s
                    """,
                    (req_device_id, req.app_version, now, new_activated_at, expires_at, req_key),
                )
                logger.info(
                    "[LICENSE DEVICE_BOUND] key=%s device=%s app_version=%s expires=%s",
                    req_key,
                    req_device_id[:12],
                    req.app_version,
                    expires_iso,
                )
                _record_license_audit(
                    cur,
                    license_key=req_key,
                    action="device_bound",
                    actor="client",
                    previous_plan=plan,
                    new_plan=plan,
                    previous_expires_at=_as_utc(row.get("expires_at")),
                    new_expires_at=expires_at,
                    previous_has_paid_renewal=has_paid,
                    new_has_paid_renewal=has_paid,
                    note=f"Bound license key to device {req_device_id}" + (" (repeat trial owner exception)" if allow_repeat_trial else ""),
                )
            else:
                cur.execute(
                    "UPDATE licenses SET device_id = %s, app_version = %s, last_seen = %s WHERE license_key = %s",
                    (req_device_id, req.app_version, now, req_key),
                )

            broadcasts = _fetch_unacked_broadcasts(cur, req_device_id)

            # Check plan / trial expiration timestamp
            if status == "expired" or (expires_at is not None and expires_at <= now):
                return ValidateResponse(
                    status="expired",
                    message="Your subscription or trial period has expired. Please renew to continue.",
                    expires_at=expires_iso,
                    plan=plan,
                    broadcasts=broadcasts,
                )

            if status == "active":
                offline_lease = _sign_offline_lease(
                    license_key=req_key,
                    device_id=req_device_id,
                    plan=plan,
                    expires_at=expires_at,
                    issued_at=now,
                )
                pending_creds = _fetch_pending_credential_provisions(cur, req_device_id)
                return ValidateResponse(
                    status="active",
                    expires_at=expires_iso,
                    plan=plan,
                    broadcasts=broadcasts,
                    offline_lease=offline_lease,
                    pending_credential_provisions=pending_creds,
                )

            return ValidateResponse(
                status=status or "expired",
                message="This license is not active.",
                expires_at=expires_iso,
                plan=plan,
                broadcasts=broadcasts,
            )


def _activate_response_for_existing_row(
    cur,
    row: dict,
    *,
    req_device_id: str,
    app_version: str,
    now: datetime,
    newly_provisioned: bool = False,
) -> ActivateDeviceResponse:
    """Build an ActivateDeviceResponse for an already-bound license row without mutating expiry/plan."""
    lic_key = str(row["license_key"])
    status = (row.get("status") or "").strip().lower()
    plan = (row.get("plan") or "trial").strip().lower()
    expires_at = _as_utc(row.get("expires_at"))
    expires_iso = _iso_utc(expires_at)

    if status == "revoked":
        return ActivateDeviceResponse(
            status="revoked",
            license_key=lic_key,
            message="This license has been revoked by the licensor.",
            expires_at=expires_iso,
            plan=plan,
            broadcasts=[],
            offline_lease=None,
            newly_provisioned=False,
        )

    cur.execute(
        "UPDATE licenses SET app_version = %s, last_seen = %s WHERE license_key = %s",
        (app_version, now, lic_key),
    )
    broadcasts = _fetch_unacked_broadcasts(cur, req_device_id)

    if status == "expired" or (expires_at is not None and expires_at <= now):
        return ActivateDeviceResponse(
            status="expired",
            license_key=lic_key,
            message="Your subscription or trial period has expired. Please renew to continue.",
            expires_at=expires_iso,
            plan=plan,
            broadcasts=broadcasts,
            offline_lease=None,
            newly_provisioned=False,
        )

    if status == "active":
        offline_lease = _sign_offline_lease(
            license_key=lic_key,
            device_id=req_device_id,
            plan=plan,
            expires_at=expires_at,
            issued_at=now,
        )
        pending_creds = _fetch_pending_credential_provisions(cur, req_device_id)
        return ActivateDeviceResponse(
            status="active",
            license_key=lic_key,
            expires_at=expires_iso,
            plan=plan,
            broadcasts=broadcasts,
            offline_lease=offline_lease,
            newly_provisioned=newly_provisioned,
            pending_credential_provisions=pending_creds,
        )

    return ActivateDeviceResponse(
        status=status or "expired",
        license_key=lic_key,
        message="This license is not active.",
        expires_at=expires_iso,
        plan=plan,
        broadcasts=broadcasts,
        offline_lease=None,
        newly_provisioned=False,
    )


@app.post("/api/v1/activate-device", response_model=ActivateDeviceResponse)
def activate_device(req: ActivateDeviceRequest, request: Request):
    """
    Silent, zero-prompt first-launch device self-registration & recovery endpoint.
    Accepts ONLY `device_id` and `app_version` (no manual license key required):
      - Already-registered device (currently bound in `licenses`, whether active,
        mid-trial, expired, or revoked): returns its exact existing license state
        without creating a second license or resetting/extending anything.
      - Brand-new device (not in `device_trials`): atomically generates a unique
        high-entropy trial license key (plan='trial', trial_days=180), records it
        in `device_trials`, starts its 180-day trial upon activation, signs an
        Ed25519 offline lease, and returns the key + active state directly.
      - Device whose prior trial license was unbound/transferred away (present in
        `device_trials` with no bound row in `licenses`): rejects with
        `status='trial_already_used'` to enforce strictly one free trial per device
        unless SystemOwner explicitly clears it via `/api/v1/admin/device-trials/override`.
    """
    now = _utc_now()
    req_device_id = (req.device_id or "").strip()
    if len(req_device_id) < 4:
        return ActivateDeviceResponse(status="invalid", message="Device identifier is required.")

    client_ip = _client_ip(request)

    with get_db() as conn:
        with conn.cursor() as cur:
            # 1. Fast path: if this device already has a bound license, return it as-is
            cur.execute(
                """
                SELECT * FROM licenses
                WHERE device_id = %s
                ORDER BY COALESCE(activated_at, last_seen, NOW()) DESC
                LIMIT 1
                FOR UPDATE
                """,
                (req_device_id,),
            )
            existing_row = cur.fetchone()
            if existing_row is not None:
                return _activate_response_for_existing_row(
                    cur,
                    existing_row,
                    req_device_id=req_device_id,
                    app_version=req.app_version,
                    now=now,
                    newly_provisioned=False,
                )

            # 2. Atomically claim the one-time free-trial slot for this device_id.
            #    In PostgreSQL, concurrent first-launch requests for the same device_id
            #    serialize on the device_trials PRIMARY KEY index so strictly ONE license
            #    is ever created per device.
            trial_days = _get_configured_trial_days(cur)
            candidate_key = _generate_secure_license_key()
            cur.execute(
                """
                INSERT INTO device_trials (device_id, first_license_key, first_activated_at, note)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (device_id) DO NOTHING
                RETURNING device_id, first_license_key
                """,
                (req_device_id, candidate_key, now, f"Auto-provisioned {trial_days}-day free trial on first launch"),
            )
            claimed = cur.fetchone()
            if claimed is None:
                # Either another concurrent request just bound a license for this device,
                # OR this device previously used its trial and was later unbound/transferred.
                cur.execute(
                    """
                    SELECT * FROM licenses
                    WHERE device_id = %s
                    ORDER BY COALESCE(activated_at, last_seen, NOW()) DESC
                    LIMIT 1
                    FOR UPDATE
                    """,
                    (req_device_id,),
                )
                raced_row = cur.fetchone()
                if raced_row is not None:
                    return _activate_response_for_existing_row(
                        cur,
                        raced_row,
                        req_device_id=req_device_id,
                        app_version=req.app_version,
                        now=now,
                        newly_provisioned=False,
                    )
                logger.warning(
                    "[DEVICE ACTIVATE TRIAL_ALREADY_USED] device=%s (already in device_trials with no bound license)",
                    req_device_id[:12],
                )
                return ActivateDeviceResponse(
                    status="trial_already_used",
                    license_key=None,
                    message=(
                        "This computer has already used its one-time free trial. "
                        "Please contact support to restore or purchase a subscription."
                    ),
                    plan="trial",
                    broadcasts=[],
                    offline_lease=None,
                    newly_provisioned=False,
                )

            # Rate-limit brand-new auto-provisions per IP (rolls back device_trials insert on 429)
            _check_and_record_activate_device_rate_limit(client_ip)

            # 3. Create the new trial license record (plan='trial', starts on activation)
            #    and bind/activate it immediately in the same atomic transaction.
            lic_key = ""
            for attempt in range(10):
                key_try = candidate_key if attempt == 0 else _generate_secure_license_key()
                cur.execute(
                    """
                    INSERT INTO licenses (
                        license_key, status, note, plan, expires_at,
                        has_paid_renewal, activated_at, trial_days, allow_repeat_trial
                    )
                    VALUES (%s, 'active', %s, 'trial', NULL, FALSE, NULL, %s, FALSE)
                    ON CONFLICT (license_key) DO NOTHING
                    RETURNING license_key
                    """,
                    (key_try, f"Auto-provisioned on first launch (device {req_device_id[:12]})", trial_days),
                )
                if cur.fetchone() is not None:
                    lic_key = key_try
                    break
            if not lic_key:
                raise HTTPException(status_code=500, detail="Failed to generate a unique license key.")

            if lic_key != candidate_key:
                cur.execute(
                    "UPDATE device_trials SET first_license_key = %s WHERE device_id = %s",
                    (lic_key, req_device_id),
                )

            expires_at = now + timedelta(days=trial_days)
            cur.execute(
                """
                UPDATE licenses
                SET device_id = %s,
                    app_version = %s,
                    last_seen = %s,
                    activated_at = %s,
                    expires_at = %s
                WHERE license_key = %s
                """,
                (req_device_id, req.app_version, now, now, expires_at, lic_key),
            )
            _record_license_audit(
                cur,
                license_key=lic_key,
                action="license_created",
                actor="auto_provision",
                previous_plan=None,
                new_plan="trial",
                previous_expires_at=None,
                new_expires_at=None,
                previous_has_paid_renewal=None,
                new_has_paid_renewal=False,
                note=f"Auto-provisioned {trial_days}d trial key for device {req_device_id}",
            )
            _record_license_audit(
                cur,
                license_key=lic_key,
                action="device_bound",
                actor="client",
                previous_plan="trial",
                new_plan="trial",
                previous_expires_at=None,
                new_expires_at=expires_at,
                previous_has_paid_renewal=False,
                new_has_paid_renewal=False,
                note=f"Auto-bound license key to device {req_device_id}",
            )
            logger.info(
                "[DEVICE AUTO_PROVISIONED] key=%s device=%s trial_days=%s app_version=%s expires=%s",
                lic_key,
                req_device_id[:12],
                trial_days,
                req.app_version,
                _iso_utc(expires_at),
            )

            broadcasts = _fetch_unacked_broadcasts(cur, req_device_id)
            pending_creds = _fetch_pending_credential_provisions(cur, req_device_id)
            offline_lease = _sign_offline_lease(
                license_key=lic_key,
                device_id=req_device_id,
                plan="trial",
                expires_at=expires_at,
                issued_at=now,
            )
            return ActivateDeviceResponse(
                status="active",
                license_key=lic_key,
                expires_at=_iso_utc(expires_at),
                plan="trial",
                broadcasts=broadcasts,
                offline_lease=offline_lease,
                newly_provisioned=True,
                pending_credential_provisions=pending_creds,
            )


@app.post("/api/v1/credential-provisions/consume")
def consume_credential_provision(req: ConsumeCredentialProvisionRequest):
    """
    One-shot consumption confirmation called by the client immediately after applying
    (or safely rejecting under last-admin protection) a remotely provisioned credential
    record so it is never re-applied on subsequent license checks.
    """
    dev_id = (req.device_id or "").strip()
    lic_key = (req.license_key or "").strip() or None
    prov_id = int(req.provision_id)
    if len(dev_id) < 4:
        raise HTTPException(status_code=400, detail="Valid device_id is required.")

    now = _utc_now()
    outcome_clean = (req.outcome or ("applied" if req.applied else "rejected")).strip()[:200]

    with get_db() as conn:
        with conn.cursor() as cur:
            # Verify the caller's device_id matches a bound license key when license_key is supplied
            audit_lic_key = f"DEVICE:{dev_id[:16]}"
            if lic_key:
                cur.execute(
                    "SELECT license_key, device_id, status FROM licenses WHERE license_key = %s",
                    (lic_key,),
                )
                lic_row = cur.fetchone()
                if lic_row is None:
                    raise HTTPException(status_code=403, detail="License key not recognized.")
                bound_dev = (lic_row.get("device_id") or "").strip()
                if bound_dev and bound_dev != dev_id:
                    raise HTTPException(status_code=403, detail="License key is bound to a different device.")
                audit_lic_key = str(lic_row["license_key"])
            else:
                cur.execute(
                    """
                    SELECT license_key FROM licenses
                    WHERE device_id = %s
                    ORDER BY COALESCE(activated_at, last_seen, NOW()) DESC
                    LIMIT 1
                    """,
                    (dev_id,),
                )
                lic_row = cur.fetchone()
                if lic_row is not None:
                    audit_lic_key = str(lic_row["license_key"])

            cur.execute(
                """
                SELECT id, device_id, username, role, consumed_at, created_by
                FROM remote_credential_provisions
                WHERE id = %s AND device_id = %s
                FOR UPDATE
                """,
                (prov_id, dev_id),
            )
            prov = cur.fetchone()
            if prov is None:
                raise HTTPException(status_code=404, detail="Credential provision record not found for this device.")

            if prov.get("consumed_at") is not None:
                return {
                    "ok": True,
                    "provision_id": prov_id,
                    "already_consumed": True,
                    "consumed_at": _iso_utc(prov.get("consumed_at")),
                }

            cur.execute(
                """
                UPDATE remote_credential_provisions
                SET consumed_at = %s
                WHERE id = %s AND device_id = %s AND consumed_at IS NULL
                """,
                (now, prov_id, dev_id),
            )
            action = "remote_credentials_consumed" if req.applied else "remote_credentials_rejected"
            _record_license_audit(
                cur,
                license_key=audit_lic_key,
                action=action,
                actor=f"device:{dev_id[:12]}",
                previous_plan=None,
                new_plan=str(prov.get("role") or "ADMIN").upper(),
                note=(
                    f"Remotely provisioned by SystemOwner ({prov.get('created_by') or 'owner'}): "
                    f"provision #{prov_id} for username='{prov['username']}' ({prov.get('role') or 'ADMIN'}) "
                    f"marked consumed by device {dev_id} ({outcome_clean})"
                ),
            )

    logger.info(
        "[REMOTE_CREDS %s] id=%s device=%s username=%s role=%s outcome=%s",
        "CONSUMED" if req.applied else "REJECTED",
        prov_id,
        dev_id[:12],
        prov["username"],
        prov.get("role"),
        outcome_clean,
    )
    return {
        "ok": True,
        "provision_id": prov_id,
        "already_consumed": False,
        "consumed_at": now.isoformat(),
    }


@app.post("/api/v1/device-rbac/sync")
def sync_device_rbac_accounts(req: SyncDeviceRbacRequest):
    """
    Sync a bound device's non-sensitive local RBAC account roster (username, email, role,
    active state, must_change_password flag) to `device_rbac_accounts` so SystemOwner can
    view known device accounts in the portal and push one-time passwords without ever
    storing or transmitting passwords/hashes from the client.
    """
    lic_key = (req.license_key or "").strip()
    dev_id = (req.device_id or "").strip()
    if not lic_key or len(dev_id) < 4:
        raise HTTPException(status_code=400, detail="license_key and valid device_id are required.")

    now = _utc_now()
    cleaned: list[tuple[str, str, str, bool, bool]] = []
    seen_users: set[str] = set()
    for acct in (req.accounts or [])[:100]:
        uname = (acct.username or "").strip().lower()
        email = (acct.email or "").strip().lower()
        role = (acct.role or "OPERATOR").strip().upper()
        if not uname or len(uname) > 64 or uname in seen_users:
            continue
        if role not in VALID_REMOTE_CREDENTIAL_ROLES:
            role = "OPERATOR"
        seen_users.add(uname)
        cleaned.append((uname, email[:128], role, bool(acct.is_active), bool(acct.must_change_password)))

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT license_key, device_id, status FROM licenses WHERE license_key = %s",
                (lic_key,),
            )
            lic_row = cur.fetchone()
            if lic_row is None:
                raise HTTPException(status_code=403, detail="License key not recognized.")
            if (lic_row.get("status") or "").strip().lower() == "revoked":
                raise HTTPException(status_code=403, detail="License is revoked.")
            bound_dev = (lic_row.get("device_id") or "").strip()
            if bound_dev != dev_id:
                raise HTTPException(status_code=403, detail="License key is not bound to this device.")

            cur.execute("DELETE FROM device_rbac_accounts WHERE device_id = %s", (dev_id,))
            for uname, email, role, is_active, must_change in cleaned:
                cur.execute(
                    """
                    INSERT INTO device_rbac_accounts (
                        device_id, username, email, role, is_active, must_change_password, last_synced_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (device_id, username) DO UPDATE
                    SET email = EXCLUDED.email,
                        role = EXCLUDED.role,
                        is_active = EXCLUDED.is_active,
                        must_change_password = EXCLUDED.must_change_password,
                        last_synced_at = EXCLUDED.last_synced_at
                    """,
                    (dev_id, uname, email, role, is_active, must_change, now),
                )

    return {
        "ok": True,
        "device_id": dev_id,
        "synced_count": len(cleaned),
        "synced_at": now.isoformat(),
    }


@app.post("/api/v1/contact-message")
def submit_contact_message(req: ContactMessageRequest):
    """
    Public two-way contact endpoint for desktop clients ("Contact Admin" dialog).
    Rate-limited to max 1 message per 2 minutes per device_id, persisted in the
    dedicated `contact_messages` table (separate from `payment_submissions`),
    and relayed immediately to the owner's Telegram chat only.
    """
    msg_text = (req.message or "").strip()
    dev_id = (req.device_id or "").strip()
    lic_key = (req.license_key or "").strip() or None

    if len(dev_id) < 4:
        raise HTTPException(status_code=400, detail="Valid device_id is required.")
    if not msg_text:
        raise HTTPException(status_code=400, detail="Message cannot be empty.")
    if len(msg_text) > MAX_CONTACT_MESSAGE_CHARS:
        raise HTTPException(
            status_code=400,
            detail=f"Message is too long (maximum {MAX_CONTACT_MESSAGE_CHARS} characters).",
        )

    client_ts: datetime | None = None
    if req.timestamp:
        try:
            raw_ts = req.timestamp.strip()
            if raw_ts.endswith("Z"):
                raw_ts = raw_ts[:-1] + "+00:00"
            client_ts = _as_utc(datetime.fromisoformat(raw_ts))
        except ValueError:
            client_ts = None

    now = _utc_now()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT received_at
                FROM contact_messages
                WHERE device_id = %s
                ORDER BY received_at DESC
                LIMIT 1
                """,
                (dev_id,),
            )
            latest = cur.fetchone()
            if latest is not None:
                last_at = _as_utc(latest.get("received_at"))
                if last_at is not None:
                    elapsed = (now - last_at).total_seconds()
                    limit_secs = CONTACT_MESSAGE_RATE_LIMIT_MINUTES * 60
                    if elapsed < limit_secs:
                        wait_secs = max(1, int(limit_secs - elapsed))
                        raise HTTPException(
                            status_code=429,
                            detail=(
                                f"You recently sent a message. Please wait {wait_secs} second(s) "
                                f"before sending another."
                            ),
                        )

            cur.execute(
                """
                INSERT INTO contact_messages (
                    license_key, device_id, message, client_timestamp, received_at, telegram_notified
                )
                VALUES (%s, %s, %s, %s, %s, FALSE)
                RETURNING id, received_at
                """,
                (lic_key, dev_id, msg_text, client_ts, now),
            )
            inserted = cur.fetchone()
            msg_id = int(inserted["id"])
            received_at = _as_utc(inserted.get("received_at")) or now

    notified = _send_telegram_contact_message(
        message_id=msg_id,
        license_key=lic_key,
        device_id=dev_id,
        message_text=msg_text,
        received_at=received_at,
    )
    if notified:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE contact_messages SET telegram_notified = TRUE WHERE id = %s",
                    (msg_id,),
                )

    logger.info(
        "[CONTACT MESSAGE] id=%s key=%s device=%s len=%d telegram=%s",
        msg_id,
        lic_key or "unregistered",
        dev_id[:12],
        len(msg_text),
        notified,
    )
    return {
        "ok": True,
        "message_id": msg_id,
        "received_at": received_at.isoformat(),
        "telegram_notified": notified,
        "detail": "Message sent — we'll get back to you soon.",
    }


@app.post("/api/v1/email/password-reset")
def relay_password_reset_email(req: PasswordResetEmailRelayRequest):
    """
    Server-side privileged password-reset email relay.
    Keeps SMTP credentials (Gmail App Password) exclusively on the Render server
    instead of packaging them in customer desktop installations.
    Requires a valid, non-revoked license key already bound to the caller's device_id.
    """
    key = (req.license_key or "").strip()
    dev = (req.device_id or "").strip()
    to_email = (req.to_email or "").strip()
    username = (req.username or "").strip()
    reset_code = (req.reset_code or "").strip()
    ttl_minutes = int(req.ttl_minutes or 10)

    if not key or not dev:
        raise HTTPException(status_code=400, detail="license_key and device_id are required.")
    if not to_email or "@" not in to_email or "." not in to_email.split("@", 1)[-1]:
        raise HTTPException(status_code=400, detail="Valid recipient email is required.")
    if not username or len(username) > 128:
        raise HTTPException(status_code=400, detail="Valid username is required.")
    if not _RESET_CODE_RE.match(reset_code):
        raise HTTPException(status_code=400, detail="Invalid reset code format.")
    if ttl_minutes < 1 or ttl_minutes > 60:
        raise HTTPException(status_code=400, detail="ttl_minutes must be between 1 and 60.")

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT license_key, status, device_id FROM licenses WHERE license_key = %s",
                (key,),
            )
            lic_row = cur.fetchone()

    if lic_row is None:
        raise HTTPException(status_code=403, detail="License key not recognized.")
    if (lic_row.get("status") or "").strip().lower() == "revoked":
        raise HTTPException(status_code=403, detail="Revoked licenses cannot use the email relay.")
    bound_dev = (lic_row.get("device_id") or "").strip()
    if not bound_dev or bound_dev != dev:
        raise HTTPException(status_code=403, detail="License key is not bound to this computer.")

    _check_and_record_email_relay_rate_limit(key)
    try:
        _send_password_reset_smtp(
            to_email=to_email,
            username=username,
            reset_code=reset_code,
            ttl_minutes=ttl_minutes,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Password reset SMTP relay failed for key=%s: %s", key, exc)
        raise HTTPException(status_code=502, detail="Failed to send password reset email.")

    logger.info("[EMAIL RELAY] Sent password reset code for key=%s device=%s", key, dev[:12])
    return {"ok": True, "relayed": True}


@app.post("/api/v1/broadcasts/{broadcast_id}/ack")
def acknowledge_broadcast_endpoint(broadcast_id: int, req: BroadcastAckRequest):
    """Mark an active broadcast message acknowledged by a specific device_id so it does not reappear."""
    key = (req.license_key or "").strip()
    dev = (req.device_id or "").strip()
    if not key or not dev:
        raise HTTPException(status_code=400, detail="license_key and device_id are required.")

    now = _utc_now()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT license_key, device_id FROM licenses WHERE license_key = %s", (key,))
            lic_row = cur.fetchone()
            if lic_row is None:
                raise HTTPException(status_code=404, detail="License key not recognized.")
            bound_dev = (lic_row.get("device_id") or "").strip()
            if bound_dev and bound_dev != dev:
                raise HTTPException(status_code=403, detail="This license key is bound to another computer.")
            cur.execute("SELECT id FROM broadcast_messages WHERE id = %s", (broadcast_id,))
            if cur.fetchone() is None:
                raise HTTPException(status_code=404, detail="Broadcast message not found.")
            cur.execute(
                """
                INSERT INTO broadcast_acknowledgments (broadcast_id, device_id, acknowledged_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (broadcast_id, device_id) DO NOTHING
                """,
                (broadcast_id, dev, now),
            )
    return {"ok": True, "broadcast_id": broadcast_id, "device_id": dev, "acknowledged_at": now.isoformat()}


@app.post("/api/v1/payment-screenshot")
async def submit_payment_screenshot(
    license_key: str = Form(...),
    device_id: str = Form(...),
    claimed_plan: str = Form(...),
    image: UploadFile = File(...),
):
    """
    Client-facing multipart endpoint for uploading manual UPI payment screenshots.
    Stores base64 in Postgres (no ephemeral local disk), enforces 1 submission per
    license key per 10 minutes, and sends a Telegram photo notification to the licensor.
    """
    key = license_key.strip()
    dev = device_id.strip()
    plan_key = claimed_plan.strip().lower()

    raw_bytes = await image.read(MAX_SCREENSHOT_BYTES + 1)
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded screenshot image is empty.")
    if len(raw_bytes) > MAX_SCREENSHOT_BYTES:
        raise HTTPException(status_code=413, detail="Screenshot file exceeds the 5 MB limit.")

    mime_type = _detect_image_mime(raw_bytes)
    if mime_type is None:
        raise HTTPException(status_code=400, detail="Unsupported image format. Upload a PNG, JPEG, or WebP screenshot.")

    now = _utc_now()
    b64_image = base64.b64encode(raw_bytes).decode("ascii")

    with get_db() as conn:
        with conn.cursor() as cur:
            active_plans = _load_plans_map(cur, include_inactive=False)
            if plan_key not in active_plans:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid or inactive plan '{claimed_plan}'. Allowed plans: {', '.join(active_plans.keys())}",
                )
            claimed_plan_meta = active_plans[plan_key]

            cur.execute(
                "SELECT license_key, status, plan, has_paid_renewal, device_id FROM licenses WHERE license_key = %s",
                (key,),
            )
            lic_row = cur.fetchone()
            if lic_row is None:
                raise HTTPException(status_code=404, detail="License key not recognized.")

            bound_dev = (lic_row.get("device_id") or "").strip()
            if bound_dev and bound_dev != dev:
                raise HTTPException(
                    status_code=403,
                    detail="This license key is already activated on another computer and cannot be renewed from this device.",
                )

            if (lic_row.get("status") or "").strip().lower() == "revoked":
                raise HTTPException(
                    status_code=403,
                    detail="Revoked licenses cannot be renewed via self-service payment submission.",
                )

            if plan_key == "launch90" and not _is_first_paid_renewal(lic_row):
                raise HTTPException(
                    status_code=400,
                    detail="Launch Offer (launch90) is only available for first-time paid renewals from trial.",
                )

            # Rate limit: max 1 submission per license key per 10 minutes
            cur.execute(
                """
                SELECT submitted_at
                FROM payment_submissions
                WHERE license_key = %s
                ORDER BY submitted_at DESC
                LIMIT 1
                """,
                (key,),
            )
            last_sub = cur.fetchone()
            if last_sub is not None and last_sub.get("submitted_at") is not None:
                elapsed = now - _as_utc(last_sub["submitted_at"])
                cooldown = timedelta(minutes=SCREENSHOT_RATE_LIMIT_MINUTES)
                if elapsed < cooldown:
                    wait_sec = max(1, int((cooldown - elapsed).total_seconds()))
                    wait_min = (wait_sec + 59) // 60
                    raise HTTPException(
                        status_code=429,
                        detail=f"Rate limit exceeded: please wait ~{wait_min} minute(s) before submitting another screenshot.",
                    )

            cur.execute(
                """
                INSERT INTO payment_submissions (license_key, device_id, claimed_plan, image_data, content_type, price_inr, days, submitted_at, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'pending')
                RETURNING id, submitted_at
                """,
                (
                    key,
                    dev,
                    plan_key,
                    b64_image,
                    mime_type,
                    int(claimed_plan_meta["price_inr"]),
                    int(claimed_plan_meta["days"]),
                    now,
                ),
            )
            inserted = cur.fetchone()
            submission_id = int(inserted["id"])
            submitted_at = _as_utc(inserted["submitted_at"]) or now

    telegram_ok = _send_telegram_payment_notification(
        submission_id=submission_id,
        license_key=key,
        device_id=dev,
        claimed_plan=plan_key,
        submitted_at=submitted_at,
        image_bytes=raw_bytes,
        content_type=mime_type,
        plan_info=claimed_plan_meta,
    )

    return {
        "ok": True,
        "submission_id": submission_id,
        "license_key": key,
        "claimed_plan": plan_key,
        "status": "pending",
        "submitted_at": submitted_at.isoformat(),
        "telegram_notified": telegram_ok,
    }


# ========================================================== ADMIN AUTH & UI
@app.post("/api/v1/admin/login")
def admin_login(req: AdminLoginRequest, request: Request, response: Response):
    ip = _client_ip(request)
    _check_login_rate_limit(ip)

    admin_tok = _get_admin_token()
    if not admin_tok:
        raise HTTPException(status_code=503, detail="Admin login is not configured on the server.")

    submitted_user = (req.username or "").strip()
    submitted_pass = req.password or ""

    def _mask_dbg(val: str | None) -> str:
        s = val or ""
        if len(s) <= 4:
            return f"*** (len={len(s)})"
        return f"{s[:2]}***{s[-2:]} (len={len(s)})"

    with get_db() as conn:
        with conn.cursor() as cur:
            _seed_initial_owner_user(cur)
            cur.execute("SELECT COUNT(*) AS cnt FROM admin_users")
            cnt_row = cur.fetchone()
            if int((cnt_row or {}).get("cnt", 0)) == 0:
                raise HTTPException(status_code=503, detail="Admin login is not configured on the server.")

            cur.execute(
                """
                SELECT id, username, password_hash, email, role
                FROM admin_users
                WHERE LOWER(username) = LOWER(%s)
                LIMIT 1
                """,
                (submitted_user,),
            )
            user_row = cur.fetchone()
            existing_rows_dbg = []
            if user_row is None:
                cur.execute(
                    "SELECT id, username, role, LEFT(password_hash, 12) AS hp, LENGTH(password_hash) AS hl, password_hash FROM admin_users ORDER BY id LIMIT 3"
                )
                existing_rows_dbg = cur.fetchall()

    pw_match = bool(user_row is not None and _verify_password(submitted_pass, user_row.get("password_hash")))
    if user_row is None:
        masked_rows = [
            {
                "id": r["id"],
                "db_user": _mask_dbg(r.get("username")),
                "role": r.get("role"),
                "hash_prefix": r.get("hp"),
                "hash_len": r.get("hl"),
                "bcrypt_match_against_owner_row": _verify_password(submitted_pass, r.get("password_hash")),
            }
            for r in existing_rows_dbg
        ]
        logger.info(
            "LOGIN_DEBUG received_user=%s received_pass=%s db_match_found=False existing_admin_users=%s",
            _mask_dbg(submitted_user),
            _mask_dbg(submitted_pass),
            masked_rows,
        )
    else:
        logger.info(
            "LOGIN_DEBUG received_user=%s received_pass=%s db_match_found=True db_user=%s role=%s hash_len=%s pw_match=%s",
            _mask_dbg(submitted_user),
            _mask_dbg(submitted_pass),
            _mask_dbg(user_row.get("username")),
            user_row.get("role"),
            len(user_row.get("password_hash") or ""),
            pw_match,
        )

    if not pw_match:
        _record_login_failure(ip)
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    _clear_login_failures(ip)
    jti = secrets.token_urlsafe(24)
    now = _utc_now()
    ttl = max(60, int(os.environ.get("ADMIN_SESSION_TTL_SECONDS", str(SESSION_TTL_SECONDS))))
    expires_at = now + timedelta(seconds=ttl)
    user_id = int(user_row["id"])
    canonical_username = str(user_row["username"])
    user_role = (user_row.get("role") or "admin").strip().lower()
    user_email = user_row.get("email")

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM admin_sessions WHERE expires_at < %s", (now - timedelta(days=1),))
            cur.execute(
                """
                INSERT INTO admin_sessions (jti, user_id, username, role, created_at, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (jti, user_id, canonical_username, user_role, now, expires_at),
            )

    token = _sign_session_token(canonical_username, jti, now, expires_at, role=user_role, user_id=user_id)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=_is_https_request(request),
        max_age=ttl,
        path="/",
    )
    return {
        "ok": True,
        "username": canonical_username,
        "email": user_email,
        "role": user_role,
        "token": token,
        "token_type": "Bearer",
        "expires_in": ttl,
        "expires_at": expires_at.isoformat(),
    }


@app.post("/api/v1/admin/logout")
def admin_logout(request: Request, response: Response):
    token, _ = _extract_session_token(request)
    if token:
        payload = _decode_session_token(token, verify_exp=False)
        if payload and payload.get("jti"):
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE admin_sessions SET revoked_at = %s WHERE jti = %s AND revoked_at IS NULL",
                        (_utc_now(), payload["jti"]),
                    )
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        samesite="lax",
        httponly=True,
        secure=_is_https_request(request),
    )
    return {"ok": True, "message": "Logged out."}


@app.get("/api/v1/admin/session")
def get_admin_session(session: dict = Depends(_require_admin_session)):
    with get_db() as conn:
        with conn.cursor() as cur:
            active_plans = _load_plans_map(cur, include_inactive=False)
    return {
        "authenticated": True,
        "user_id": session.get("user_id"),
        "username": session["username"],
        "email": session.get("email"),
        "role": session.get("role", "owner"),
        "is_owner": (session.get("role") or "").lower() == "owner",
        "expires_at": session["expires_at"],
        "plans": _public_plans_dict(active_plans),
    }


@app.get("/api/v1/admin/account")
def get_owner_account(session: dict = Depends(_require_owner_session)):
    """Return the signed-in SystemOwner profile and admin_users directory (hashes excluded)."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, username, email, role, created_at, updated_at
                FROM admin_users
                WHERE id = %s
                """,
                (session["user_id"],),
            )
            me = cur.fetchone()
            if me is None:
                raise HTTPException(status_code=404, detail="Admin account not found.")

            cur.execute(
                """
                SELECT id, username, email, role, created_at, updated_at
                FROM admin_users
                ORDER BY id ASC
                """
            )
            all_rows = cur.fetchall()

    def _ser(r: dict) -> dict:
        return {
            "id": int(r["id"]),
            "username": r["username"],
            "email": r.get("email") or "",
            "role": (r.get("role") or "admin").strip().lower(),
            "created_at": _iso_utc(r.get("created_at")),
            "updated_at": _iso_utc(r.get("updated_at")),
        }

    return {
        "account": _ser(me),
        "accounts": [_ser(r) for r in all_rows],
    }


@app.put("/api/v1/admin/account")
def update_owner_account(
    req: UpdateOwnerAccountRequest,
    request: Request,
    response: Response,
    session: dict = Depends(_require_owner_session),
):
    """
    Allow SystemOwner (`owner`) to update their own username, email, and/or password.
    Requires current password verification, hashes new passwords with bcrypt server-side,
    never logs plaintext credentials, and refreshes the active session token seamlessly.
    """
    if not req.current_password:
        raise HTTPException(status_code=400, detail="Current password is required.")

    now = _utc_now()
    ttl = max(60, int(os.environ.get("ADMIN_SESSION_TTL_SECONDS", str(SESSION_TTL_SECONDS))))
    new_jti = secrets.token_urlsafe(24)
    new_expires_at = now + timedelta(seconds=ttl)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, username, password_hash, email, role, created_at, updated_at
                FROM admin_users
                WHERE id = %s
                """,
                (session["user_id"],),
            )
            me = cur.fetchone()
            if me is None:
                raise HTTPException(status_code=404, detail="Admin account not found.")

            if not _verify_password(req.current_password, me.get("password_hash")):
                raise HTTPException(status_code=403, detail="Current password is incorrect.")

            new_username = (req.username if req.username is not None else me["username"]).strip()
            new_email = (req.email if req.email is not None else (me.get("email") or "")).strip()
            new_pw_raw = req.new_password or ""
            pw_changed = bool(new_pw_raw)

            if not new_username or len(new_username) < 3:
                raise HTTPException(status_code=400, detail="Username must be at least 3 characters.")
            if any(ch.isspace() for ch in new_username):
                raise HTTPException(status_code=400, detail="Username cannot contain whitespace.")
            if new_email and ("@" not in new_email or "." not in new_email.split("@", 1)[-1]):
                raise HTTPException(status_code=400, detail="Please enter a valid email address.")
            if pw_changed and len(new_pw_raw) < 8:
                raise HTTPException(status_code=400, detail="New password must be at least 8 characters.")

            cur.execute(
                """
                SELECT id FROM admin_users
                WHERE LOWER(username) = LOWER(%s) AND id != %s
                LIMIT 1
                """,
                (new_username, me["id"]),
            )
            if cur.fetchone() is not None:
                raise HTTPException(status_code=409, detail="That username is already in use.")

            changed_fields = []
            if new_username != me["username"]:
                changed_fields.append("username")
            if (new_email or None) != (me.get("email") or None):
                changed_fields.append("email")
            if pw_changed:
                changed_fields.append("password")

            new_hash = _hash_password(new_pw_raw) if pw_changed else me["password_hash"]
            cur.execute(
                """
                UPDATE admin_users
                SET username = %s,
                    email = %s,
                    password_hash = %s,
                    updated_at = %s
                WHERE id = %s
                """,
                (new_username, new_email or None, new_hash, now, me["id"]),
            )

            # Rotate current session (and revoke all sessions if password changed)
            if pw_changed:
                cur.execute(
                    "UPDATE admin_sessions SET revoked_at = %s WHERE user_id = %s AND revoked_at IS NULL",
                    (now, me["id"]),
                )
            else:
                cur.execute(
                    "UPDATE admin_sessions SET revoked_at = %s WHERE jti = %s AND revoked_at IS NULL",
                    (now, session["jti"]),
                )

            owner_role = (me.get("role") or "owner").strip().lower()
            cur.execute(
                """
                INSERT INTO admin_sessions (jti, user_id, username, role, created_at, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (new_jti, int(me["id"]), new_username, owner_role, now, new_expires_at),
            )

    fresh_token = _sign_session_token(
        new_username, new_jti, now, new_expires_at, role=owner_role, user_id=int(me["id"])
    )
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=fresh_token,
        httponly=True,
        samesite="lax",
        secure=_is_https_request(request),
        max_age=ttl,
        path="/",
    )
    logger.info(
        "SystemOwner account id=%s updated fields=%s (username='%s').",
        me["id"],
        ",".join(changed_fields) if changed_fields else "none",
        new_username,
    )
    return {
        "ok": True,
        "message": "Admin account updated successfully.",
        "changed_fields": changed_fields,
        "account": {
            "id": int(me["id"]),
            "username": new_username,
            "email": new_email or "",
            "role": owner_role,
            "updated_at": now.isoformat(),
        },
        "token": fresh_token,
        "expires_at": new_expires_at.isoformat(),
    }


@app.get("/admin/login", include_in_schema=False)
def admin_login_page(request: Request):
    token, _ = _extract_session_token(request)
    if token and _get_admin_token() and _verify_active_session(token) is not None:
        return RedirectResponse(url="/admin", status_code=302)
    html = (ADMIN_UI_DIR / "login.html").read_text(encoding="utf-8")
    return HTMLResponse(content=html, headers={"Content-Security-Policy": ADMIN_PAGE_CSP})


@app.get("/admin", include_in_schema=False)
@app.get("/admin/", include_in_schema=False)
def admin_dashboard_page(request: Request):
    token, source = _extract_session_token(request)
    session = _verify_active_session(token) if token else None
    if session is not None:
        _check_admin(_get_admin_token())
        html = (ADMIN_UI_DIR / "dashboard.html").read_text(encoding="utf-8")
        return HTMLResponse(content=html, headers={"Content-Security-Policy": ADMIN_PAGE_CSP})

    accept = (request.headers.get("accept") or "").lower()
    if "application/json" in accept and "text/html" not in accept:
        raise HTTPException(status_code=401, detail="Authentication required.")

    target = "/admin/login?expired=1" if (source == "cookie" and token) else "/admin/login"
    redirect = RedirectResponse(url=target, status_code=302)
    if source == "cookie":
        redirect.delete_cookie(
            key=SESSION_COOKIE_NAME,
            path="/",
            samesite="lax",
            httponly=True,
            secure=_is_https_request(request),
        )
    return redirect


# =============================================================== ADMIN ROUTES
@app.post("/api/v1/admin/create")
def create_license(req: CreateLicenseRequest, auth: dict = Depends(_require_admin_api)):
    plan_key = (req.plan or "trial").strip().lower()
    actor = str(auth.get("username") or auth.get("auth_type") or "admin")
    is_owner = (auth.get("role") or "").strip().lower() == "owner" or auth.get("auth_type") == "admin_token"
    if req.allow_repeat_trial and not is_owner:
        raise HTTPException(
            status_code=403,
            detail="SystemOwner (owner) privileges are required to authorize a repeat trial exception.",
        )

    with get_db() as conn:
        with conn.cursor() as cur:
            all_plans = _load_plans_map(cur, include_inactive=True)
            if plan_key != "trial" and plan_key not in all_plans:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid plan '{req.plan}'. Use 'trial' or one of: {', '.join(all_plans.keys())}",
                )

            configured_trial_days = _get_configured_trial_days(cur)
            duration_days = max(
                1,
                int(req.days)
                if req.days is not None
                else (configured_trial_days if plan_key == "trial" else int(all_plans[plan_key]["days"])),
            )
            has_paid = plan_key != "trial"
            # Free trial countdown starts at FIRST successful device activation (expires_at = NULL until bound).
            # Paid licenses start immediately upon provisioning.
            expires_at = None if plan_key == "trial" else (_utc_now() + timedelta(days=duration_days))
            trial_days = duration_days if plan_key == "trial" else configured_trial_days

            clean_label = (req.label or "").strip()[:120] or None
            explicit_key = (req.license_key or "").strip()
            if explicit_key:
                lic_key = explicit_key
                cur.execute(
                    """
                    INSERT INTO licenses (
                        license_key, status, note, label, plan, expires_at,
                        has_paid_renewal, activated_at, trial_days, allow_repeat_trial
                    )
                    VALUES (%s, 'active', %s, %s, %s, %s, %s, NULL, %s, %s)
                    ON CONFLICT (license_key) DO NOTHING
                    RETURNING license_key
                    """,
                    (lic_key, req.note, clean_label, plan_key, expires_at, has_paid, trial_days, bool(req.allow_repeat_trial)),
                )
                if cur.fetchone() is None:
                    raise HTTPException(
                        status_code=409,
                        detail=f"License key '{lic_key}' already exists. Duplicate keys cannot overwrite existing subscriptions.",
                    )
            else:
                lic_key = ""
                for _ in range(10):
                    candidate = _generate_secure_license_key()
                    cur.execute(
                        """
                        INSERT INTO licenses (
                            license_key, status, note, label, plan, expires_at,
                            has_paid_renewal, activated_at, trial_days, allow_repeat_trial
                        )
                        VALUES (%s, 'active', %s, %s, %s, %s, %s, NULL, %s, %s)
                        ON CONFLICT (license_key) DO NOTHING
                        RETURNING license_key
                        """,
                        (candidate, req.note, clean_label, plan_key, expires_at, has_paid, trial_days, bool(req.allow_repeat_trial)),
                    )
                    if cur.fetchone() is not None:
                        lic_key = candidate
                        break
                if not lic_key:
                    raise HTTPException(status_code=500, detail="Failed to generate a unique license key.")

            _record_license_audit(
                cur,
                license_key=lic_key,
                action="license_created",
                actor=actor,
                previous_plan=None,
                new_plan=plan_key,
                previous_expires_at=None,
                new_expires_at=expires_at,
                previous_has_paid_renewal=None,
                new_has_paid_renewal=has_paid,
                note=(
                    (req.note or "").strip()
                    or (f"Created {trial_days}d trial key (starts on activation)" if plan_key == "trial" else f"Created {plan_key} key ({duration_days}d)")
                ),
            )
            logger.info("[LICENSE CREATED] actor=%s key=%s label=%s plan=%s starts_on_activation=%s", actor, lic_key, clean_label, plan_key, expires_at is None)

    return {
        "ok": True,
        "license_key": lic_key,
        "label": clean_label,
        "status": "active",
        "plan": plan_key,
        "trial_days": trial_days if plan_key == "trial" else None,
        "expires_at": _iso_utc(expires_at),
        "starts_on_activation": expires_at is None,
        "allow_repeat_trial": bool(req.allow_repeat_trial),
    }


@app.post("/api/v1/admin/label")
def update_license_label(
    license_key: str = Query(...),
    label: str = Query(default=""),
    auth: dict = Depends(_require_admin_api),
):
    """Set or update a human-friendly identification label on a license (e.g. 'Vivek's Dev PC')."""
    key = license_key.strip()
    clean_label = (label or "").strip()
    if len(clean_label) > 120:
        raise HTTPException(status_code=400, detail="Label must be 120 characters or fewer.")
    new_val = clean_label or None
    actor = str(auth.get("username") or auth.get("auth_type") or "admin")

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT license_key, label, plan, expires_at, has_paid_renewal FROM licenses WHERE license_key = %s FOR UPDATE",
                (key,),
            )
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Key not found")
            prev_label = row.get("label")
            cur.execute("UPDATE licenses SET label = %s WHERE license_key = %s", (new_val, key))
            plan = (row.get("plan") or "trial").strip().lower()
            exp = _as_utc(row.get("expires_at"))
            has_paid = bool(row.get("has_paid_renewal", False))
            _record_license_audit(
                cur,
                license_key=key,
                action="label_updated",
                actor=actor,
                previous_plan=plan,
                new_plan=plan,
                previous_expires_at=exp,
                new_expires_at=exp,
                previous_has_paid_renewal=has_paid,
                new_has_paid_renewal=has_paid,
                note=f"Label updated: '{prev_label or '—'}' -> '{new_val or '—'}'",
            )
    logger.info("[LICENSE LABEL] actor=%s key=%s label=%r", actor, key, new_val)
    return {
        "ok": True,
        "license_key": key,
        "label": new_val,
        "previous_label": prev_label,
    }


@app.post("/api/v1/admin/delete")
def delete_license(
    license_key: str = Query(...),
    clear_device_trial: bool = Query(
        default=False,
        description="Explicit opt-in: also delete device_trials row for the bound device_id so it may re-provision a fresh trial.",
    ),
    auth: dict = Depends(_require_admin_api),
):
    """
    Hard-delete a license row for testing/reissue.
    By default preserves `device_trials` so a device cannot silently bypass one-trial-per-device;
    clearing the trial record requires an explicit separate confirmation step (either via
    `POST /api/v1/admin/device-trials/override` or `clear_device_trial=true`).
    """
    key = license_key.strip()
    actor = str(auth.get("username") or auth.get("auth_type") or "admin")
    is_owner = (auth.get("role") or "").strip().lower() == "owner" or auth.get("auth_type") == "admin_token"
    if clear_device_trial and not is_owner:
        raise HTTPException(
            status_code=403,
            detail="SystemOwner (owner) privileges are required to clear device_trials history.",
        )

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT license_key, device_id, label, status, plan, expires_at, has_paid_renewal
                FROM licenses
                WHERE license_key = %s
                FOR UPDATE
                """,
                (key,),
            )
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Key not found")

            prev_device = (row.get("device_id") or "").strip() or None
            prev_label = row.get("label")
            plan = (row.get("plan") or "trial").strip().lower()
            exp = _as_utc(row.get("expires_at"))
            has_paid = bool(row.get("has_paid_renewal", False))

            had_trial = False
            trial_cleared = False
            if prev_device:
                cur.execute(
                    "SELECT device_id FROM device_trials WHERE device_id = %s",
                    (prev_device,),
                )
                had_trial = cur.fetchone() is not None

            cur.execute("DELETE FROM licenses WHERE license_key = %s", (key,))

            if clear_device_trial and prev_device and had_trial:
                cur.execute("DELETE FROM device_trials WHERE device_id = %s", (prev_device,))
                trial_cleared = True
                _record_license_audit(
                    cur,
                    license_key=key,
                    action="trial_override",
                    actor=actor,
                    note=f"Explicitly cleared device_trials for device {prev_device} during license deletion",
                )

            _record_license_audit(
                cur,
                license_key=key,
                action="license_deleted",
                actor=actor,
                previous_plan=plan,
                new_plan=None,
                previous_expires_at=exp,
                new_expires_at=None,
                previous_has_paid_renewal=has_paid,
                new_has_paid_renewal=None,
                note=(
                    f"Hard-deleted license '{key}'"
                    + (f" (label='{prev_label}')" if prev_label else "")
                    + f", device={prev_device or 'unbound'}, device_trial_cleared={trial_cleared}"
                ),
            )
    logger.info(
        "[LICENSE DELETED] actor=%s key=%s label=%r device=%s had_trial=%s trial_cleared=%s",
        actor,
        key,
        prev_label,
        prev_device,
        had_trial,
        trial_cleared,
    )
    return {
        "ok": True,
        "action": "license_deleted",
        "license_key": key,
        "label": prev_label,
        "previous_device_id": prev_device,
        "had_device_trial": had_trial,
        "device_trial_cleared": trial_cleared,
    }


@app.get("/api/v1/admin/device-trials")
def get_admin_device_trials(
    device_id: str | None = Query(
        default=None,
        description="Optional device_id (exact or prefix) to inspect current trial status before clearing.",
    ),
    limit: int = Query(default=100, ge=1, le=500),
    _auth: dict = Depends(_require_owner_or_token),
):
    """
    SystemOwner-only: inspect `device_trials` records alongside any currently bound `licenses` row.
    - When `device_id` is supplied (exact or unambiguous prefix): returns that device's trial status
      (`used`, `first_activated_at`, `first_license_key`, `note`, `bound_license`, `is_orphaned`)
      so SystemOwner has full context before deliberately clearing a stuck trial record.
    - When `device_id` is omitted: lists recent `device_trials` rows (flagging orphaned records that
      have no bound license row and would receive `trial_already_used`).
    """
    query = (device_id or "").strip()

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT device_id, first_license_key, first_activated_at, note
                FROM device_trials
                ORDER BY first_activated_at DESC, device_id ASC
                LIMIT %s
                """,
                (500 if query else limit,),
            )
            dt_rows = cur.fetchall()

            cur.execute(
                """
                SELECT license_key, label, status, plan, expires_at, device_id
                FROM licenses
                WHERE device_id IS NOT NULL
                ORDER BY license_key ASC
                """
            )
            lic_rows = cur.fetchall()

    bound_by_dev: dict[str, dict] = {}
    for r in lic_rows:
        dev = (r.get("device_id") or "").strip()
        if dev:
            bound_by_dev[dev] = {
                "license_key": str(r["license_key"]),
                "label": r.get("label"),
                "status": str(r.get("status") or "active").strip().lower(),
                "plan": str(r.get("plan") or "trial").strip().lower(),
                "expires_at": _iso_utc(r.get("expires_at")),
            }

    def _serialize_trial(row: dict) -> dict:
        did = str(row["device_id"])
        bound = bound_by_dev.get(did)
        return {
            "device_id": did,
            "used": True,
            "first_license_key": row.get("first_license_key"),
            "first_activated_at": _iso_utc(row.get("first_activated_at")),
            "note": row.get("note") or "",
            "bound_license": bound,
            "is_orphaned": bound is None,
        }

    all_trials = [_serialize_trial(r) for r in dt_rows]

    if query:
        q_low = query.lower()
        exact = next((t for t in all_trials if t["device_id"].lower() == q_low), None)
        if exact is not None:
            return {
                "query": query,
                **exact,
                "ambiguous": False,
                "matches": [exact],
            }

        prefix_matches = [t for t in all_trials if t["device_id"].lower().startswith(q_low)]
        if len(prefix_matches) == 1:
            match = prefix_matches[0]
            return {
                "query": query,
                **match,
                "ambiguous": False,
                "matches": [match],
            }
        if len(prefix_matches) > 1:
            return {
                "query": query,
                "device_id": None,
                "used": True,
                "first_license_key": None,
                "first_activated_at": None,
                "note": f"Multiple ({len(prefix_matches)}) device trial records match prefix '{query}'. Pick the exact device_id.",
                "bound_license": None,
                "is_orphaned": False,
                "ambiguous": True,
                "matches": prefix_matches[:20],
            }

        # Not present in device_trials -> check if any bound license matches query
        bound_match = None
        for did, binfo in bound_by_dev.items():
            if did.lower() == q_low or did.lower().startswith(q_low):
                bound_match = binfo
                query_dev = did
                break
        else:
            query_dev = query

        return {
            "query": query,
            "device_id": query_dev,
            "used": False,
            "first_license_key": None,
            "first_activated_at": None,
            "note": "",
            "bound_license": bound_match,
            "is_orphaned": False,
            "ambiguous": False,
            "matches": [],
        }

    return {
        "trials": all_trials[:limit],
        "total": len(all_trials),
        "orphaned_count": sum(1 for t in all_trials if t["is_orphaned"]),
    }


@app.post("/api/v1/admin/device-trials/override")
def override_device_trial_history(
    req: DeviceTrialOverrideRequest,
    auth: dict = Depends(_require_owner_or_token),
):
    """
    SystemOwner-only exception mechanism: clear a device's prior trial record so an
    authorized replacement or recovery installation may start a fresh trial.
    """
    dev = (req.device_id or "").strip()
    if not dev:
        raise HTTPException(status_code=400, detail="device_id is required.")
    actor = str(auth.get("username") or auth.get("auth_type") or "owner")
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT device_id, first_license_key FROM device_trials WHERE device_id = %s FOR UPDATE",
                (dev,),
            )
            existing = cur.fetchone()
            cur.execute("DELETE FROM device_trials WHERE device_id = %s", (dev,))
            prev_key = (existing or {}).get("first_license_key") or f"DEVICE:{dev[:12]}"
            _record_license_audit(
                cur,
                license_key=str(prev_key),
                action="trial_override",
                actor=actor,
                note=(req.note or "").strip() or f"Owner authorized trial history override for device {dev}",
            )
    logger.info("[DEVICE TRIAL OVERRIDE] actor=%s device=%s had_record=%s", actor, dev[:12], existing is not None)
    return {
        "ok": True,
        "device_id": dev,
        "cleared": existing is not None,
    }


@app.post("/api/v1/admin/renew")
def renew_license(
    license_key: str = Query(...),
    plan: str = Query(...),
    auth: dict = Depends(_require_admin_api),
):
    actor = str(auth.get("username") or auth.get("auth_type") or "admin")
    with get_db() as conn:
        with conn.cursor() as cur:
            return _apply_renewal(cur, license_key.strip(), plan, actor=actor, audit_action="renew")


@app.post("/api/v1/admin/reset-plan")
def reset_license_plan(
    license_key: str = Query(...),
    plan: str = Query(default="trial"),
    auth: dict = Depends(_require_owner_or_token),
):
    """
    SystemOwner handover reset: discards any elapsed or remaining period and starts
    a fresh full plan period (TRIAL_DAYS for 'trial', or PLANS[plan]['days']) from NOW.
    Restores has_paid_renewal = FALSE when resetting to 'trial' so launch90 stays eligible.
    Distinct from /renew (which extends on top of remaining time for paying customers).
    """
    actor = str(auth.get("username") or auth.get("auth_type") or "owner")
    with get_db() as conn:
        with conn.cursor() as cur:
            return _apply_plan_reset(cur, license_key.strip(), plan, actor=actor)


@app.post("/api/v1/admin/unbind-device")
def unbind_license_device(
    license_key: str = Query(...),
    auth: dict = Depends(_require_owner_or_token),
):
    """
    SystemOwner device transfer action: clears the bound device_id on a license key
    so it can be activated on a replacement computer. The previous computer will be
    blocked on its next check once the new computer binds the key.
    """
    key = license_key.strip()
    actor = str(auth.get("username") or auth.get("auth_type") or "owner")
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT license_key, device_id, plan, expires_at, has_paid_renewal FROM licenses WHERE license_key = %s FOR UPDATE",
                (key,),
            )
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Key not found")
            prev_device = (row.get("device_id") or "").strip() or None
            cur.execute("UPDATE licenses SET device_id = NULL WHERE license_key = %s", (key,))
            # Hold any pending queued outgoing admin messages so a replacement device cannot
            # accidentally receive messages intended for the previous bound installation.
            held_count = 0
            if prev_device:
                cur.execute(
                    """
                    UPDATE license_messages
                    SET status = 'held_device_changed'
                    WHERE license_key = %s
                      AND sender_type = 'admin'
                      AND status = 'queued'
                      AND (target_device_id IS NULL OR target_device_id = %s)
                    """,
                    (key, prev_device),
                )
                held_count = int(cur.rowcount or 0)
            plan = (row.get("plan") or "trial").strip().lower()
            exp = _as_utc(row.get("expires_at"))
            has_paid = bool(row.get("has_paid_renewal", False))
            _record_license_audit(
                cur,
                license_key=key,
                action="unbind_device",
                actor=actor,
                previous_plan=plan,
                new_plan=plan,
                previous_expires_at=exp,
                new_expires_at=exp,
                previous_has_paid_renewal=has_paid,
                new_has_paid_renewal=has_paid,
                note=f"Unbound device {prev_device or 'none'} to allow transfer to another PC",
            )
            if held_count > 0:
                _record_license_audit(
                    cur,
                    license_key=key,
                    action="messages_held_on_unbind",
                    actor=actor,
                    previous_plan=plan,
                    new_plan=plan,
                    previous_expires_at=exp,
                    new_expires_at=exp,
                    previous_has_paid_renewal=has_paid,
                    new_has_paid_renewal=has_paid,
                    note=f"Held {held_count} queued admin message(s) after unbinding device {prev_device[:12]}",
                )
            logger.info(
                "[LICENSE UNBIND_DEVICE] actor=%s key=%s previous_device=%s held_messages=%d",
                actor,
                key,
                prev_device,
                held_count,
            )
    return {
        "ok": True,
        "action": "unbind_device",
        "license_key": key,
        "previous_device_id": prev_device,
        "device_id": None,
        "held_message_count": held_count,
    }


@app.get("/api/v1/admin/audit-log")
def list_license_audit_log(
    limit: int = Query(default=50, ge=1, le=200),
    _auth: dict = Depends(_require_admin_api),
):
    """Return recent license lifecycle audit entries (distinguishing handover resets from paid renewals)."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, license_key, action, actor, previous_plan, new_plan,
                       previous_expires_at, new_expires_at,
                       previous_has_paid_renewal, new_has_paid_renewal,
                       note, created_at
                FROM license_audit_log
                ORDER BY created_at DESC, id DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()
    return [
        {
            "id": int(r["id"]),
            "license_key": r["license_key"],
            "action": r["action"],
            "actor": r["actor"],
            "previous_plan": r.get("previous_plan"),
            "new_plan": r.get("new_plan"),
            "previous_expires_at": _iso_utc(r.get("previous_expires_at")),
            "new_expires_at": _iso_utc(r.get("new_expires_at")),
            "previous_has_paid_renewal": r.get("previous_has_paid_renewal"),
            "new_has_paid_renewal": r.get("new_has_paid_renewal"),
            "note": r.get("note") or "",
            "created_at": _iso_utc(r.get("created_at")),
        }
        for r in rows
    ]


@app.post("/api/v1/admin/revoke")
def revoke_license(license_key: str, auth: dict = Depends(_require_admin_api)):
    key = license_key.strip()
    actor = str(auth.get("username") or auth.get("auth_type") or "admin")
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT license_key, status, plan, expires_at, has_paid_renewal FROM licenses WHERE license_key = %s FOR UPDATE",
                (key,),
            )
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Key not found")
            cur.execute("UPDATE licenses SET status = 'revoked' WHERE license_key = %s", (key,))
            plan = (row.get("plan") or "trial").strip().lower()
            exp = _as_utc(row.get("expires_at"))
            has_paid = bool(row.get("has_paid_renewal", False))
            _record_license_audit(
                cur,
                license_key=key,
                action="revoked",
                actor=actor,
                previous_plan=plan,
                new_plan=plan,
                previous_expires_at=exp,
                new_expires_at=exp,
                previous_has_paid_renewal=has_paid,
                new_has_paid_renewal=has_paid,
                note=f"Revoked license (previous status={row.get('status')})",
            )
            logger.info("[LICENSE REVOKED] actor=%s key=%s", actor, key)
    return {"ok": True, "license_key": key, "status": "revoked"}


@app.post("/api/v1/admin/reactivate")
def reactivate_license(license_key: str, auth: dict = Depends(_require_owner_or_token)):
    """SystemOwner-only explicit reactivation of a revoked license (required before any renewal)."""
    key = license_key.strip()
    actor = str(auth.get("username") or auth.get("auth_type") or "owner")
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT license_key, status, plan, expires_at, has_paid_renewal FROM licenses WHERE license_key = %s FOR UPDATE",
                (key,),
            )
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Key not found")
            cur.execute("UPDATE licenses SET status = 'active' WHERE license_key = %s", (key,))
            plan = (row.get("plan") or "trial").strip().lower()
            exp = _as_utc(row.get("expires_at"))
            has_paid = bool(row.get("has_paid_renewal", False))
            _record_license_audit(
                cur,
                license_key=key,
                action="reactivated",
                actor=actor,
                previous_plan=plan,
                new_plan=plan,
                previous_expires_at=exp,
                new_expires_at=exp,
                previous_has_paid_renewal=has_paid,
                new_has_paid_renewal=has_paid,
                note=f"Owner reactivated license (previous status={row.get('status')})",
            )
            logger.info("[LICENSE REACTIVATED] actor=%s key=%s", actor, key)
    return {"ok": True, "license_key": key, "status": "active"}


@app.post("/api/v1/admin/expire")
def force_expire_license(
    license_key: str = Query(...),
    days_from_now: float | None = Query(
        default=None,
        description="Optional offset in days from now (e.g. 3 for expiry-warning testing; omit or <=0 to force expired).",
    ),
    _auth: dict = Depends(_require_admin_api),
):
    """Admin test helper: move a license's expires_at into the past (or N days from now) for testing."""
    now = _utc_now()
    if days_from_now is None:
        target_exp = now - timedelta(hours=1)
    else:
        target_exp = now + timedelta(days=float(days_from_now))
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE licenses SET status = 'active', expires_at = %s WHERE license_key = %s",
                (target_exp, license_key.strip()),
            )
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Key not found")
    derived_status = "expired" if target_exp <= now else "active"
    return {
        "ok": True,
        "license_key": license_key.strip(),
        "status": derived_status,
        "expires_at": target_exp.isoformat(),
    }


@app.get("/api/v1/admin/list")
def list_licenses(_auth: dict = Depends(_require_admin_api)):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT license_key, status, plan, expires_at, has_paid_renewal,
                       device_id, app_version, last_seen, note, label,
                       activated_at, trial_days, allow_repeat_trial
                FROM licenses
                ORDER BY license_key ASC
                """
            )
            return cur.fetchall()


@app.get("/api/v1/admin/payment-submissions")
def list_payment_submissions(
    status: str = Query(default="pending"),
    _auth: dict = Depends(_require_admin_api),
):
    """List payment screenshot submissions (defaults to 'pending'; pass status=all for full history)."""
    status_filter = (status or "pending").strip().lower()
    if status_filter not in {"pending", "approved", "rejected", "all"}:
        raise HTTPException(status_code=400, detail="Invalid status filter.")

    with get_db() as conn:
        with conn.cursor() as cur:
            all_plans = _load_plans_map(cur, include_inactive=True)
            if status_filter == "all":
                cur.execute(
                    """
                    SELECT id, license_key, device_id, claimed_plan, image_data,
                           content_type, price_inr, days, submitted_at, status
                    FROM payment_submissions
                    ORDER BY submitted_at DESC
                    """
                )
            else:
                cur.execute(
                    """
                    SELECT id, license_key, device_id, claimed_plan, image_data,
                           content_type, price_inr, days, submitted_at, status
                    FROM payment_submissions
                    WHERE status = %s
                    ORDER BY submitted_at DESC
                    """,
                    (status_filter,),
                )
            rows = cur.fetchall()

    results = []
    for row in rows:
        plan_key = row["claimed_plan"]
        plan_meta = all_plans.get(plan_key, {})
        mime = row.get("content_type") or "image/png"
        b64 = row["image_data"]
        snap_price = row.get("price_inr")
        snap_days = row.get("days")
        results.append({
            "id": row["id"],
            "license_key": row["license_key"],
            "device_id": row["device_id"],
            "claimed_plan": plan_key,
            "plan_label": plan_meta.get("label", plan_key),
            "price_inr": snap_price if snap_price is not None else plan_meta.get("price_inr"),
            "days": snap_days if snap_days is not None else plan_meta.get("days"),
            "submitted_at": _iso_utc(row["submitted_at"]),
            "status": row["status"],
            "content_type": mime,
            "image_data": b64,
            "image_data_uri": f"data:{mime};base64,{b64}",
        })
    return results


@app.get("/api/v1/admin/payment-submissions/{submission_id}/image")
def view_payment_submission_image(
    submission_id: int,
    _auth: dict = Depends(_require_admin_api),
):
    """Return the raw decoded screenshot image for direct viewing."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT image_data, content_type FROM payment_submissions WHERE id = %s",
                (submission_id,),
            )
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Submission not found")
    raw = base64.b64decode(row["image_data"])
    return Response(content=raw, media_type=row.get("content_type") or "image/png")


@app.post("/api/v1/admin/payment-submissions/{submission_id}/approve")
def approve_payment_submission(
    submission_id: int,
    auth: dict = Depends(_require_admin_api),
):
    """Mark a pending submission approved and automatically apply the plan renewal atomically."""
    actor = str(auth.get("username") or auth.get("auth_type") or "admin")
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, license_key, claimed_plan, status
                FROM payment_submissions
                WHERE id = %s
                FOR UPDATE
                """,
                (submission_id,),
            )
            sub = cur.fetchone()
            if sub is None:
                raise HTTPException(status_code=404, detail="Submission not found")
            if sub["status"] != "pending":
                raise HTTPException(
                    status_code=409,
                    detail=f"Submission #{submission_id} is already '{sub['status']}'.",
                )

            renewal = _apply_renewal(
                cur,
                sub["license_key"],
                sub["claimed_plan"],
                actor=actor,
                audit_action="payment_approved",
                audit_note=f"Approved payment submission #{submission_id} ({sub['claimed_plan']})",
            )
            cur.execute(
                "UPDATE payment_submissions SET status = 'approved' WHERE id = %s",
                (submission_id,),
            )
    return {
        "ok": True,
        "submission_id": submission_id,
        "submission_status": "approved",
        "renewal": renewal,
    }


@app.post("/api/v1/admin/payment-submissions/{submission_id}/reject")
def reject_payment_submission(
    submission_id: int,
    _auth: dict = Depends(_require_admin_api),
):
    """Mark a pending submission rejected without applying any license renewal."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, status FROM payment_submissions WHERE id = %s FOR UPDATE",
                (submission_id,),
            )
            sub = cur.fetchone()
            if sub is None:
                raise HTTPException(status_code=404, detail="Submission not found")
            if sub["status"] != "pending":
                raise HTTPException(
                    status_code=409,
                    detail=f"Submission #{submission_id} is already '{sub['status']}'.",
                )
            cur.execute(
                "UPDATE payment_submissions SET status = 'rejected' WHERE id = %s",
                (submission_id,),
            )
    return {
        "ok": True,
        "submission_id": submission_id,
        "submission_status": "rejected",
    }


def _plan_display_label(plan_key: str | None, plans_map: dict[str, dict] | None = None) -> str:
    k = (plan_key or "trial").strip().lower()
    if k == "trial":
        return "Free Trial"
    source = plans_map if plans_map is not None else PLANS
    info = source.get(k)
    return info["label"] if info else k.title()


def _compute_days_remaining(expires_at: datetime | None, now: datetime) -> int | None:
    exp = _as_utc(expires_at)
    if exp is None:
        return None
    remaining_sec = (exp - now).total_seconds()
    if remaining_sec <= 0:
        return 0
    return int(math.ceil(remaining_sec / 86400.0))


@app.get("/api/v1/admin/summary")
def admin_dashboard_summary(
    warning_days: int = Query(default=7, ge=1, le=60),
    _auth: dict = Depends(_require_admin_api),
):
    """
    Lightweight overview payload for the Admin Dashboard Home tab.
    Computes overall health state (`all_good` vs `needs_attention`), actionable
    issues, active fleet list, counts, and current-month approved revenue without
    transferring base64 payment screenshot blobs.
    """
    now = _utc_now()

    with get_db() as conn:
        with conn.cursor() as cur:
            all_plans = _load_plans_map(cur, include_inactive=True)
            cur.execute(
                """
                SELECT license_key, status, plan, expires_at, has_paid_renewal,
                       device_id, app_version, last_seen, note, label
                FROM licenses
                ORDER BY license_key ASC
                """
            )
            license_rows = cur.fetchall()

            cur.execute(
                """
                SELECT id, license_key, claimed_plan, price_inr, days, submitted_at, status
                FROM payment_submissions
                ORDER BY submitted_at DESC
                """
            )
            submission_rows = cur.fetchall()

    issues: list[dict] = []
    active_licenses: list[dict] = []
    enriched_all: list[dict] = []

    counts = {
        "total_licenses": len(license_rows),
        "active_licenses": 0,
        "expiring_soon_licenses": 0,
        "expired_licenses": 0,
        "revoked_licenses": 0,
        "pending_payments": 0,
        "approved_payments_this_month": 0,
        "revenue_this_month_inr": 0,
    }

    for row in license_rows:
        key = row["license_key"]
        raw_status = (row.get("status") or "active").strip().lower()
        plan = (row.get("plan") or "trial").strip().lower()
        exp_dt = _as_utc(row.get("expires_at"))
        days_rem = _compute_days_remaining(exp_dt, now)

        if raw_status == "revoked":
            eff = "revoked"
            counts["revoked_licenses"] += 1
            issues.append({
                "type": "revoked",
                "license_key": key,
                "severity": "critical",
                "title": f"{key} — Revoked",
                "detail": f"License is manually revoked ({_plan_display_label(plan, all_plans)}).",
                "target_tab": "licenses",
                "action_label": "Manage in Licenses",
            })
        elif exp_dt is not None and exp_dt <= now:
            eff = "expired"
            counts["expired_licenses"] += 1
            issues.append({
                "type": "expired",
                "license_key": key,
                "severity": "critical",
                "title": f"{key} — Expired",
                "detail": f"{_plan_display_label(plan, all_plans)} expired on {exp_dt.strftime('%Y-%m-%d')}.",
                "target_tab": "licenses",
                "action_label": "Renew in Licenses",
            })
        elif days_rem is not None and days_rem <= warning_days:
            eff = "expiring_soon"
            counts["expiring_soon_licenses"] += 1
            unit = "day" if days_rem == 1 else "days"
            issues.append({
                "type": "expiring_soon",
                "license_key": key,
                "severity": "warning",
                "title": f"{key} — Expiring in {days_rem} {unit}",
                "detail": f"{_plan_display_label(plan, all_plans)} ends on {exp_dt.strftime('%Y-%m-%d')}.",
                "target_tab": "licenses",
                "action_label": "View in Licenses",
            })
        else:
            eff = "active"
            counts["active_licenses"] += 1

        item = {
            "license_key": key,
            "status": raw_status,
            "effective_status": eff,
            "plan": plan,
            "plan_label": _plan_display_label(plan, all_plans),
            "expires_at": _iso_utc(exp_dt),
            "expires_date": exp_dt.strftime("%Y-%m-%d") if exp_dt else None,
            "days_remaining": days_rem,
            "device_id": row.get("device_id"),
            "app_version": row.get("app_version"),
            "last_seen": _iso_utc(row.get("last_seen")),
            "note": row.get("note"),
            "label": row.get("label"),
        }
        enriched_all.append(item)
        if eff == "active":
            active_licenses.append(item)

    for sub in submission_rows:
        st = (sub.get("status") or "").strip().lower()
        if st == "pending":
            counts["pending_payments"] += 1
        elif st == "approved":
            sub_dt = _as_utc(sub.get("submitted_at"))
            if sub_dt is not None and sub_dt.year == now.year and sub_dt.month == now.month:
                counts["approved_payments_this_month"] += 1
                snap_price = sub.get("price_inr")
                if snap_price is not None:
                    counts["revenue_this_month_inr"] += int(snap_price)
                else:
                    plan_meta = all_plans.get((sub.get("claimed_plan") or "").strip().lower(), {})
                    counts["revenue_this_month_inr"] += int(plan_meta.get("price_inr") or 0)

    if counts["pending_payments"] > 0:
        n_pend = counts["pending_payments"]
        noun = "payment submission" if n_pend == 1 else "payment submissions"
        issues.insert(0, {
            "type": "pending_payments",
            "license_key": None,
            "severity": "action",
            "title": f"{n_pend} pending {noun}",
            "detail": "Manual UPI screenshot verification awaiting review.",
            "target_tab": "pending",
            "action_label": "Review Pending Payments",
        })

    if counts["total_licenses"] == 0:
        issues.append({
            "type": "no_licenses",
            "license_key": None,
            "severity": "info",
            "title": "No licenses provisioned yet",
            "detail": "Create a license key in the Licenses tab to get started.",
            "target_tab": "licenses",
            "action_label": "Open Licenses",
        })

    primary_license = None
    if len(enriched_all) == 1:
        primary_license = enriched_all[0]
    elif active_licenses:
        primary_license = next(
            (x for x in active_licenses if x["license_key"] == "VIVEK-ANPR-0001"),
            active_licenses[0],
        )
    elif enriched_all:
        primary_license = enriched_all[0]

    overall_state = "all_good" if (counts["total_licenses"] > 0 and len(issues) == 0) else "needs_attention"

    return {
        "overall_state": overall_state,
        "primary_license": primary_license,
        "issues": issues,
        "active_licenses": active_licenses,
        "counts": counts,
        "warning_days": warning_days,
        "generated_at": now.isoformat(),
    }


# ========================================= OWNER BROADCASTS & LIVE PRICING
@app.get("/api/v1/admin/broadcasts")
def list_broadcasts(_auth: dict = Depends(_require_owner_or_token)):
    """SystemOwner-only: list all server-to-client broadcast messages with acknowledgment counts."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT b.id, b.message, b.tone, b.created_at, b.active, b.created_by,
                       COUNT(a.device_id) AS ack_count
                FROM broadcast_messages b
                LEFT JOIN broadcast_acknowledgments a ON a.broadcast_id = b.id
                GROUP BY b.id
                ORDER BY b.created_at DESC, b.id DESC
                """
            )
            rows = cur.fetchall()
    return [
        {
            "id": int(r["id"]),
            "message": str(r["message"]),
            "tone": str(r.get("tone") or "notice"),
            "active": bool(r.get("active", False)),
            "created_by": str(r.get("created_by") or "owner"),
            "created_at": _iso_utc(r.get("created_at")),
            "ack_count": int(r.get("ack_count") or 0),
        }
        for r in rows
    ]


@app.post("/api/v1/admin/broadcasts")
def create_broadcast(req: CreateBroadcastRequest, auth: dict = Depends(_require_owner_or_token)):
    """SystemOwner-only: publish a new active broadcast notification to client apps."""
    msg = (req.message or "").strip()
    if not msg:
        raise HTTPException(status_code=400, detail="Broadcast message cannot be empty.")
    if len(msg) > 2000:
        raise HTTPException(status_code=400, detail="Broadcast message must be 2000 characters or fewer.")
    tone = (req.tone or "notice").strip().lower()
    if tone not in VALID_BROADCAST_TONES:
        tone = "notice"

    actor = str(auth.get("username") or auth.get("auth_type") or "owner")
    now = _utc_now()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO broadcast_messages (message, tone, created_at, active, created_by)
                VALUES (%s, %s, %s, TRUE, %s)
                RETURNING id, message, tone, created_at, active, created_by
                """,
                (msg, tone, now, actor),
            )
            row = cur.fetchone()
    logger.info("[BROADCAST CREATED] id=%s actor=%s tone=%s len=%d", row["id"], actor, tone, len(msg))
    return {
        "ok": True,
        "id": int(row["id"]),
        "message": str(row["message"]),
        "tone": str(row.get("tone") or tone),
        "active": bool(row.get("active", True)),
        "created_by": str(row.get("created_by") or actor),
        "created_at": _iso_utc(row.get("created_at") or now),
        "ack_count": 0,
    }


@app.post("/api/v1/admin/broadcasts/{broadcast_id}/deactivate")
def deactivate_broadcast(broadcast_id: int, auth: dict = Depends(_require_owner_or_token)):
    """SystemOwner-only: deactivate a broadcast so devices that haven't seen it will no longer receive it."""
    actor = str(auth.get("username") or auth.get("auth_type") or "owner")
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE broadcast_messages SET active = FALSE WHERE id = %s", (broadcast_id,))
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Broadcast message not found.")
    logger.info("[BROADCAST DEACTIVATED] id=%s actor=%s", broadcast_id, actor)
    return {"ok": True, "id": broadcast_id, "active": False}


@app.post("/api/v1/admin/broadcasts/{broadcast_id}/activate")
def activate_broadcast(broadcast_id: int, auth: dict = Depends(_require_owner_or_token)):
    """SystemOwner-only: re-enable a previously deactivated broadcast."""
    actor = str(auth.get("username") or auth.get("auth_type") or "owner")
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE broadcast_messages SET active = TRUE WHERE id = %s", (broadcast_id,))
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Broadcast message not found.")
    logger.info("[BROADCAST ACTIVATED] id=%s actor=%s", broadcast_id, actor)
    return {"ok": True, "id": broadcast_id, "active": True}


@app.get("/api/v1/admin/plans")
def list_admin_plans(_auth: dict = Depends(_require_owner_or_token)):
    """SystemOwner-only: list all subscription plans (active and inactive) from `subscription_plans`."""
    with get_db() as conn:
        with conn.cursor() as cur:
            all_plans = _load_plans_map(cur, include_inactive=True)
    return [
        {
            "plan_key": pk,
            "label": meta["label"],
            "days": int(meta["days"]),
            "price_inr": int(meta["price_inr"]),
            "active": bool(meta["active"]),
            "sort_order": int(meta.get("sort_order", 100)),
            "updated_at": meta.get("updated_at"),
            "first_renewal_only": pk == "launch90",
        }
        for pk, meta in all_plans.items()
    ]


@app.post("/api/v1/admin/plans")
def create_admin_plan(req: CreatePlanRequest, auth: dict = Depends(_require_owner_or_token)):
    """SystemOwner-only: add a new live subscription plan to `subscription_plans`."""
    pk = (req.plan_key or "").strip().lower()
    label = (req.label or "").strip()
    if pk == "trial" or not _PLAN_KEY_RE.match(pk):
        raise HTTPException(
            status_code=400,
            detail="Plan key must be 2–32 lowercase letters, digits, hyphens, or underscores (cannot be 'trial').",
        )
    if not label:
        raise HTTPException(status_code=400, detail="Plan label cannot be empty.")
    if int(req.days) < 1 or int(req.days) > 3650:
        raise HTTPException(status_code=400, detail="Plan days must be between 1 and 3650.")
    if int(req.price_inr) < 1 or int(req.price_inr) > 1000000:
        raise HTTPException(status_code=400, detail="Plan price_inr must be between 1 and 1000000.")

    actor = str(auth.get("username") or auth.get("auth_type") or "owner")
    now = _utc_now()
    with get_db() as conn:
        with conn.cursor() as cur:
            _seed_default_plans(cur)
            cur.execute(
                "SELECT plan_key, label, days, price_inr, active, sort_order, updated_at FROM subscription_plans WHERE plan_key = %s",
                (pk,),
            )
            if cur.fetchone() is not None:
                raise HTTPException(status_code=409, detail=f"Plan '{pk}' already exists.")
            cur.execute(
                """
                INSERT INTO subscription_plans (plan_key, label, days, price_inr, active, sort_order, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (pk, label, int(req.days), int(req.price_inr), bool(req.active), 100, now),
            )
            _record_license_audit(
                cur,
                license_key=f"PLAN:{pk}",
                action="plan_created",
                actor=actor,
                new_plan=pk,
                note=f"Created plan '{pk}' ({label}, ₹{int(req.price_inr)} / {int(req.days)}d, active={bool(req.active)})",
            )
    logger.info("[PLAN CREATED] actor=%s plan=%s price=₹%s days=%s", actor, pk, int(req.price_inr), int(req.days))
    return {
        "ok": True,
        "plan_key": pk,
        "label": label,
        "days": int(req.days),
        "price_inr": int(req.price_inr),
        "active": bool(req.active),
        "updated_at": now.isoformat(),
        "first_renewal_only": pk == "launch90",
    }


@app.put("/api/v1/admin/plans/{plan_key}")
def update_admin_plan(plan_key: str, req: UpdatePlanRequest, auth: dict = Depends(_require_owner_or_token)):
    """SystemOwner-only: update a plan's label, price_inr, days, or active state live in DB."""
    pk = (plan_key or "").strip().lower()
    actor = str(auth.get("username") or auth.get("auth_type") or "owner")
    now = _utc_now()

    with get_db() as conn:
        with conn.cursor() as cur:
            _seed_default_plans(cur)
            cur.execute(
                "SELECT plan_key, label, days, price_inr, active, sort_order, updated_at FROM subscription_plans WHERE plan_key = %s",
                (pk,),
            )
            existing = cur.fetchone()
            if existing is None:
                raise HTTPException(status_code=404, detail=f"Plan '{pk}' not found.")

            new_label = (req.label if req.label is not None else str(existing["label"])).strip()
            new_days = int(req.days) if req.days is not None else int(existing["days"])
            new_price = int(req.price_inr) if req.price_inr is not None else int(existing["price_inr"])
            new_active = bool(req.active) if req.active is not None else bool(existing.get("active", True))

            if not new_label:
                raise HTTPException(status_code=400, detail="Plan label cannot be empty.")
            if new_days < 1 or new_days > 3650:
                raise HTTPException(status_code=400, detail="Plan days must be between 1 and 3650.")
            if new_price < 1 or new_price > 1000000:
                raise HTTPException(status_code=400, detail="Plan price_inr must be between 1 and 1000000.")

            cur.execute(
                """
                UPDATE subscription_plans
                SET label = %s, days = %s, price_inr = %s, active = %s, updated_at = %s
                WHERE plan_key = %s
                """,
                (new_label, new_days, new_price, new_active, now, pk),
            )
            _record_license_audit(
                cur,
                license_key=f"PLAN:{pk}",
                action="plan_updated",
                actor=actor,
                previous_plan=pk,
                new_plan=pk,
                note=(
                    f"Updated plan '{pk}': label='{existing['label']}'->'{new_label}', "
                    f"price=₹{existing['price_inr']}->₹{new_price}, days={existing['days']}->{new_days}, "
                    f"active={bool(existing.get('active', True))}->{new_active}"
                ),
            )
    logger.info(
        "[PLAN UPDATED] actor=%s plan=%s price=₹%s->₹%s days=%s active=%s",
        actor, pk, existing["price_inr"], new_price, new_days, new_active,
    )
    return {
        "ok": True,
        "plan_key": pk,
        "label": new_label,
        "days": new_days,
        "price_inr": new_price,
        "active": new_active,
        "updated_at": now.isoformat(),
        "first_renewal_only": pk == "launch90",
    }


@app.get("/api/v1/admin/settings")
def get_admin_settings(_auth: dict = Depends(_require_owner_or_token)):
    """SystemOwner-only: inspect dynamic server settings (including `trial_days`)."""
    with get_db() as conn:
        with conn.cursor() as cur:
            _seed_default_system_settings(cur)
            cur.execute("SELECT key, value, updated_at, updated_by FROM system_settings ORDER BY key ASC")
            rows = cur.fetchall()
            trial_days = _get_configured_trial_days(cur)

    settings_map = {
        str(r["key"]): {
            "value": str(r["value"]),
            "updated_at": _iso_utc(r.get("updated_at")),
            "updated_by": str(r.get("updated_by") or "system"),
        }
        for r in rows
    }
    return {
        "trial_days": trial_days,
        "settings": settings_map,
    }


@app.put("/api/v1/admin/settings")
def update_admin_settings(req: UpdateSystemSettingsRequest, auth: dict = Depends(_require_owner_or_token)):
    """
    SystemOwner-only: update dynamic server settings (currently `trial_days`).
    Applies immediately to all newly auto-provisioned or newly created trial licenses;
    never retroactively alters already-activated trials.
    """
    new_days = int(req.trial_days)
    if new_days < 1 or new_days > 3650:
        raise HTTPException(status_code=400, detail="trial_days must be an integer between 1 and 3650.")

    actor = str(auth.get("username") or auth.get("auth_type") or "owner")
    now = _utc_now()

    with get_db() as conn:
        with conn.cursor() as cur:
            _seed_default_system_settings(cur)
            prev_days = _get_configured_trial_days(cur)
            cur.execute(
                """
                INSERT INTO system_settings (key, value, updated_at, updated_by)
                VALUES ('trial_days', %s, %s, %s)
                ON CONFLICT (key) DO UPDATE
                SET value = EXCLUDED.value,
                    updated_at = EXCLUDED.updated_at,
                    updated_by = EXCLUDED.updated_by
                """,
                (str(new_days), now, actor),
            )
            _record_license_audit(
                cur,
                license_key="SETTING:trial_days",
                action="setting_updated",
                actor=actor,
                previous_plan=f"{prev_days}d",
                new_plan=f"{new_days}d",
                note=f"Updated default free trial duration for new devices: {prev_days}d -> {new_days}d (non-retroactive)",
            )

    logger.info("[SETTING UPDATED] actor=%s key=trial_days %sd->%sd", actor, prev_days, new_days)
    return {
        "ok": True,
        "trial_days": new_days,
        "previous_trial_days": prev_days,
        "updated_at": now.isoformat(),
        "updated_by": actor,
    }


@app.get("/api/v1/admin/contact-messages")
def list_contact_messages(
    limit: int = Query(default=50, ge=1, le=200),
    _auth: dict = Depends(_require_admin_api),
):
    """Admin-only: list support messages submitted from desktop apps (separate from payment submissions)."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, license_key, device_id, message, client_timestamp, received_at, telegram_notified
                FROM contact_messages
                ORDER BY received_at DESC, id DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()
    return [
        {
            "id": int(r["id"]),
            "license_key": r.get("license_key"),
            "device_id": str(r["device_id"]),
            "message": str(r["message"]),
            "client_timestamp": _iso_utc(r.get("client_timestamp")),
            "received_at": _iso_utc(r.get("received_at")),
            "telegram_notified": bool(r.get("telegram_notified", False)),
        }
        for r in rows
    ]


@app.get("/api/v1/admin/credential-provisions")
def list_credential_provisions(
    device_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _auth: dict = Depends(_require_owner_or_token),
):
    """
    SystemOwner-only: list remote emergency credential provisions (password hashes NEVER returned).
    Optionally filter by `device_id`.
    """
    dev_filter = (device_id or "").strip() or None
    with get_db() as conn:
        with conn.cursor() as cur:
            if dev_filter:
                cur.execute(
                    """
                    SELECT id, device_id, username, email, role, must_change_password, created_at, consumed_at, created_by
                    FROM remote_credential_provisions
                    WHERE device_id = %s
                    ORDER BY created_at DESC, id DESC
                    LIMIT %s
                    """,
                    (dev_filter, limit),
                )
            else:
                cur.execute(
                    """
                    SELECT id, device_id, username, email, role, must_change_password, created_at, consumed_at, created_by
                    FROM remote_credential_provisions
                    ORDER BY created_at DESC, id DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
            rows = cur.fetchall()
    return [
        {
            "id": int(r["id"]),
            "device_id": str(r["device_id"]),
            "username": str(r["username"]),
            "email": str(r["email"]),
            "role": str(r.get("role") or "ADMIN").strip().upper(),
            "must_change_password": bool(r.get("must_change_password", True)),
            "created_at": _iso_utc(r.get("created_at")),
            "consumed_at": _iso_utc(r.get("consumed_at")),
            "created_by": str(r.get("created_by") or "owner"),
            "status": "consumed" if r.get("consumed_at") is not None else "pending",
        }
        for r in rows
    ]


@app.post("/api/v1/admin/credential-provisions")
def create_credential_provision(
    req: ProvisionCredentialsRequest,
    auth: dict = Depends(_require_owner_or_token),
):
    """
    SystemOwner-only emergency recovery action: queue a one-shot login credential creation/overwrite
    for a specific `device_id`. Password is immediately bcrypt-hashed server-side (matching the client
    app's bcrypt format), never stored in plaintext or logged, and returned ONCE in this POST response
    so SystemOwner can copy/communicate it. Marks `must_change_password = True` by default so the user
    must rotate the temporary password on next login.
    """
    dev_id = (req.device_id or "").strip()
    username = (req.username or "").strip().lower()
    email = (req.email or "").strip().lower()
    raw_password = (req.password or "").strip()
    auto_generated = False
    if not raw_password:
        raw_password = _generate_one_time_password()
        auto_generated = True
    role = (req.role or "ADMIN").strip().upper()
    must_change = bool(req.must_change_password)

    if len(dev_id) < 4:
        raise HTTPException(status_code=400, detail="A valid bound device_id is required.")
    if len(username) < 3 or len(username) > 64 or any(ch.isspace() for ch in username):
        raise HTTPException(
            status_code=400,
            detail="Username must be 3–64 characters with no whitespace.",
        )
    if not email or len(email) > 128 or "@" not in email or "." not in email.split("@", 1)[-1]:
        raise HTTPException(status_code=400, detail="Please enter a valid email address.")
    if len(raw_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")
    if role not in VALID_REMOTE_CREDENTIAL_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role '{req.role}'. Allowed roles: ADMIN, OPERATOR, AUDITOR.",
        )

    actor = str(auth.get("username") or auth.get("auth_type") or "owner")
    now = _utc_now()
    pw_hash = _hash_password(raw_password)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT license_key FROM licenses
                WHERE device_id = %s
                ORDER BY COALESCE(activated_at, last_seen, NOW()) DESC
                LIMIT 1
                """,
                (dev_id,),
            )
            lic_row = cur.fetchone()
            audit_lic_key = str(lic_row["license_key"]) if lic_row is not None else f"DEVICE:{dev_id[:16]}"

            cur.execute(
                """
                INSERT INTO remote_credential_provisions (
                    device_id, username, email, password_hash, role, must_change_password, created_at, consumed_at, created_by
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, NULL, %s)
                RETURNING id, created_at
                """,
                (dev_id, username, email, pw_hash, role, must_change, now, actor),
            )
            inserted = cur.fetchone()
            prov_id = int(inserted["id"])
            created_at = _as_utc(inserted.get("created_at")) or now

            # Keep non-sensitive portal directory up to date (NEVER stores password/hash)
            cur.execute(
                """
                INSERT INTO device_rbac_accounts (
                    device_id, username, email, role, is_active, must_change_password, last_synced_at
                )
                VALUES (%s, %s, %s, %s, TRUE, %s, %s)
                ON CONFLICT (device_id, username) DO UPDATE
                SET email = EXCLUDED.email,
                    role = EXCLUDED.role,
                    is_active = TRUE,
                    must_change_password = EXCLUDED.must_change_password,
                    last_synced_at = EXCLUDED.last_synced_at
                """,
                (dev_id, username, email, role, must_change, now),
            )

            _record_license_audit(
                cur,
                license_key=audit_lic_key,
                action="remote_credentials_provisioned",
                actor=actor,
                previous_plan=None,
                new_plan=role,
                note=(
                    f"Remotely provisioned by SystemOwner ({actor}): queued one-shot login credentials "
                    f"for device {dev_id} (username='{username}', email='{email}', role={role}, "
                    f"must_change_password={must_change}, provision_id={prov_id})"
                ),
            )

    logger.info(
        "[REMOTE_CREDS PROVISIONED] id=%s actor=%s device=%s username=%s role=%s must_change=%s auto_pw=%s",
        prov_id,
        actor,
        dev_id[:12],
        username,
        role,
        must_change,
        auto_generated,
    )
    return {
        "ok": True,
        "id": prov_id,
        "device_id": dev_id,
        "username": username,
        "email": email,
        "role": role,
        "must_change_password": must_change,
        "one_time_password": raw_password,
        "auto_generated_password": auto_generated,
        "created_at": created_at.isoformat(),
        "consumed_at": None,
        "created_by": actor,
        "status": "pending",
    }


@app.get("/api/v1/admin/device-rbac-accounts")
def list_device_rbac_accounts(_auth: dict = Depends(_require_owner_or_token)):
    """
    SystemOwner-only portal directory: returns known device_ids grouped with their
    license metadata (label, license_key, status, plan), local RBAC usernames/emails/roles
    (STRICTLY NO passwords or password hashes), and recent one-shot provisions.
    """
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT license_key, label, status, plan, device_id, last_seen, note
                FROM licenses
                WHERE device_id IS NOT NULL
                ORDER BY license_key ASC
                """
            )
            lic_rows = cur.fetchall()

            cur.execute(
                """
                SELECT device_id, username, email, role, is_active, must_change_password, last_synced_at
                FROM device_rbac_accounts
                ORDER BY device_id ASC, username ASC
                """
            )
            acct_rows = cur.fetchall()

            cur.execute(
                """
                SELECT id, device_id, username, email, role, must_change_password, created_at, consumed_at, created_by
                FROM remote_credential_provisions
                ORDER BY created_at DESC, id DESC
                LIMIT 200
                """
            )
            prov_rows = cur.fetchall()

    devices: dict[str, dict] = {}

    def _ensure_dev(dev_id: str) -> dict:
        if dev_id not in devices:
            devices[dev_id] = {
                "device_id": dev_id,
                "license_key": None,
                "label": None,
                "status": None,
                "plan": None,
                "last_seen": None,
                "note": None,
                "accounts": [],
                "provisions": [],
            }
        return devices[dev_id]

    for r in lic_rows:
        dev = (r.get("device_id") or "").strip()
        if not dev:
            continue
        entry = _ensure_dev(dev)
        entry["license_key"] = r.get("license_key")
        entry["label"] = r.get("label")
        entry["status"] = r.get("status")
        entry["plan"] = r.get("plan")
        entry["last_seen"] = _iso_utc(r.get("last_seen"))
        entry["note"] = r.get("note")

    for a in acct_rows:
        dev = (a.get("device_id") or "").strip()
        if not dev:
            continue
        entry = _ensure_dev(dev)
        entry["accounts"].append({
            "username": str(a["username"]),
            "email": str(a.get("email") or ""),
            "role": str(a.get("role") or "OPERATOR").strip().upper(),
            "is_active": bool(a.get("is_active", True)),
            "must_change_password": bool(a.get("must_change_password", False)),
            "last_synced_at": _iso_utc(a.get("last_synced_at")),
        })

    for p in prov_rows:
        dev = (p.get("device_id") or "").strip()
        if not dev:
            continue
        entry = _ensure_dev(dev)
        entry["provisions"].append({
            "id": int(p["id"]),
            "username": str(p["username"]),
            "email": str(p.get("email") or ""),
            "role": str(p.get("role") or "ADMIN").strip().upper(),
            "must_change_password": bool(p.get("must_change_password", True)),
            "created_at": _iso_utc(p.get("created_at")),
            "consumed_at": _iso_utc(p.get("consumed_at")),
            "created_by": str(p.get("created_by") or "owner"),
            "status": "consumed" if p.get("consumed_at") is not None else "pending",
        })

    return sorted(
        devices.values(),
        key=lambda d: ((d.get("label") or "").lower() == "", (d.get("label") or d.get("license_key") or d["device_id"]).lower()),
    )


# ============================================ TWO-WAY LICENSE-LINKED MESSAGING
@app.post("/api/v1/messages/send")
def client_send_message(req: ClientMessageSendRequest, request: Request):
    """
    Authenticated client-to-admin messaging endpoint.
    Server derives and verifies the sending license identity exclusively from the
    authenticated (license_key, device_id) bound in `licenses`. Supports idempotency keys
    and per-client rate limiting. Never logs private message body contents.
    """
    eff_key, eff_dev = _resolve_client_auth_pair(
        request,
        body_key=req.license_key,
        body_device_id=req.device_id,
        target_license_key=req.target_license_key,
    )
    body_text = _validate_message_body(req.body)
    idem_key = _validate_idempotency_key(req.idempotency_key)
    operator_name = _sanitize_operator_name(req.operator_name)
    client_ip = _client_ip(request)
    now = _utc_now()

    with get_db() as conn:
        with conn.cursor() as cur:
            lic = _authenticate_client_messaging(cur, eff_key, eff_dev, client_ip)
            auth_key = str(lic["license_key"])
            auth_dev = str(lic["device_id"])

            if idem_key:
                cur.execute(
                    """
                    SELECT id, license_key, sender_type, sender_identity, target_device_id,
                           body, status, idempotency_key, created_at, delivered_at, read_at, read_by,
                           retargeted_from_device_id, retargeted_by, retargeted_at
                    FROM license_messages
                    WHERE license_key = %s
                      AND sender_type = 'client'
                      AND idempotency_key = %s
                    """,
                    (auth_key, idem_key),
                )
                existing = cur.fetchone()
                if existing is not None:
                    return {
                        "ok": True,
                        "deduplicated": True,
                        "message": _serialize_license_message(existing),
                    }

            _check_and_record_client_message_rate_limit(f"{auth_key}:{auth_dev}")
            sender_identity = (
                f"{operator_name} (device:{auth_dev[:12]})"
                if operator_name
                else f"device:{auth_dev[:12]}"
            )
            cur.execute(
                """
                INSERT INTO license_messages (
                    license_key, sender_type, sender_identity, target_device_id,
                    body, status, idempotency_key, created_at
                )
                VALUES (%s, 'client', %s, %s, %s, 'received', %s, %s)
                RETURNING id, license_key, sender_type, sender_identity, target_device_id,
                          body, status, idempotency_key, created_at, delivered_at, read_at, read_by,
                          retargeted_from_device_id, retargeted_by, retargeted_at
                """,
                (auth_key, sender_identity, auth_dev, body_text, idem_key, now),
            )
            inserted = cur.fetchone()
            msg = _serialize_license_message(inserted)

    logger.info(
        "[LICENSE MESSAGE] id=%s dir=client->admin key=%s device=%s status=received len=%d",
        msg["id"],
        auth_key,
        auth_dev[:12],
        len(body_text),
    )
    return {
        "ok": True,
        "deduplicated": False,
        "message": msg,
    }


@app.post("/api/v1/messages/sync")
def client_sync_messages(req: ClientMessageSyncRequest, request: Request):
    """
    Synchronize this authenticated client's own conversation history and pending queued
    admin messages. Deliberately does NOT mark `queued` messages as `delivered` — client
    must explicitly confirm receipt via `POST /api/v1/messages/ack-delivered`.
    """
    eff_key, eff_dev = _resolve_client_auth_pair(
        request,
        body_key=req.license_key,
        body_device_id=req.device_id,
        target_license_key=req.target_license_key,
    )
    client_ip = _client_ip(request)
    now = _utc_now()

    with get_db() as conn:
        with conn.cursor() as cur:
            lic = _authenticate_client_messaging(cur, eff_key, eff_dev, client_ip)
            auth_key = str(lic["license_key"])
            auth_dev = str(lic["device_id"])
            messages = _fetch_client_scoped_messages(
                cur,
                license_key=auth_key,
                device_id=auth_dev,
                since_id=req.since_id,
            )

    pending_delivery_ids = [
        m["id"] for m in messages if m["sender_type"] == "admin" and m["status"] == "queued"
    ]
    unread_count = sum(
        1 for m in messages if m["sender_type"] == "admin" and m["status"] in ("queued", "delivered")
    )
    return {
        "ok": True,
        "license_key": auth_key,
        "license_label": lic.get("label") or None,
        "device_id": auth_dev,
        "messages": messages,
        "pending_delivery_ids": pending_delivery_ids,
        "unread_count": unread_count,
        "server_time": now.isoformat(),
    }


@app.get("/api/v1/messages/conversation/{license_key}")
def client_get_conversation(
    license_key: str,
    request: Request,
    since_id: int | None = Query(default=None),
):
    """
    Read-only client conversation endpoint enforcing strict license isolation:
    authenticated via X-License-Key + X-Device-Id headers; any attempt to query a
    different license_key is immediately rejected with 403 Forbidden.
    """
    eff_key, eff_dev = _resolve_client_auth_pair(
        request,
        target_license_key=license_key,
    )
    client_ip = _client_ip(request)
    now = _utc_now()

    with get_db() as conn:
        with conn.cursor() as cur:
            lic = _authenticate_client_messaging(cur, eff_key, eff_dev, client_ip)
            auth_key = str(lic["license_key"])
            auth_dev = str(lic["device_id"])
            messages = _fetch_client_scoped_messages(
                cur,
                license_key=auth_key,
                device_id=auth_dev,
                since_id=since_id,
            )

    pending_delivery_ids = [
        m["id"] for m in messages if m["sender_type"] == "admin" and m["status"] == "queued"
    ]
    unread_count = sum(
        1 for m in messages if m["sender_type"] == "admin" and m["status"] in ("queued", "delivered")
    )
    return {
        "ok": True,
        "license_key": auth_key,
        "license_label": lic.get("label") or None,
        "device_id": auth_dev,
        "messages": messages,
        "pending_delivery_ids": pending_delivery_ids,
        "unread_count": unread_count,
        "server_time": now.isoformat(),
    }


@app.post("/api/v1/messages/ack-delivered")
def client_ack_delivered(req: ClientMessageAckRequest, request: Request):
    """
    Explicit client delivery acknowledgment. Transitions matching outgoing admin messages
    strictly bound to this authenticated (license_key, device_id) from `queued` -> `delivered`
    and records `delivered_at` + audit trail. Idempotent on retries.
    """
    eff_key, eff_dev = _resolve_client_auth_pair(
        request,
        body_key=req.license_key,
        body_device_id=req.device_id,
        target_license_key=req.target_license_key,
    )
    clean_ids = sorted({int(mid) for mid in (req.message_ids or []) if int(mid) > 0})[:200]
    if not clean_ids:
        raise HTTPException(status_code=400, detail="At least one valid message_id is required.")

    client_ip = _client_ip(request)
    now = _utc_now()

    with get_db() as conn:
        with conn.cursor() as cur:
            lic = _authenticate_client_messaging(cur, eff_key, eff_dev, client_ip)
            auth_key = str(lic["license_key"])
            auth_dev = str(lic["device_id"])

            cur.execute(
                """
                UPDATE license_messages
                SET status = 'delivered',
                    delivered_at = %s
                WHERE license_key = %s
                  AND target_device_id = %s
                  AND sender_type = 'admin'
                  AND status = 'queued'
                  AND id = ANY(%s)
                RETURNING id, license_key, sender_type, sender_identity, target_device_id,
                          body, status, idempotency_key, created_at, delivered_at, read_at, read_by,
                          retargeted_from_device_id, retargeted_by, retargeted_at
                """,
                (now, auth_key, auth_dev, clean_ids),
            )
            updated_rows = cur.fetchall()
            acknowledged_ids = [int(r["id"]) for r in updated_rows]

            if acknowledged_ids:
                plan = (lic.get("plan") or "trial").strip().lower()
                exp = _as_utc(lic.get("expires_at"))
                has_paid = bool(lic.get("has_paid_renewal", False))
                ids_str = ",".join(str(i) for i in acknowledged_ids[:10])
                _record_license_audit(
                    cur,
                    license_key=auth_key,
                    action="messages_delivered",
                    actor=f"client:{auth_dev[:12]}",
                    previous_plan=plan,
                    new_plan=plan,
                    previous_expires_at=exp,
                    new_expires_at=exp,
                    previous_has_paid_renewal=has_paid,
                    new_has_paid_renewal=has_paid,
                    note=f"Client acknowledged delivery of {len(acknowledged_ids)} admin message(s) (ids={ids_str})",
                )
                logger.info(
                    "[LICENSE MESSAGE DELIVERED] key=%s device=%s count=%d ids=%s",
                    auth_key,
                    auth_dev[:12],
                    len(acknowledged_ids),
                    ids_str,
                )

            cur.execute(
                """
                SELECT id, license_key, sender_type, sender_identity, target_device_id,
                       body, status, idempotency_key, created_at, delivered_at, read_at, read_by,
                       retargeted_from_device_id, retargeted_by, retargeted_at
                FROM license_messages
                WHERE license_key = %s
                  AND target_device_id = %s
                  AND sender_type = 'admin'
                  AND id = ANY(%s)
                ORDER BY created_at ASC, id ASC
                """,
                (auth_key, auth_dev, clean_ids),
            )
            current_msgs = [_serialize_license_message(r) for r in cur.fetchall()]

    return {
        "ok": True,
        "acknowledged_ids": acknowledged_ids,
        "delivered_at": now.isoformat() if acknowledged_ids else (current_msgs[0]["delivered_at"] if current_msgs else None),
        "messages": current_msgs,
    }


@app.post("/api/v1/messages/mark-read")
def client_mark_messages_read(req: ClientMessageAckRequest, request: Request):
    """
    Client read-receipt endpoint called when the operator opens the Messages Inbox and
    views incoming admin messages. Transitions matching messages to `read` with `read_at`.
    """
    eff_key, eff_dev = _resolve_client_auth_pair(
        request,
        body_key=req.license_key,
        body_device_id=req.device_id,
        target_license_key=req.target_license_key,
    )
    clean_ids = sorted({int(mid) for mid in (req.message_ids or []) if int(mid) > 0})[:200]
    if not clean_ids:
        raise HTTPException(status_code=400, detail="At least one valid message_id is required.")

    client_ip = _client_ip(request)
    now = _utc_now()

    with get_db() as conn:
        with conn.cursor() as cur:
            lic = _authenticate_client_messaging(cur, eff_key, eff_dev, client_ip)
            auth_key = str(lic["license_key"])
            auth_dev = str(lic["device_id"])
            reader = f"device:{auth_dev[:12]}"

            cur.execute(
                """
                UPDATE license_messages
                SET status = 'read',
                    delivered_at = COALESCE(delivered_at, %s),
                    read_at = %s,
                    read_by = %s
                WHERE license_key = %s
                  AND target_device_id = %s
                  AND sender_type = 'admin'
                  AND status IN ('queued', 'delivered')
                  AND id = ANY(%s)
                RETURNING id, license_key, sender_type, sender_identity, target_device_id,
                          body, status, idempotency_key, created_at, delivered_at, read_at, read_by,
                          retargeted_from_device_id, retargeted_by, retargeted_at
                """,
                (now, now, reader, auth_key, auth_dev, clean_ids),
            )
            updated_rows = cur.fetchall()
            read_ids = [int(r["id"]) for r in updated_rows]

            if read_ids:
                plan = (lic.get("plan") or "trial").strip().lower()
                exp = _as_utc(lic.get("expires_at"))
                has_paid = bool(lic.get("has_paid_renewal", False))
                ids_str = ",".join(str(i) for i in read_ids[:10])
                _record_license_audit(
                    cur,
                    license_key=auth_key,
                    action="messages_client_read",
                    actor=f"client:{auth_dev[:12]}",
                    previous_plan=plan,
                    new_plan=plan,
                    previous_expires_at=exp,
                    new_expires_at=exp,
                    previous_has_paid_renewal=has_paid,
                    new_has_paid_renewal=has_paid,
                    note=f"Client opened and marked {len(read_ids)} admin message(s) read (ids={ids_str})",
                )
                logger.info(
                    "[LICENSE MESSAGE CLIENT_READ] key=%s device=%s count=%d ids=%s",
                    auth_key,
                    auth_dev[:12],
                    len(read_ids),
                    ids_str,
                )

            cur.execute(
                """
                SELECT id, license_key, sender_type, sender_identity, target_device_id,
                       body, status, idempotency_key, created_at, delivered_at, read_at, read_by,
                       retargeted_from_device_id, retargeted_by, retargeted_at
                FROM license_messages
                WHERE license_key = %s
                  AND target_device_id = %s
                  AND sender_type = 'admin'
                  AND id = ANY(%s)
                ORDER BY created_at ASC, id ASC
                """,
                (auth_key, auth_dev, clean_ids),
            )
            current_msgs = [_serialize_license_message(r) for r in cur.fetchall()]

    return {
        "ok": True,
        "read_ids": read_ids,
        "read_at": now.isoformat() if read_ids else (current_msgs[0]["read_at"] if current_msgs else None),
        "messages": current_msgs,
    }


@app.get("/api/v1/admin/messages/inbox")
def admin_list_messages_inbox(
    q: str | None = Query(default=None),
    filter: str = Query(default="all"),
    _auth: dict = Depends(_require_admin_api),
):
    """
    Admin Inbox listing per-license conversations sorted by latest activity.
    Supports searching by license key / label / note / device ID and filtering
    by `all`, `unread` (has unread client messages), or `read`.
    """
    flt = (filter or "all").strip().lower()
    if flt not in {"all", "unread", "read"}:
        raise HTTPException(status_code=400, detail="Invalid filter. Use 'all', 'unread', or 'read'.")
    search_q = (q or "").strip().lower()
    now = _utc_now()

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT license_key, status, plan, expires_at, device_id,
                       app_version, last_seen, note, label
                FROM licenses
                ORDER BY license_key ASC
                """
            )
            lic_rows = cur.fetchall()
            lic_map = {str(r["license_key"]): r for r in lic_rows}

            cur.execute(
                """
                SELECT id, license_key, sender_type, sender_identity, target_device_id,
                       body, status, created_at, delivered_at, read_at
                FROM license_messages
                ORDER BY created_at ASC, id ASC
                """
            )
            msg_rows = cur.fetchall()

    threads: dict[str, dict] = {}
    for m in msg_rows:
        key = str(m["license_key"])
        lic = lic_map.get(key)
        if lic is None:
            continue
        entry = threads.get(key)
        if entry is None:
            entry = {
                "license_key": key,
                "label": lic.get("label") or None,
                "note": lic.get("note") or None,
                "license_status": _effective_license_status_str(lic, now=now),
                "plan": (lic.get("plan") or "trial").strip().lower(),
                "device_id": lic.get("device_id") or None,
                "app_version": lic.get("app_version") or None,
                "last_seen": _iso_utc(lic.get("last_seen")),
                "unread_count": 0,
                "queued_count": 0,
                "held_count": 0,
                "total_messages": 0,
                "last_message_id": None,
                "last_message_preview": "",
                "last_sender_type": None,
                "last_message_status": None,
                "last_activity_at": None,
                "_sort_ts": datetime.min.replace(tzinfo=timezone.utc),
                "_sort_id": 0,
            }
            threads[key] = entry

        entry["total_messages"] += 1
        st = str(m.get("status") or "")
        stype = str(m.get("sender_type") or "")
        if stype == "client" and st == "received":
            entry["unread_count"] += 1
        elif stype == "admin" and st == "queued":
            entry["queued_count"] += 1
        elif stype == "admin" and st == "held_device_changed":
            entry["held_count"] += 1

        created_dt = _as_utc(m.get("created_at")) or now
        mid = int(m["id"])
        if (created_dt, mid) >= (entry["_sort_ts"], entry["_sort_id"]):
            raw_body = str(m.get("body") or "")
            preview = raw_body if len(raw_body) <= 120 else raw_body[:117] + "..."
            entry["_sort_ts"] = created_dt
            entry["_sort_id"] = mid
            entry["last_message_id"] = mid
            entry["last_message_preview"] = preview
            entry["last_sender_type"] = stype
            entry["last_message_status"] = st
            entry["last_activity_at"] = created_dt.isoformat()

    all_convs = sorted(
        threads.values(),
        key=lambda c: (c["_sort_ts"], c["_sort_id"]),
        reverse=True,
    )
    total_unread = sum(int(c["unread_count"]) for c in all_convs)

    filtered_convs = []
    for c in all_convs:
        if flt == "unread" and c["unread_count"] <= 0:
            continue
        if flt == "read" and c["unread_count"] > 0:
            continue
        if search_q:
            haystack = " ".join(
                str(v or "").lower()
                for v in (c["license_key"], c["label"], c["note"], c["device_id"])
            )
            if search_q not in haystack:
                continue
        clean_c = {k: v for k, v in c.items() if not k.startswith("_")}
        filtered_convs.append(clean_c)

    return {
        "conversations": filtered_convs,
        "total_unread": total_unread,
        "total_conversations": len(all_convs),
    }


@app.get("/api/v1/admin/messages/conversation/{license_key}")
def admin_get_conversation(
    license_key: str,
    mark_read: bool = Query(default=True),
    auth: dict = Depends(_require_admin_api),
):
    """
    Open a single license's full two-way conversation history in the Admin Inbox.
    When `mark_read=true` (default), transitions incoming client messages from
    `received` -> `read` with `read_at` and records the action in `license_audit_log`.
    """
    key = (license_key or "").strip()
    actor = str(auth.get("username") or auth.get("auth_type") or "admin")
    now = _utc_now()

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT license_key, status, plan, expires_at, has_paid_renewal,
                       device_id, app_version, last_seen, note, label
                FROM licenses
                WHERE license_key = %s
                """,
                (key,),
            )
            lic = cur.fetchone()
            if lic is None:
                raise HTTPException(status_code=404, detail="License key not found.")

            marked_read_ids: list[int] = []
            if mark_read:
                cur.execute(
                    """
                    UPDATE license_messages
                    SET status = 'read',
                        read_at = %s,
                        read_by = %s
                    WHERE license_key = %s
                      AND sender_type = 'client'
                      AND status = 'received'
                    RETURNING id
                    """,
                    (now, actor, key),
                )
                marked_read_ids = [int(r["id"]) for r in cur.fetchall()]
                if marked_read_ids:
                    plan = (lic.get("plan") or "trial").strip().lower()
                    exp = _as_utc(lic.get("expires_at"))
                    has_paid = bool(lic.get("has_paid_renewal", False))
                    ids_str = ",".join(str(i) for i in marked_read_ids[:10])
                    _record_license_audit(
                        cur,
                        license_key=key,
                        action="messages_read",
                        actor=actor,
                        previous_plan=plan,
                        new_plan=plan,
                        previous_expires_at=exp,
                        new_expires_at=exp,
                        previous_has_paid_renewal=has_paid,
                        new_has_paid_renewal=has_paid,
                        note=f"Admin opened conversation and marked {len(marked_read_ids)} client message(s) read (ids={ids_str})",
                    )
                    logger.info(
                        "[LICENSE MESSAGE ADMIN_READ] actor=%s key=%s count=%d ids=%s",
                        actor,
                        key,
                        len(marked_read_ids),
                        ids_str,
                    )

            cur.execute(
                """
                SELECT id, license_key, sender_type, sender_identity, target_device_id,
                       body, status, idempotency_key, created_at, delivered_at, read_at, read_by,
                       retargeted_from_device_id, retargeted_by, retargeted_at
                FROM license_messages
                WHERE license_key = %s
                ORDER BY created_at ASC, id ASC
                """,
                (key,),
            )
            messages = [_serialize_license_message(r) for r in cur.fetchall()]

    return {
        "license": {
            "license_key": str(lic["license_key"]),
            "label": lic.get("label") or None,
            "note": lic.get("note") or None,
            "status": _effective_license_status_str(lic, now=now),
            "raw_status": (lic.get("status") or "active").strip().lower(),
            "plan": (lic.get("plan") or "trial").strip().lower(),
            "expires_at": _iso_utc(lic.get("expires_at")),
            "device_id": lic.get("device_id") or None,
            "app_version": lic.get("app_version") or None,
            "last_seen": _iso_utc(lic.get("last_seen")),
        },
        "messages": messages,
        "marked_read_ids": marked_read_ids,
    }


@app.post("/api/v1/admin/messages/send")
def admin_send_message(req: AdminMessageSendRequest, auth: dict = Depends(_require_admin_api)):
    """
    Send an individual message strictly to ONE selected license and its currently bound
    device_id. Stores the message in `queued` state (never `delivered` until the intended
    client acknowledges receipt). Rejects broadcast wildcards, revoked licenses, and
    unbound licenses so messages are never exposed to an unintended device.
    """
    key = (req.license_key or "").strip()
    if not key or key.lower() in {"*", "all", "broadcast"} or any(ch in key for ch in (",", ";", " ", "\n", "\r")):
        raise HTTPException(
            status_code=400,
            detail="A single specific license_key is required for individual messaging.",
        )

    body_text = _validate_message_body(req.body)
    idem_key = _validate_idempotency_key(req.idempotency_key)
    actor = str(auth.get("username") or auth.get("auth_type") or "admin")
    now = _utc_now()

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT license_key, status, plan, expires_at, has_paid_renewal, device_id, label
                FROM licenses
                WHERE license_key = %s
                """,
                (key,),
            )
            lic = cur.fetchone()
            if lic is None:
                raise HTTPException(status_code=404, detail="License key not found.")

            raw_status = (lic.get("status") or "").strip().lower()
            if raw_status in {"revoked", "suspended", "disabled"}:
                raise HTTPException(
                    status_code=409,
                    detail="Cannot send an individual message to a revoked or inactive license.",
                )

            bound_dev = (lic.get("device_id") or "").strip()
            if not bound_dev:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "This license is currently unbound (no device activated). "
                        "Individual messages require an active bound device to prevent unintended delivery."
                    ),
                )

            if idem_key:
                cur.execute(
                    """
                    SELECT id, license_key, sender_type, sender_identity, target_device_id,
                           body, status, idempotency_key, created_at, delivered_at, read_at, read_by,
                           retargeted_from_device_id, retargeted_by, retargeted_at
                    FROM license_messages
                    WHERE license_key = %s
                      AND sender_type = 'admin'
                      AND idempotency_key = %s
                    """,
                    (key, idem_key),
                )
                existing = cur.fetchone()
                if existing is not None:
                    return {
                        "ok": True,
                        "deduplicated": True,
                        "message": _serialize_license_message(existing),
                    }

            cur.execute(
                """
                INSERT INTO license_messages (
                    license_key, sender_type, sender_identity, target_device_id,
                    body, status, idempotency_key, created_at
                )
                VALUES (%s, 'admin', %s, %s, %s, 'queued', %s, %s)
                RETURNING id, license_key, sender_type, sender_identity, target_device_id,
                          body, status, idempotency_key, created_at, delivered_at, read_at, read_by,
                          retargeted_from_device_id, retargeted_by, retargeted_at
                """,
                (key, actor, bound_dev, body_text, idem_key, now),
            )
            inserted = cur.fetchone()
            msg = _serialize_license_message(inserted)

            plan = (lic.get("plan") or "trial").strip().lower()
            exp = _as_utc(lic.get("expires_at"))
            has_paid = bool(lic.get("has_paid_renewal", False))
            _record_license_audit(
                cur,
                license_key=key,
                action="message_sent",
                actor=actor,
                previous_plan=plan,
                new_plan=plan,
                previous_expires_at=exp,
                new_expires_at=exp,
                previous_has_paid_renewal=has_paid,
                new_has_paid_renewal=has_paid,
                note=f"Queued admin message #{msg['id']} for device {bound_dev[:12]} (len={len(body_text)})",
            )

    logger.info(
        "[LICENSE MESSAGE] id=%s dir=admin->client actor=%s key=%s target_device=%s status=queued len=%d",
        msg["id"],
        actor,
        key,
        bound_dev[:12],
        len(body_text),
    )
    return {
        "ok": True,
        "deduplicated": False,
        "message": msg,
    }


@app.post("/api/v1/admin/messages/{message_id}/retarget")
def admin_retarget_held_message(
    message_id: int,
    req: AdminMessageRetargetRequest,
    auth: dict = Depends(_require_owner_or_token),
):
    """
    Explicit SystemOwner policy for outgoing messages held when a license's bound device
    was unbound/transferred (`status = 'held_device_changed'`):
      - action='retarget': explicitly re-targets the held message to the license's newly
        bound device_id and re-queues it (`status = 'queued'`), recording full audit lineage.
      - action='cancel': cancels delivery permanently (`status = 'cancelled'`).
    """
    action = (req.action or "retarget").strip().lower()
    if action not in {"retarget", "cancel"}:
        raise HTTPException(status_code=400, detail="Action must be 'retarget' or 'cancel'.")
    actor = str(auth.get("username") or auth.get("auth_type") or "owner")
    now = _utc_now()

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, license_key, sender_type, sender_identity, target_device_id,
                       body, status, idempotency_key, created_at, delivered_at, read_at, read_by,
                       retargeted_from_device_id, retargeted_by, retargeted_at
                FROM license_messages
                WHERE id = %s
                FOR UPDATE
                """,
                (int(message_id),),
            )
            msg_row = cur.fetchone()
            if msg_row is None:
                raise HTTPException(status_code=404, detail="Message not found.")
            if msg_row.get("sender_type") != "admin":
                raise HTTPException(status_code=400, detail="Only outgoing admin messages can be retargeted.")
            if msg_row.get("status") != "held_device_changed":
                raise HTTPException(
                    status_code=409,
                    detail=f"Message #{message_id} is in status '{msg_row.get('status')}', not 'held_device_changed'.",
                )

            key = str(msg_row["license_key"])
            prev_dev = (msg_row.get("target_device_id") or "").strip() or None

            cur.execute(
                "SELECT license_key, status, plan, expires_at, has_paid_renewal, device_id FROM licenses WHERE license_key = %s",
                (key,),
            )
            lic = cur.fetchone()
            if lic is None:
                raise HTTPException(status_code=404, detail="Associated license not found.")
            plan = (lic.get("plan") or "trial").strip().lower()
            exp = _as_utc(lic.get("expires_at"))
            has_paid = bool(lic.get("has_paid_renewal", False))

            if action == "cancel":
                cur.execute(
                    """
                    UPDATE license_messages
                    SET status = 'cancelled',
                        retargeted_by = %s,
                        retargeted_at = %s
                    WHERE id = %s
                    RETURNING id, license_key, sender_type, sender_identity, target_device_id,
                              body, status, idempotency_key, created_at, delivered_at, read_at, read_by,
                              retargeted_from_device_id, retargeted_by, retargeted_at
                    """,
                    (actor, now, int(message_id)),
                )
                updated = _serialize_license_message(cur.fetchone())
                _record_license_audit(
                    cur,
                    license_key=key,
                    action="message_cancelled",
                    actor=actor,
                    previous_plan=plan,
                    new_plan=plan,
                    previous_expires_at=exp,
                    new_expires_at=exp,
                    previous_has_paid_renewal=has_paid,
                    new_has_paid_renewal=has_paid,
                    note=f"Cancelled held admin message #{message_id} (previous device={prev_dev[:12] if prev_dev else 'none'})",
                )
                logger.info("[LICENSE MESSAGE CANCELLED] id=%s actor=%s key=%s", message_id, actor, key)
                return {"ok": True, "action": "cancel", "message": updated}

            # action == "retarget"
            if (lic.get("status") or "").strip().lower() in {"revoked", "suspended", "disabled"}:
                raise HTTPException(status_code=409, detail="Cannot retarget a message for a revoked license.")
            current_dev = (lic.get("device_id") or "").strip()
            if not current_dev:
                raise HTTPException(
                    status_code=409,
                    detail="Cannot retarget message while license is unbound. Wait for the new device to bind first.",
                )

            cur.execute(
                """
                UPDATE license_messages
                SET status = 'queued',
                    retargeted_from_device_id = %s,
                    target_device_id = %s,
                    retargeted_by = %s,
                    retargeted_at = %s
                WHERE id = %s
                RETURNING id, license_key, sender_type, sender_identity, target_device_id,
                          body, status, idempotency_key, created_at, delivered_at, read_at, read_by,
                          retargeted_from_device_id, retargeted_by, retargeted_at
                """,
                (prev_dev, current_dev, actor, now, int(message_id)),
            )
            updated = _serialize_license_message(cur.fetchone())
            _record_license_audit(
                cur,
                license_key=key,
                action="message_retargeted",
                actor=actor,
                previous_plan=plan,
                new_plan=plan,
                previous_expires_at=exp,
                new_expires_at=exp,
                previous_has_paid_renewal=has_paid,
                new_has_paid_renewal=has_paid,
                note=(
                    f"Explicitly retargeted held admin message #{message_id} from "
                    f"{prev_dev[:12] if prev_dev else 'none'} to {current_dev[:12]}"
                ),
            )
            logger.info(
                "[LICENSE MESSAGE RETARGETED] id=%s actor=%s key=%s from=%s to=%s",
                message_id,
                actor,
                key,
                prev_dev[:12] if prev_dev else "none",
                current_dev[:12],
            )
            return {"ok": True, "action": "retarget", "message": updated}


@app.get("/", include_in_schema=False)
def root_redirect():
    return RedirectResponse(url="/admin", status_code=302)


if os.environ.get("SKIP_INIT_DB_ON_IMPORT") != "1":
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL environment variable is not set.")
    init_db()
