import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg2
import psycopg2.extras
import requests
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

logger = logging.getLogger("license_server")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

DATABASE_URL = os.environ.get("DATABASE_URL")  # set on Render — Neon Postgres connection string
ADMIN_TOKEN = os.environ.get("LICENSE_ADMIN_TOKEN")

TRIAL_DAYS = 180
SCREENSHOT_RATE_LIMIT_MINUTES = 10
MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024  # 5 MB

ADMIN_UI_DIR = Path(__file__).resolve().parent / "admin_ui"
SESSION_COOKIE_NAME = "admin_session"
SESSION_TTL_SECONDS = int(os.environ.get("ADMIN_SESSION_TTL_SECONDS", str(4 * 3600)))
LOGIN_RATE_LIMIT_MAX_ATTEMPTS = 10
LOGIN_RATE_LIMIT_WINDOW_SECONDS = 15 * 60
_LOGIN_ATTEMPTS: dict[str, list[float]] = {}
ADMIN_PAGE_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)

PLANS = {
    "monthly":   {"days": 30,  "price_inr": 150, "label": "Monthly"},
    "quarterly": {"days": 90,  "price_inr": 300, "label": "Quarterly"},
    "annual":    {"days": 365, "price_inr": 900, "label": "Annual"},
    "launch90":  {"days": 90,  "price_inr": 200, "label": "Launch Offer — 90 days"},
}

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
    conn = psycopg2.connect(db_url, sslmode="require")
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
                    expires_at TIMESTAMPTZ,
                    plan TEXT NOT NULL DEFAULT 'trial',
                    has_paid_renewal BOOLEAN NOT NULL DEFAULT FALSE
                )
            """)
            # Idempotent column upgrades for existing Neon Postgres databases
            cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ")
            cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS plan TEXT NOT NULL DEFAULT 'trial'")
            cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS has_paid_renewal BOOLEAN NOT NULL DEFAULT FALSE")

            # Backfill NULL plan values on legacy rows
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

            # Payment submissions stored as base64 in Postgres (Render free disk is ephemeral)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS payment_submissions (
                    id SERIAL PRIMARY KEY,
                    license_key TEXT NOT NULL REFERENCES licenses(license_key) ON DELETE CASCADE,
                    device_id TEXT NOT NULL,
                    claimed_plan TEXT NOT NULL,
                    image_data TEXT NOT NULL,
                    content_type TEXT NOT NULL DEFAULT 'image/png',
                    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    status TEXT NOT NULL DEFAULT 'pending'
                )
            """)
            cur.execute("ALTER TABLE payment_submissions ADD COLUMN IF NOT EXISTS content_type TEXT NOT NULL DEFAULT 'image/png'")
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_payment_submissions_key_time
                ON payment_submissions (license_key, submitted_at DESC)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_payment_submissions_status
                ON payment_submissions (status, submitted_at DESC)
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS admin_sessions (
                    jti TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    expires_at TIMESTAMPTZ NOT NULL,
                    revoked_at TIMESTAMPTZ
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires
                ON admin_sessions (expires_at)
            """)


if os.environ.get("SKIP_INIT_DB_ON_IMPORT") != "1":
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL environment variable is not set.")
    init_db()


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


def _get_admin_credentials() -> tuple[str | None, str | None]:
    username = (os.environ.get("ADMIN_USERNAME") or "").strip()
    password = os.environ.get("ADMIN_PASSWORD") or ""
    if not username or not password:
        return None, None
    return username, password


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


def _sign_session_token(username: str, jti: str, issued_at: datetime, expires_at: datetime) -> str:
    key = _get_session_signing_key()
    header_b64 = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode("utf-8"))
    payload = {
        "sub": username,
        "jti": jti,
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
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
                "SELECT jti, username, expires_at, revoked_at FROM admin_sessions WHERE jti = %s",
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
    return {
        "jti": row["jti"],
        "username": row["username"],
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


def _require_admin_session(request: Request) -> dict:
    token, _ = _extract_session_token(request)
    session = _verify_active_session(token)
    if session is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    _check_admin(_get_admin_token())
    return session


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


def _apply_renewal(cur, license_key: str, plan: str) -> dict:
    """
    Core renewal logic shared by /api/v1/admin/renew and submission approval.
    Extends expires_at by PLANS[plan]['days'] from max(now, current expires_at).
    """
    plan_key = (plan or "").strip().lower()
    if plan_key not in PLANS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid plan '{plan}'. Allowed plans: {', '.join(PLANS.keys())}",
        )

    cur.execute(
        "SELECT license_key, status, expires_at, plan, has_paid_renewal FROM licenses WHERE license_key = %s FOR UPDATE",
        (license_key,),
    )
    row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Key not found")

    now = _utc_now()
    current_exp = _as_utc(row.get("expires_at"))
    base_time = max(now, current_exp) if current_exp is not None else now
    days_to_add = int(PLANS[plan_key]["days"])
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

    return {
        "ok": True,
        "license_key": license_key,
        "status": "active",
        "plan": plan_key,
        "days_added": days_to_add,
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

    plan_info = PLANS.get(claimed_plan, {})
    label = plan_info.get("label", claimed_plan)
    price = plan_info.get("price_inr", "?")
    days = plan_info.get("days", "?")
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


# ===================================================================== SCHEMAS
class ValidateRequest(BaseModel):
    license_key: str
    device_id: str
    app_version: str


class ValidateResponse(BaseModel):
    status: str  # "active" | "revoked" | "expired" | "unknown"
    message: str | None = None
    expires_at: str | None = None
    plan: str | None = None


class CreateLicenseRequest(BaseModel):
    license_key: str
    note: str | None = None
    plan: str = "trial"
    days: int | None = None


class AdminLoginRequest(BaseModel):
    username: str
    password: str


# ============================================================== PUBLIC ROUTES
@app.get("/api/v1/plans")
def get_plans(license_key: str | None = Query(default=None)):
    """
    Public endpoint returning available subscription plans plus whether the given
    license_key qualifies for the first-time paid renewal Launch Offer (launch90).
    """
    first_paid = False
    if license_key:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT license_key, plan, has_paid_renewal FROM licenses WHERE license_key = %s",
                    (license_key.strip(),),
                )
                row = cur.fetchone()
                first_paid = _is_first_paid_renewal(row)

    return {
        "plans": PLANS,
        "is_first_paid_renewal": first_paid,
        "upi_vpa": (os.environ.get("UPI_VPA") or "").strip(),
        "upi_name": (os.environ.get("UPI_PAYEE_NAME") or "").strip(),
    }


@app.post("/api/v1/validate", response_model=ValidateResponse)
def validate(req: ValidateRequest):
    now = _utc_now()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM licenses WHERE license_key = %s", (req.license_key,))
            row = cur.fetchone()

            if row is None:
                return ValidateResponse(status="unknown", message="License key not recognized.")

            status = (row["status"] or "").strip().lower()
            plan = (row.get("plan") or "trial").strip().lower()
            expires_at = _as_utc(row.get("expires_at"))
            expires_iso = _iso_utc(expires_at)

            cur.execute(
                "UPDATE licenses SET device_id = %s, app_version = %s, last_seen = %s WHERE license_key = %s",
                (req.device_id, req.app_version, now, req.license_key),
            )

            # Revoked is an active licensor action and always takes precedence over expiry
            if status == "revoked":
                return ValidateResponse(
                    status="revoked",
                    message="This license has been revoked by the licensor.",
                    expires_at=expires_iso,
                    plan=plan,
                )

            # Check plan / trial expiration timestamp
            if status == "expired" or (expires_at is not None and expires_at <= now):
                return ValidateResponse(
                    status="expired",
                    message="Your subscription or trial period has expired. Please renew to continue.",
                    expires_at=expires_iso,
                    plan=plan,
                )

            if status == "active":
                return ValidateResponse(
                    status="active",
                    expires_at=expires_iso,
                    plan=plan,
                )

            return ValidateResponse(
                status=status or "expired",
                message="This license is not active.",
                expires_at=expires_iso,
                plan=plan,
            )


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

    if plan_key not in PLANS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid plan '{claimed_plan}'. Allowed plans: {', '.join(PLANS.keys())}",
        )

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
            cur.execute(
                "SELECT license_key, status, plan, has_paid_renewal FROM licenses WHERE license_key = %s",
                (key,),
            )
            lic_row = cur.fetchone()
            if lic_row is None:
                raise HTTPException(status_code=404, detail="License key not recognized.")

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
                INSERT INTO payment_submissions (license_key, device_id, claimed_plan, image_data, content_type, submitted_at, status)
                VALUES (%s, %s, %s, %s, %s, %s, 'pending')
                RETURNING id, submitted_at
                """,
                (key, dev, plan_key, b64_image, mime_type, now),
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

    expected_user, expected_pass = _get_admin_credentials()
    admin_tok = _get_admin_token()
    if not expected_user or not expected_pass or not admin_tok:
        raise HTTPException(status_code=503, detail="Admin login is not configured on the server.")

    user_ok = hmac.compare_digest(req.username.encode("utf-8"), expected_user.encode("utf-8"))
    pass_ok = hmac.compare_digest(req.password.encode("utf-8"), expected_pass.encode("utf-8"))
    if not (user_ok and pass_ok):
        _record_login_failure(ip)
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    _clear_login_failures(ip)
    jti = secrets.token_urlsafe(24)
    now = _utc_now()
    ttl = max(60, int(os.environ.get("ADMIN_SESSION_TTL_SECONDS", str(SESSION_TTL_SECONDS))))
    expires_at = now + timedelta(seconds=ttl)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM admin_sessions WHERE expires_at < %s", (now - timedelta(days=1),))
            cur.execute(
                """
                INSERT INTO admin_sessions (jti, username, created_at, expires_at)
                VALUES (%s, %s, %s, %s)
                """,
                (jti, expected_user, now, expires_at),
            )

    token = _sign_session_token(expected_user, jti, now, expires_at)
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
        "username": expected_user,
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
    return {
        "authenticated": True,
        "username": session["username"],
        "expires_at": session["expires_at"],
        "plans": PLANS,
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
def create_license(req: CreateLicenseRequest, _auth: dict = Depends(_require_admin_api)):
    plan_key = (req.plan or "trial").strip().lower()
    if plan_key != "trial" and plan_key not in PLANS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid plan '{req.plan}'. Use 'trial' or one of: {', '.join(PLANS.keys())}",
        )

    duration_days = (
        int(req.days)
        if req.days is not None
        else (TRIAL_DAYS if plan_key == "trial" else int(PLANS[plan_key]["days"]))
    )
    expires_at = _utc_now() + timedelta(days=max(1, duration_days))
    has_paid = plan_key != "trial"

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO licenses (license_key, status, note, plan, expires_at, has_paid_renewal)
                VALUES (%s, 'active', %s, %s, %s, %s)
                ON CONFLICT (license_key) DO UPDATE SET
                    status = 'active',
                    note = EXCLUDED.note,
                    plan = EXCLUDED.plan,
                    expires_at = EXCLUDED.expires_at,
                    has_paid_renewal = EXCLUDED.has_paid_renewal
                """,
                (req.license_key.strip(), req.note, plan_key, expires_at, has_paid),
            )
    return {
        "ok": True,
        "license_key": req.license_key.strip(),
        "status": "active",
        "plan": plan_key,
        "expires_at": expires_at.isoformat(),
    }


@app.post("/api/v1/admin/renew")
def renew_license(
    license_key: str = Query(...),
    plan: str = Query(...),
    _auth: dict = Depends(_require_admin_api),
):
    with get_db() as conn:
        with conn.cursor() as cur:
            return _apply_renewal(cur, license_key.strip(), plan)


@app.post("/api/v1/admin/revoke")
def revoke_license(license_key: str, _auth: dict = Depends(_require_admin_api)):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE licenses SET status = 'revoked' WHERE license_key = %s", (license_key,))
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Key not found")
    return {"ok": True, "license_key": license_key, "status": "revoked"}


@app.post("/api/v1/admin/reactivate")
def reactivate_license(license_key: str, _auth: dict = Depends(_require_admin_api)):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE licenses SET status = 'active' WHERE license_key = %s", (license_key,))
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Key not found")
    return {"ok": True, "license_key": license_key, "status": "active"}


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
                       device_id, app_version, last_seen, note
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
            if status_filter == "all":
                cur.execute(
                    """
                    SELECT id, license_key, device_id, claimed_plan, image_data,
                           content_type, submitted_at, status
                    FROM payment_submissions
                    ORDER BY submitted_at DESC
                    """
                )
            else:
                cur.execute(
                    """
                    SELECT id, license_key, device_id, claimed_plan, image_data,
                           content_type, submitted_at, status
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
        plan_meta = PLANS.get(plan_key, {})
        mime = row.get("content_type") or "image/png"
        b64 = row["image_data"]
        results.append({
            "id": row["id"],
            "license_key": row["license_key"],
            "device_id": row["device_id"],
            "claimed_plan": plan_key,
            "plan_label": plan_meta.get("label", plan_key),
            "price_inr": plan_meta.get("price_inr"),
            "days": plan_meta.get("days"),
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
    _auth: dict = Depends(_require_admin_api),
):
    """Mark a pending submission approved and automatically apply the plan renewal atomically."""
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

            renewal = _apply_renewal(cur, sub["license_key"], sub["claimed_plan"])
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


def _plan_display_label(plan_key: str | None) -> str:
    k = (plan_key or "trial").strip().lower()
    if k == "trial":
        return "Free Trial"
    info = PLANS.get(k)
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
    x_admin_token: str | None = Header(default=None),
):
    """
    Lightweight overview payload for the Admin Dashboard Home tab.
    Computes overall health state (`all_good` vs `needs_attention`), actionable
    issues, active fleet list, counts, and current-month approved revenue without
    transferring base64 payment screenshot blobs.
    """
    _check_admin(x_admin_token)
    now = _utc_now()

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT license_key, status, plan, expires_at, has_paid_renewal,
                       device_id, app_version, last_seen, note
                FROM licenses
                ORDER BY license_key ASC
                """
            )
            license_rows = cur.fetchall()

            cur.execute(
                """
                SELECT id, license_key, claimed_plan, submitted_at, status
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
                "detail": f"License is manually revoked ({_plan_display_label(plan)}).",
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
                "detail": f"{_plan_display_label(plan)} expired on {exp_dt.strftime('%Y-%m-%d')}.",
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
                "detail": f"{_plan_display_label(plan)} ends on {exp_dt.strftime('%Y-%m-%d')}.",
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
            "plan_label": _plan_display_label(plan),
            "expires_at": _iso_utc(exp_dt),
            "expires_date": exp_dt.strftime("%Y-%m-%d") if exp_dt else None,
            "days_remaining": days_rem,
            "device_id": row.get("device_id"),
            "app_version": row.get("app_version"),
            "last_seen": _iso_utc(row.get("last_seen")),
            "note": row.get("note"),
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
                plan_meta = PLANS.get((sub.get("claimed_plan") or "").strip().lower(), {})
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
            "target_tab": "payments",
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


_DASHBOARD_HTML_PATH = Path(__file__).resolve().parent / "admin_dashboard.html"


@app.get("/", include_in_schema=False)
def root_redirect():
    return RedirectResponse(url="/admin")


@app.get("/admin", response_class=HTMLResponse, include_in_schema=False)
def serve_admin_dashboard():
    """Serve the lightweight mobile-friendly Admin Dashboard (Home, Licenses, Pending Payments)."""
    if not _DASHBOARD_HTML_PATH.is_file():
        raise HTTPException(status_code=500, detail="Admin dashboard HTML asset is missing.")
    return HTMLResponse(content=_DASHBOARD_HTML_PATH.read_text(encoding="utf-8"))
