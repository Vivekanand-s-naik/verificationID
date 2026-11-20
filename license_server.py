import base64
import hmac
import logging
import os
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import psycopg2
import psycopg2.extras
import requests
from fastapi import FastAPI, File, Form, Header, HTTPException, Query, Response, UploadFile
from pydantic import BaseModel

logger = logging.getLogger("license_server")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

DATABASE_URL = os.environ.get("DATABASE_URL")  # set on Render — Neon Postgres connection string
ADMIN_TOKEN = os.environ.get("LICENSE_ADMIN_TOKEN")

TRIAL_DAYS = 180
SCREENSHOT_RATE_LIMIT_MINUTES = 10
MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024  # 5 MB

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


if os.environ.get("SKIP_INIT_DB_ON_IMPORT") != "1":
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL environment variable is not set.")
    init_db()


def _check_admin(token: str | None):
    expected = os.environ.get("LICENSE_ADMIN_TOKEN") or ADMIN_TOKEN
    if not expected or not token or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=403, detail="Forbidden")


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

    caption = (
        f"ANPR Payment Verification Required (#{submission_id})\n"
        f"License Key: {license_key}\n"
        f"Device ID: {device_id}\n"
        f"Claimed Plan: {claimed_plan} ({label} — Rs.{price} / {days}d)\n"
        f"Submitted (UTC): {submitted_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
        f"Verify in your UPI/bank app, then approve or reject via admin API:\n"
        f"POST /api/v1/admin/payment-submissions/{submission_id}/approve\n"
        f"POST /api/v1/admin/payment-submissions/{submission_id}/reject"
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


# =============================================================== ADMIN ROUTES
@app.post("/api/v1/admin/create")
def create_license(req: CreateLicenseRequest, x_admin_token: str | None = Header(default=None)):
    _check_admin(x_admin_token)
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
    x_admin_token: str | None = Header(default=None),
):
    _check_admin(x_admin_token)
    with get_db() as conn:
        with conn.cursor() as cur:
            return _apply_renewal(cur, license_key.strip(), plan)


@app.post("/api/v1/admin/revoke")
def revoke_license(license_key: str, x_admin_token: str | None = Header(default=None)):
    _check_admin(x_admin_token)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE licenses SET status = 'revoked' WHERE license_key = %s", (license_key,))
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Key not found")
    return {"ok": True, "license_key": license_key, "status": "revoked"}


@app.post("/api/v1/admin/reactivate")
def reactivate_license(license_key: str, x_admin_token: str | None = Header(default=None)):
    _check_admin(x_admin_token)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE licenses SET status = 'active' WHERE license_key = %s", (license_key,))
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Key not found")
    return {"ok": True, "license_key": license_key, "status": "active"}


@app.post("/api/v1/admin/expire")
def force_expire_license(
    license_key: str = Query(...),
    x_admin_token: str | None = Header(default=None),
):
    """Admin test helper: move a license's expires_at into the past so the expired renewal flow can be tested."""
    _check_admin(x_admin_token)
    expired_at = _utc_now() - timedelta(hours=1)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE licenses SET status = 'active', expires_at = %s WHERE license_key = %s",
                (expired_at, license_key.strip()),
            )
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Key not found")
    return {
        "ok": True,
        "license_key": license_key.strip(),
        "status": "expired",
        "expires_at": expired_at.isoformat(),
    }


@app.get("/api/v1/admin/list")
def list_licenses(x_admin_token: str | None = Header(default=None)):
    _check_admin(x_admin_token)
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
    x_admin_token: str | None = Header(default=None),
):
    """List payment screenshot submissions (defaults to 'pending'; pass status=all for full history)."""
    _check_admin(x_admin_token)
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
    x_admin_token: str | None = Header(default=None),
):
    """Return the raw decoded screenshot image for direct viewing."""
    _check_admin(x_admin_token)
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
    x_admin_token: str | None = Header(default=None),
):
    """Mark a pending submission approved and automatically apply the plan renewal atomically."""
    _check_admin(x_admin_token)
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
    x_admin_token: str | None = Header(default=None),
):
    """Mark a pending submission rejected without applying any license renewal."""
    _check_admin(x_admin_token)
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
