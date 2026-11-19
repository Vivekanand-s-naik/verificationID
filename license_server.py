import hashlib
import hmac
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

DB_PATH = os.environ.get("LICENSE_DB_PATH", "licenses.db")
ADMIN_TOKEN = os.environ.get("LICENSE_ADMIN_TOKEN")  # set this in your host's env vars

app = FastAPI(title="License Server")


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                license_key TEXT PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'active',
                device_id TEXT,
                app_version TEXT,
                last_seen TEXT,
                note TEXT
            )
        """)


init_db()


class ValidateRequest(BaseModel):
    license_key: str
    device_id: str
    app_version: str


class ValidateResponse(BaseModel):
    status: str  # "active" | "revoked" | "expired" | "unknown"
    message: str | None = None


def _hash_ok(a: str, b: str) -> bool:
    # constant-time compare to avoid timing attacks on key lookups
    return hmac.compare_digest(a, b)


@app.post("/api/v1/validate", response_model=ValidateResponse)
def validate(req: ValidateRequest):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM licenses WHERE license_key = ?", (req.license_key,)
        ).fetchone()

        if row is None:
            return ValidateResponse(status="unknown", message="License key not recognized.")

        status = row["status"]

        conn.execute(
            "UPDATE licenses SET device_id = ?, app_version = ?, last_seen = ? WHERE license_key = ?",
            (req.device_id, req.app_version, datetime.now(timezone.utc).isoformat(), req.license_key),
        )

        if status == "active":
            return ValidateResponse(status="active")
        elif status == "revoked":
            return ValidateResponse(status="revoked", message="This license has been revoked by the licensor.")
        else:
            return ValidateResponse(status="expired", message="This license has expired.")


# --- Admin endpoints: protect with a secret token, never leave this open ---

def _check_admin(token: str | None):
    if not ADMIN_TOKEN or not token or not _hash_ok(token, ADMIN_TOKEN):
        raise HTTPException(status_code=403, detail="Forbidden")


class CreateLicenseRequest(BaseModel):
    license_key: str
    note: str | None = None


@app.post("/api/v1/admin/create")
def create_license(req: CreateLicenseRequest, x_admin_token: str | None = Header(default=None)):
    _check_admin(x_admin_token)
    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO licenses (license_key, status, note) VALUES (?, 'active', ?)",
            (req.license_key, req.note),
        )
    return {"ok": True}


@app.post("/api/v1/admin/revoke")
def revoke_license(license_key: str, x_admin_token: str | None = Header(default=None)):
    _check_admin(x_admin_token)
    with get_db() as conn:
        result = conn.execute(
            "UPDATE licenses SET status = 'revoked' WHERE license_key = ?", (license_key,)
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Key not found")
    return {"ok": True, "license_key": license_key, "status": "revoked"}


@app.post("/api/v1/admin/reactivate")
def reactivate_license(license_key: str, x_admin_token: str | None = Header(default=None)):
    _check_admin(x_admin_token)
    with get_db() as conn:
        result = conn.execute(
            "UPDATE licenses SET status = 'active' WHERE license_key = ?", (license_key,)
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Key not found")
    return {"ok": True, "license_key": license_key, "status": "active"}


@app.get("/api/v1/admin/list")
def list_licenses(x_admin_token: str | None = Header(default=None)):
    _check_admin(x_admin_token)
    with get_db() as conn:
        rows = conn.execute("SELECT license_key, status, device_id, app_version, last_seen, note FROM licenses").fetchall()
        return [dict(r) for r in rows]