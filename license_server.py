import os
from contextlib import contextmanager
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

DATABASE_URL = os.environ.get("DATABASE_URL")  # set this on Render — Neon connection string
ADMIN_TOKEN = os.environ.get("LICENSE_ADMIN_TOKEN")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is not set.")

app = FastAPI(title="License Server")


@contextmanager
def get_db():
    conn = psycopg2.connect(DATABASE_URL, sslmode="require")
    conn.cursor_factory = psycopg2.extras.RealDictCursor
    try:
        yield conn
        conn.commit()
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


def _check_admin(token: str | None):
    if not ADMIN_TOKEN or not token or token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden")


@app.post("/api/v1/validate", response_model=ValidateResponse)
def validate(req: ValidateRequest):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM licenses WHERE license_key = %s", (req.license_key,))
            row = cur.fetchone()

            if row is None:
                return ValidateResponse(status="unknown", message="License key not recognized.")

            status = row["status"]

            cur.execute(
                "UPDATE licenses SET device_id = %s, app_version = %s, last_seen = %s WHERE license_key = %s",
                (req.device_id, req.app_version, datetime.now(timezone.utc), req.license_key),
            )

            if status == "active":
                return ValidateResponse(status="active")
            elif status == "revoked":
                return ValidateResponse(status="revoked", message="This license has been revoked by the licensor.")
            else:
                return ValidateResponse(status="expired", message="This license has expired.")


class CreateLicenseRequest(BaseModel):
    license_key: str
    note: str | None = None


@app.post("/api/v1/admin/create")
def create_license(req: CreateLicenseRequest, x_admin_token: str | None = Header(default=None)):
    _check_admin(x_admin_token)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO licenses (license_key, status, note)
                VALUES (%s, 'active', %s)
                ON CONFLICT (license_key) DO UPDATE SET status = 'active', note = EXCLUDED.note
                """,
                (req.license_key, req.note),
            )
    return {"ok": True}


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


@app.get("/api/v1/admin/list")
def list_licenses(x_admin_token: str | None = Header(default=None)):
    _check_admin(x_admin_token)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT license_key, status, device_id, app_version, last_seen, note FROM licenses")
            return cur.fetchall()