"""
Comprehensive test suite for ANPR License & Subscription Server (`license_server.py`)
Tests trial creation, VIVEK-ANPR-0001 180-day migration, plans & launch90 eligibility,
expired vs revoked precedence, base64 Postgres screenshot upload, 10-minute rate limit,
Telegram sendPhoto dispatch, and admin approve/reject atomic workflows.
"""
import base64
import os
import re
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

os.environ["SKIP_INIT_DB_ON_IMPORT"] = "1"
os.environ["DATABASE_URL"] = "postgresql://mock/test"
os.environ["LICENSE_ADMIN_TOKEN"] = "test-admin-secret"
os.environ["UPI_VPA"] = "testmerchant@upi"
os.environ["UPI_PAYEE_NAME"] = "ANPR Security"

import license_server as srv


PNG_1X1 = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01"
    b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)


class FakePostgresDB:
    """Lightweight in-memory relational emulator for license_server's exact Postgres queries."""

    def __init__(self):
        self.licenses: dict[str, dict] = {}
        self.submissions: list[dict] = []
        self._next_sub_id = 1
        self.executed_sql: list[str] = []

    @contextmanager
    def connect(self):
        yield _FakeConn(self)


class _FakeConn:
    def __init__(self, db: FakePostgresDB):
        self.db = db

    def cursor(self):
        return _FakeCursor(self.db)


class _FakeCursor:
    def __init__(self, db: FakePostgresDB):
        self.db = db
        self._rows: list[dict] = []
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql: str, params=None):
        norm = " ".join(sql.split())
        self.db.executed_sql.append(norm)
        params = params or ()
        self._rows = []
        self.rowcount = 0

        if norm.startswith(("CREATE TABLE", "ALTER TABLE", "CREATE INDEX")):
            return

        if norm == "UPDATE licenses SET plan = 'trial' WHERE plan IS NULL":
            for row in self.db.licenses.values():
                if row.get("plan") is None:
                    row["plan"] = "trial"
                    self.rowcount += 1
            return

        if "WHERE license_key = 'VIVEK-ANPR-0001' AND expires_at IS NULL" in norm:
            row = self.db.licenses.get("VIVEK-ANPR-0001")
            if row and row.get("expires_at") is None:
                row["expires_at"] = datetime.now(timezone.utc) + timedelta(days=180)
                row["plan"] = "trial"
                self.rowcount = 1
            return

        if norm.startswith("SELECT") and "FROM licenses WHERE license_key = %s" in norm:
            row = self.db.licenses.get(params[0])
            self._rows = [dict(row)] if row else []
            return

        if norm.startswith("SELECT") and "FROM licenses ORDER BY" in norm:
            self._rows = [dict(self.db.licenses[k]) for k in sorted(self.db.licenses)]
            return

        if norm.startswith("INSERT INTO licenses"):
            key, note, plan, exp, has_paid = params
            self.db.licenses[key] = {
                "license_key": key,
                "status": "active",
                "device_id": None,
                "app_version": None,
                "last_seen": None,
                "note": note,
                "plan": plan,
                "expires_at": exp,
                "has_paid_renewal": has_paid,
            }
            self.rowcount = 1
            return

        if norm.startswith("UPDATE licenses SET device_id = %s"):
            dev, ver, seen, key = params
            if key in self.db.licenses:
                self.db.licenses[key].update(device_id=dev, app_version=ver, last_seen=seen)
                self.rowcount = 1
            return

        if norm.startswith("UPDATE licenses SET status = 'active', plan = %s"):
            plan, exp, key = params
            if key in self.db.licenses:
                self.db.licenses[key].update(
                    status="active", plan=plan, expires_at=exp, has_paid_renewal=True
                )
                self.rowcount = 1
            return

        if norm.startswith("UPDATE licenses SET status = 'revoked'"):
            key = params[0]
            if key in self.db.licenses:
                self.db.licenses[key]["status"] = "revoked"
                self.rowcount = 1
            return

        if norm.startswith("UPDATE licenses SET status = 'active' WHERE"):
            key = params[0]
            if key in self.db.licenses:
                self.db.licenses[key]["status"] = "active"
                self.rowcount = 1
            return

        if "FROM payment_submissions WHERE license_key = %s ORDER BY submitted_at DESC LIMIT 1" in norm:
            matches = [s for s in self.db.submissions if s["license_key"] == params[0]]
            matches.sort(key=lambda s: s["submitted_at"], reverse=True)
            self._rows = [dict(matches[0])] if matches else []
            return

        if norm.startswith("INSERT INTO payment_submissions"):
            key, dev, plan, b64, mime, submitted_at = params
            sub = {
                "id": self.db._next_sub_id,
                "license_key": key,
                "device_id": dev,
                "claimed_plan": plan,
                "image_data": b64,
                "content_type": mime,
                "submitted_at": submitted_at,
                "status": "pending",
            }
            self.db._next_sub_id += 1
            self.db.submissions.append(sub)
            self._rows = [{"id": sub["id"], "submitted_at": sub["submitted_at"]}]
            self.rowcount = 1
            return

        if "FROM payment_submissions WHERE id = %s" in norm:
            sub = next((s for s in self.db.submissions if s["id"] == params[0]), None)
            self._rows = [dict(sub)] if sub else []
            return

        if "FROM payment_submissions WHERE status = %s" in norm:
            matches = [dict(s) for s in self.db.submissions if s["status"] == params[0]]
            matches.sort(key=lambda s: s["submitted_at"], reverse=True)
            self._rows = matches
            return

        if "FROM payment_submissions ORDER BY submitted_at DESC" in norm:
            matches = [dict(s) for s in self.db.submissions]
            matches.sort(key=lambda s: s["submitted_at"], reverse=True)
            self._rows = matches
            return

        if norm.startswith("UPDATE payment_submissions SET status ="):
            m = re.search(r"status = '(\w+)'", norm)
            new_st = m.group(1)
            sub = next((s for s in self.db.submissions if s["id"] == params[0]), None)
            if sub:
                sub["status"] = new_st
                self.rowcount = 1
            return

        raise AssertionError(f"Unhandled SQL in test fake: {norm}")

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


@pytest.fixture
def env_client(monkeypatch):
    db = FakePostgresDB()
    # Seed legacy VIVEK-ANPR-0001 with NULL expires_at to verify one-time migration
    db.licenses["VIVEK-ANPR-0001"] = {
        "license_key": "VIVEK-ANPR-0001",
        "status": "active",
        "device_id": "dev-old",
        "app_version": "1.0.0",
        "last_seen": None,
        "note": "existing key",
        "plan": None,
        "expires_at": None,
        "has_paid_renewal": False,
    }
    monkeypatch.setattr(srv, "get_db", db.connect)
    srv.init_db()
    return TestClient(srv.app), db


ADMIN_HDR = {"X-Admin-Token": "test-admin-secret"}


def test_vivek_migration_idempotent_180_day_trial(env_client):
    client, db = env_client
    row = db.licenses["VIVEK-ANPR-0001"]
    assert row["plan"] == "trial"
    assert row["expires_at"] is not None
    delta = row["expires_at"] - datetime.now(timezone.utc)
    assert 179 <= delta.days <= 180

    # Re-running init_db must NOT reset expires_at once set
    original_exp = row["expires_at"] - timedelta(days=50)
    row["expires_at"] = original_exp
    srv.init_db()
    assert db.licenses["VIVEK-ANPR-0001"]["expires_at"] == original_exp


def test_create_license_defaults_to_180_day_trial_and_validate_returns_plan_expiry(env_client):
    client, _ = env_client
    r = client.post("/api/v1/admin/create", json={"license_key": "NEW-USER-001", "note": "Gate 2"}, headers=ADMIN_HDR)
    assert r.status_code == 200
    body = r.json()
    assert body["plan"] == "trial"
    exp = datetime.fromisoformat(body["expires_at"])
    assert 179 <= (exp - datetime.now(timezone.utc)).days <= 180

    # Validate active trial
    v = client.post("/api/v1/validate", json={"license_key": "NEW-USER-001", "device_id": "abc", "app_version": "1.0.0"})
    assert v.status_code == 200
    vb = v.json()
    assert vb["status"] == "active"
    assert vb["plan"] == "trial"
    assert vb["expires_at"] is not None


def test_validate_distinguishes_expired_vs_revoked(env_client):
    client, db = env_client
    # Expire VIVEK-ANPR-0001
    db.licenses["VIVEK-ANPR-0001"]["expires_at"] = datetime.now(timezone.utc) - timedelta(hours=2)
    v_exp = client.post("/api/v1/validate", json={"license_key": "VIVEK-ANPR-0001", "device_id": "d1", "app_version": "1.0.0"})
    assert v_exp.json()["status"] == "expired"
    assert v_exp.json()["plan"] == "trial"

    # Revoke overrides expired
    client.post("/api/v1/admin/revoke", params={"license_key": "VIVEK-ANPR-0001"}, headers=ADMIN_HDR)
    v_rev = client.post("/api/v1/validate", json={"license_key": "VIVEK-ANPR-0001", "device_id": "d1", "app_version": "1.0.0"})
    assert v_rev.json()["status"] == "revoked"


def test_plans_first_paid_renewal_flag_and_admin_renew(env_client):
    client, db = env_client
    p1 = client.get("/api/v1/plans", params={"license_key": "VIVEK-ANPR-0001"})
    assert p1.status_code == 200
    d1 = p1.json()
    assert set(d1["plans"].keys()) == {"monthly", "quarterly", "annual", "launch90"}
    assert d1["is_first_paid_renewal"] is True
    assert d1["upi_vpa"] == "testmerchant@upi"

    # Renew with launch90 while still having ~180 days -> extends from max(now, current_expires_at)
    old_exp = db.licenses["VIVEK-ANPR-0001"]["expires_at"]
    rn = client.post(
        "/api/v1/admin/renew",
        params={"license_key": "VIVEK-ANPR-0001", "plan": "launch90"},
        headers=ADMIN_HDR,
    )
    assert rn.status_code == 200
    new_exp = datetime.fromisoformat(rn.json()["expires_at"])
    assert abs((new_exp - old_exp).days - 90) <= 1

    # Now repeat renewer must see is_first_paid_renewal == False
    p2 = client.get("/api/v1/plans", params={"license_key": "VIVEK-ANPR-0001"})
    assert p2.json()["is_first_paid_renewal"] is False


def test_screenshot_upload_rate_limit_telegram_and_approve_reject(env_client, monkeypatch):
    client, db = env_client
    db.licenses["VIVEK-ANPR-0001"]["expires_at"] = datetime.now(timezone.utc) - timedelta(days=1)

    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "12345:FAKE_TOKEN")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "999888777")
    tg_calls = []

    def fake_tg_post(url, data=None, files=None, timeout=None):
        tg_calls.append({"url": url, "data": data, "files": files})
        resp = MagicMock()
        resp.status_code = 200
        return resp

    with patch.object(srv.requests, "post", side_effect=fake_tg_post):
        r = client.post(
            "/api/v1/payment-screenshot",
            data={"license_key": "VIVEK-ANPR-0001", "device_id": "dev-123", "claimed_plan": "launch90"},
            files={"image": ("proof.png", PNG_1X1, "image/png")},
        )
    assert r.status_code == 200
    sub_id = r.json()["submission_id"]
    assert r.json()["telegram_notified"] is True
    assert len(tg_calls) == 1
    assert "/sendPhoto" in tg_calls[0]["url"]
    assert "VIVEK-ANPR-0001" in tg_calls[0]["data"]["caption"]
    assert "launch90" in tg_calls[0]["data"]["caption"]

    # Immediate second upload within 10 minutes -> 429 rate limited
    r_rl = client.post(
        "/api/v1/payment-screenshot",
        data={"license_key": "VIVEK-ANPR-0001", "device_id": "dev-123", "claimed_plan": "monthly"},
        files={"image": ("proof2.png", PNG_1X1, "image/png")},
    )
    assert r_rl.status_code == 429

    # Admin lists pending submissions with viewable base64 image
    lst = client.get("/api/v1/admin/payment-submissions", headers=ADMIN_HDR)
    assert lst.status_code == 200
    items = lst.json()
    assert len(items) == 1
    assert items[0]["id"] == sub_id
    assert base64.b64decode(items[0]["image_data"]) == PNG_1X1
    assert items[0]["image_data_uri"].startswith("data:image/png;base64,")

    # Admin raw image view works
    img_r = client.get(f"/api/v1/admin/payment-submissions/{sub_id}/image", headers=ADMIN_HDR)
    assert img_r.status_code == 200 and img_r.content == PNG_1X1

    # Admin approves -> marks approved AND extends license atomically from now (since it was expired!)
    app_r = client.post(f"/api/v1/admin/payment-submissions/{sub_id}/approve", headers=ADMIN_HDR)
    assert app_r.status_code == 200
    assert app_r.json()["submission_status"] == "approved"
    assert app_r.json()["renewal"]["plan"] == "launch90"
    assert app_r.json()["renewal"]["days_added"] == 90

    # Double-approve rejected with 409
    app_r2 = client.post(f"/api/v1/admin/payment-submissions/{sub_id}/approve", headers=ADMIN_HDR)
    assert app_r2.status_code == 409

    # License is now active again & launch90 is no longer eligible
    v_now = client.post("/api/v1/validate", json={"license_key": "VIVEK-ANPR-0001", "device_id": "dev-123", "app_version": "1.0.0"})
    assert v_now.json()["status"] == "active"
    assert v_now.json()["plan"] == "launch90"

    # Simulate 11 minutes passing and submit a monthly proof, then reject it
    db.submissions[0]["submitted_at"] = datetime.now(timezone.utc) - timedelta(minutes=11)
    # Trying launch90 again after already paying must be blocked (400)
    r_bad_launch = client.post(
        "/api/v1/payment-screenshot",
        data={"license_key": "VIVEK-ANPR-0001", "device_id": "dev-123", "claimed_plan": "launch90"},
        files={"image": ("proof3.png", PNG_1X1, "image/png")},
    )
    assert r_bad_launch.status_code == 400

    with patch.object(srv.requests, "post", side_effect=fake_tg_post):
        r_m = client.post(
            "/api/v1/payment-screenshot",
            data={"license_key": "VIVEK-ANPR-0001", "device_id": "dev-123", "claimed_plan": "monthly"},
            files={"image": ("proof4.png", PNG_1X1, "image/png")},
        )
    assert r_m.status_code == 200
    sub2 = r_m.json()["submission_id"]
    exp_before_reject = db.licenses["VIVEK-ANPR-0001"]["expires_at"]
    rej_r = client.post(f"/api/v1/admin/payment-submissions/{sub2}/reject", headers=ADMIN_HDR)
    assert rej_r.status_code == 200 and rej_r.json()["submission_status"] == "rejected"
    assert db.licenses["VIVEK-ANPR-0001"]["expires_at"] == exp_before_reject
