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
os.environ["ADMIN_USERNAME"] = "test-admin-user"
os.environ["ADMIN_PASSWORD"] = "test-admin-password"
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
        self.sessions: dict[str, dict] = {}
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

        if norm.startswith("UPDATE licenses SET status = 'active', expires_at = %s WHERE"):
            exp, key = params
            if key in self.db.licenses:
                self.db.licenses[key]["status"] = "active"
                self.db.licenses[key]["expires_at"] = exp
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

        if norm.startswith("DELETE FROM admin_sessions WHERE expires_at < %s"):
            cutoff = params[0]
            to_del = [jti for jti, s in self.db.sessions.items() if s["expires_at"] < cutoff]
            for jti in to_del:
                del self.db.sessions[jti]
            self.rowcount = len(to_del)
            return

        if norm.startswith("INSERT INTO admin_sessions"):
            jti, username, created_at, expires_at = params
            self.db.sessions[jti] = {
                "jti": jti,
                "username": username,
                "created_at": created_at,
                "expires_at": expires_at,
                "revoked_at": None,
            }
            self.rowcount = 1
            return

        if "FROM admin_sessions WHERE jti = %s" in norm:
            sess = self.db.sessions.get(params[0])
            self._rows = [dict(sess)] if sess else []
            return

        if norm.startswith("UPDATE admin_sessions SET revoked_at = %s WHERE jti = %s"):
            revoked_at, jti = params
            sess = self.db.sessions.get(jti)
            if sess and sess.get("revoked_at") is None:
                sess["revoked_at"] = revoked_at
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
    srv._LOGIN_ATTEMPTS.clear()
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


def test_admin_expire_endpoint_forces_expired_status(env_client):
    client, _ = env_client
    # Initially active (180-day trial)
    v1 = client.post("/api/v1/validate", json={"license_key": "VIVEK-ANPR-0001", "device_id": "d1", "app_version": "1.0.0"})
    assert v1.json()["status"] == "active"

    # Admin expire helper forces expires_at into the past so renewal flow can be tested immediately
    exp_r = client.post("/api/v1/admin/expire", params={"license_key": "VIVEK-ANPR-0001"}, headers=ADMIN_HDR)
    assert exp_r.status_code == 200
    assert exp_r.json()["status"] == "expired"

    v2 = client.post("/api/v1/validate", json={"license_key": "VIVEK-ANPR-0001", "device_id": "d1", "app_version": "1.0.0"})
    assert v2.json()["status"] == "expired"

    # Admin expire helper with positive days_from_now=3 sets active license expiring in 3 days (for reminder testing)
    soon_r = client.post(
        "/api/v1/admin/expire",
        params={"license_key": "VIVEK-ANPR-0001", "days_from_now": 3},
        headers=ADMIN_HDR,
    )
    assert soon_r.status_code == 200
    assert soon_r.json()["status"] == "active"
    v3 = client.post("/api/v1/validate", json={"license_key": "VIVEK-ANPR-0001", "device_id": "d1", "app_version": "1.0.0"})
    assert v3.json()["status"] == "active"
    exp_dt = datetime.fromisoformat(v3.json()["expires_at"])
    assert 2 <= (exp_dt - datetime.now(timezone.utc)).days <= 3


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


def test_admin_pages_require_session_auth_and_redirect(env_client):
    client, _ = env_client

    # Unauthenticated /admin and /admin/ redirect to /admin/login
    for path in ("/admin", "/admin/"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 302
        assert r.headers["location"] == "/admin/login"

    # JSON callers requesting /admin get 401
    r_json = client.get("/admin", headers={"Accept": "application/json"}, follow_redirects=False)
    assert r_json.status_code == 401

    # Raw X-Admin-Token header alone must NOT grant UI access without a session token
    r_hdr = client.get("/admin", headers=ADMIN_HDR, follow_redirects=False)
    assert r_hdr.status_code == 302
    assert r_hdr.headers["location"] == "/admin/login"

    # Login page loads cleanly as HTML
    login_page = client.get("/admin/login")
    assert login_page.status_code == 200
    assert "text/html" in login_page.headers["content-type"]
    assert "<form id=\"login-form\"" in login_page.text


def test_admin_login_validation_constant_time_and_session_lifecycle(env_client):
    client, db = env_client

    # Wrong username or wrong password -> 401
    bad_u = client.post("/api/v1/admin/login", json={"username": "wrong-user", "password": "test-admin-password"})
    assert bad_u.status_code == 401
    bad_p = client.post("/api/v1/admin/login", json={"username": "test-admin-user", "password": "wrong-password"})
    assert bad_p.status_code == 401

    # Unauthenticated admin API calls fail with 401
    assert client.get("/api/v1/admin/list").status_code == 401
    assert client.get("/api/v1/admin/session").status_code == 401

    # Raw LICENSE_ADMIN_TOKEN sent as Bearer token or session cookie must be rejected
    assert client.get("/api/v1/admin/list", headers={"Authorization": "Bearer test-admin-secret"}).status_code == 401
    bad_cookie_client = TestClient(srv.app)
    bad_cookie_client.cookies.set(srv.SESSION_COOKIE_NAME, "test-admin-secret")
    assert bad_cookie_client.get("/api/v1/admin/list").status_code == 401

    # Valid login over HTTPS proxy headers -> 200, HttpOnly+Secure cookie, signed JWT distinct from LICENSE_ADMIN_TOKEN
    https_client = TestClient(srv.app, base_url="https://testserver")
    https_login_r = https_client.post(
        "/api/v1/admin/login",
        json={"username": "test-admin-user", "password": "test-admin-password"},
        headers={"X-Forwarded-Proto": "https"},
    )
    assert https_login_r.status_code == 200
    set_cookie_hdr = https_login_r.headers.get("set-cookie", "")
    assert "admin_session=" in set_cookie_hdr
    assert "HttpOnly" in set_cookie_hdr
    assert "Secure" in set_cookie_hdr
    assert https_client.get("/admin", follow_redirects=False).status_code == 200

    # Valid login on standard HTTP test client -> cookie sent over HTTP
    login_r = client.post(
        "/api/v1/admin/login",
        json={"username": "test-admin-user", "password": "test-admin-password"},
    )
    assert login_r.status_code == 200
    login_body = login_r.json()
    session_token = login_body["token"]
    assert login_body["ok"] is True
    assert login_body["username"] == "test-admin-user"
    assert session_token != "test-admin-secret"
    assert "test-admin-secret" not in session_token
    assert "test-admin-password" not in session_token
    assert session_token.count(".") == 2

    # Cookie-authenticated browser requests succeed across UI & all admin API endpoints
    dash_r = client.get("/admin", follow_redirects=False)
    assert dash_r.status_code == 200
    assert "Pending Payments" in dash_r.text

    # Visiting /admin/login while authenticated redirects to /admin
    already_r = client.get("/admin/login", follow_redirects=False)
    assert already_r.status_code == 302
    assert already_r.headers["location"] == "/admin"

    sess_r = client.get("/api/v1/admin/session")
    assert sess_r.status_code == 200
    assert sess_r.json()["username"] == "test-admin-user"
    assert set(sess_r.json()["plans"].keys()) == {"monthly", "quarterly", "annual", "launch90"}

    # Upload a screenshot via public endpoint, then exercise create/list/revoke/reactivate/renew/approve/reject with cookie
    up1 = client.post(
        "/api/v1/payment-screenshot",
        data={"license_key": "VIVEK-ANPR-0001", "device_id": "dev-ui-1", "claimed_plan": "monthly"},
        files={"image": ("proof.png", PNG_1X1, "image/png")},
    )
    assert up1.status_code == 200
    sub_id = up1.json()["submission_id"]

    assert client.post("/api/v1/admin/create", json={"license_key": "UI-KEY-001", "note": "Front Gate"}).status_code == 200
    listed = client.get("/api/v1/admin/list")
    assert listed.status_code == 200
    assert any(item["license_key"] == "UI-KEY-001" for item in listed.json())

    assert client.post("/api/v1/admin/revoke", params={"license_key": "UI-KEY-001"}).status_code == 200
    assert client.post("/api/v1/admin/reactivate", params={"license_key": "UI-KEY-001"}).status_code == 200
    assert client.post("/api/v1/admin/renew", params={"license_key": "UI-KEY-001", "plan": "quarterly"}).status_code == 200
    assert client.get("/api/v1/admin/payment-submissions", params={"status": "pending"}).status_code == 200
    assert client.get(f"/api/v1/admin/payment-submissions/{sub_id}/image").status_code == 200
    assert client.post(f"/api/v1/admin/payment-submissions/{sub_id}/approve").status_code == 200

    # Submit a second screenshot after cooldown to test reject via Bearer token on a cookieless TestClient
    db.submissions[0]["submitted_at"] = datetime.now(timezone.utc) - timedelta(minutes=11)
    up2 = client.post(
        "/api/v1/payment-screenshot",
        data={"license_key": "VIVEK-ANPR-0001", "device_id": "dev-ui-1", "claimed_plan": "monthly"},
        files={"image": ("proof2.png", PNG_1X1, "image/png")},
    )
    assert up2.status_code == 200
    sub_id2 = up2.json()["submission_id"]

    bearer_client = TestClient(srv.app)
    bearer_hdr = {"Authorization": f"Bearer {session_token}"}
    assert bearer_client.get("/api/v1/admin/list", headers=bearer_hdr).status_code == 200
    assert bearer_client.get("/api/v1/admin/payment-submissions", params={"status": "all"}, headers=bearer_hdr).status_code == 200
    assert bearer_client.post(f"/api/v1/admin/payment-submissions/{sub_id2}/reject", headers=bearer_hdr).status_code == 200


def test_admin_session_expiration_and_logout_invalidation(env_client, monkeypatch):
    client, db = env_client

    # Login with short TTL and inspect expiration handling
    monkeypatch.setenv("ADMIN_SESSION_TTL_SECONDS", "60")
    login_r = client.post(
        "/api/v1/admin/login",
        json={"username": "test-admin-user", "password": "test-admin-password"},
    )
    assert login_r.status_code == 200
    token = login_r.json()["token"]

    # Forge an expired JWT signed with the server key and verify rejection
    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    expired_jwt = srv._sign_session_token("test-admin-user", "expired-jti", past - timedelta(hours=1), past)
    assert TestClient(srv.app).get(
        "/api/v1/admin/list", headers={"Authorization": f"Bearer {expired_jwt}"}
    ).status_code == 401

    # Also test DB expiry + stale cookie redirect to /admin/login?expired=1
    jti = next(iter(db.sessions))
    db.sessions[jti]["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=10)
    assert client.get("/api/v1/admin/list").status_code == 401
    exp_page = client.get("/admin", follow_redirects=False)
    assert exp_page.status_code == 302
    assert exp_page.headers["location"] == "/admin/login?expired=1"

    # Fresh login, then logout must revoke jti server-side and invalidate both cookie and Bearer token
    login_r2 = client.post(
        "/api/v1/admin/login",
        json={"username": "test-admin-user", "password": "test-admin-password"},
    )
    assert login_r2.status_code == 200
    token2 = login_r2.json()["token"]
    bearer_hdr = {"Authorization": f"Bearer {token2}"}
    assert TestClient(srv.app).get("/api/v1/admin/list", headers=bearer_hdr).status_code == 200

    logout_r = client.post("/api/v1/admin/logout")
    assert logout_r.status_code == 200
    assert logout_r.json()["ok"] is True

    # Cookie is cleared and old Bearer token is rejected because jti is revoked
    assert client.get("/api/v1/admin/list").status_code == 401
    assert TestClient(srv.app).get("/api/v1/admin/list", headers=bearer_hdr).status_code == 401
    assert client.get("/admin", follow_redirects=False).status_code == 302


def test_admin_login_missing_env_fails_closed_and_rate_limit(env_client, monkeypatch):
    client, _ = env_client

    # Missing ADMIN_PASSWORD -> 503
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    r_no_pw = client.post(
        "/api/v1/admin/login",
        json={"username": "test-admin-user", "password": "test-admin-password"},
    )
    assert r_no_pw.status_code == 503

    # Missing ADMIN_USERNAME -> 503
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.delenv("ADMIN_USERNAME", raising=False)
    r_no_user = client.post(
        "/api/v1/admin/login",
        json={"username": "test-admin-user", "password": "test-admin-password"},
    )
    assert r_no_user.status_code == 503

    # Restore credentials, log in, then verify removing LICENSE_ADMIN_TOKEN blocks admin routes
    monkeypatch.setenv("ADMIN_USERNAME", "test-admin-user")
    monkeypatch.setenv("ADMIN_SESSION_SECRET", "separate-session-secret")
    login_r = client.post(
        "/api/v1/admin/login",
        json={"username": "test-admin-user", "password": "test-admin-password"},
    )
    assert login_r.status_code == 200

    monkeypatch.delenv("LICENSE_ADMIN_TOKEN", raising=False)
    monkeypatch.setattr(srv, "ADMIN_TOKEN", None)
    assert client.get("/api/v1/admin/list").status_code == 403
    assert client.get("/admin", follow_redirects=False).status_code == 403

    # Restore LICENSE_ADMIN_TOKEN and verify login rate limiting after repeated failures
    monkeypatch.setenv("LICENSE_ADMIN_TOKEN", "test-admin-secret")
    monkeypatch.setattr(srv, "ADMIN_TOKEN", "test-admin-secret")
    srv._LOGIN_ATTEMPTS.clear()
    for _ in range(srv.LOGIN_RATE_LIMIT_MAX_ATTEMPTS):
        bad = client.post(
            "/api/v1/admin/login",
            json={"username": "test-admin-user", "password": "wrong-password"},
        )
        assert bad.status_code == 401
    blocked = client.post(
        "/api/v1/admin/login",
        json={"username": "test-admin-user", "password": "test-admin-password"},
    )
    assert blocked.status_code == 429


def test_served_html_contains_no_secrets(env_client):
    client, _ = env_client

    login_html_r = client.get("/admin/login")
    assert login_html_r.status_code == 200
    assert "no-store" in login_html_r.headers.get("cache-control", "")

    login_r = client.post(
        "/api/v1/admin/login",
        json={"username": "test-admin-user", "password": "test-admin-password"},
    )
    assert login_r.status_code == 200

    dash_html_r = client.get("/admin")
    assert dash_html_r.status_code == 200
    assert "no-store" in dash_html_r.headers.get("cache-control", "")
    assert "Content-Security-Policy" in dash_html_r.headers

    forbidden_substrings = [
        "test-admin-secret",
        "test-admin-password",
        "LICENSE_ADMIN_TOKEN",
        "ADMIN_PASSWORD",
        "X-Admin-Token",
    ]
    for body in (login_html_r.text, dash_html_r.text):
        for needle in forbidden_substrings:
            assert needle not in body, f"Forbidden secret/identifier leaked into HTML: {needle}"


def test_admin_summary_states_revenue_and_dashboard_html(env_client):
    """Verify authenticated GET /admin HTML and GET /api/v1/admin/summary all_good vs needs_attention."""
    client, db = env_client

    # Unauthenticated access redirects UI and rejects API summary
    assert client.get("/admin", follow_redirects=False).status_code == 302
    assert client.get("/api/v1/admin/summary").status_code == 401

    # Log in via session endpoint so /admin renders dashboard.html
    login_r = client.post(
        "/api/v1/admin/login",
        json={"username": "test-admin-user", "password": "test-admin-password"},
    )
    assert login_r.status_code == 200

    # 1. Admin dashboard HTML defaults to Home tab first and queries /api/v1/admin/summary
    page = client.get("/admin", follow_redirects=False)
    assert page.status_code == 200
    assert 'data-tab="home"' in page.text
    assert 'id="panel-home" class="panel active"' in page.text
    assert page.text.index('data-tab="home"') < page.text.index('data-tab="pending"')
    assert "/api/v1/admin/summary" in page.text
    assert "All Systems Active" in page.text
    assert "home-good-shell" in page.text
    assert "home-plain-shell" in page.text

    # 2. Single healthy active license + 0 pending submissions -> all_good (works via session cookie & token)
    s1_cookie = client.get("/api/v1/admin/summary")
    assert s1_cookie.status_code == 200
    s1 = TestClient(srv.app).get("/api/v1/admin/summary", headers=ADMIN_HDR)
    assert s1.status_code == 200
    b1 = s1.json()
    assert b1["overall_state"] == "all_good"
    assert b1["issues"] == []
    assert b1["primary_license"]["license_key"] == "VIVEK-ANPR-0001"
    assert b1["counts"]["total_licenses"] == 1
    assert b1["counts"]["active_licenses"] == 1
    assert b1["counts"]["pending_payments"] == 0
    assert b1["counts"]["revenue_this_month_inr"] == 0

    # 3. Pending payment flips state to needs_attention with jump link to payments/pending tab
    r_sub = client.post(
        "/api/v1/payment-screenshot",
        data={"license_key": "VIVEK-ANPR-0001", "device_id": "dev-1", "claimed_plan": "annual"},
        files={"image": ("p.png", PNG_1X1, "image/png")},
    )
    sub_id = r_sub.json()["submission_id"]
    s2 = client.get("/api/v1/admin/summary").json()
    assert s2["overall_state"] == "needs_attention"
    assert s2["counts"]["pending_payments"] == 1
    assert any(i["type"] == "pending_payments" and i["target_tab"] in {"pending", "payments"} for i in s2["issues"])

    # 4. Approving payment clears pending issue, restores all_good, and counts ₹900 monthly revenue
    client.post(f"/api/v1/admin/payment-submissions/{sub_id}/approve")
    s3 = client.get("/api/v1/admin/summary").json()
    assert s3["overall_state"] == "all_good"
    assert s3["counts"]["pending_payments"] == 0
    assert s3["counts"]["approved_payments_this_month"] == 1
    assert s3["counts"]["revenue_this_month_inr"] == 900

    # 5. Mixed fleet (1 active + 1 revoked + 1 expiring soon) -> needs_attention overall, active listed separately
    client.post("/api/v1/admin/create", json={"license_key": "CUST-0002", "note": "Gate 2"})
    client.post("/api/v1/admin/revoke", params={"license_key": "CUST-0002"})
    client.post("/api/v1/admin/create", json={"license_key": "CUST-0003", "note": "Gate 3"})
    client.post("/api/v1/admin/expire", params={"license_key": "CUST-0003", "days_from_now": 3})

    s4 = client.get("/api/v1/admin/summary").json()
    assert s4["overall_state"] == "needs_attention"
    assert s4["counts"]["total_licenses"] == 3
    assert s4["counts"]["active_licenses"] == 1
    assert s4["counts"]["revoked_licenses"] == 1
    assert s4["counts"]["expiring_soon_licenses"] == 1
    issue_types = {i["type"] for i in s4["issues"]}
    assert {"revoked", "expiring_soon"}.issubset(issue_types)
    assert [a["license_key"] for a in s4["active_licenses"]] == ["VIVEK-ANPR-0001"]
