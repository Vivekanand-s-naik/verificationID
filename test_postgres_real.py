"""
Real PostgreSQL 17 Integration & Concurrency Test Suite for `VerificationId`
===========================================================================
Executes directly against a REAL PostgreSQL database (no FakePostgresDB mocks)
specified via `REAL_POSTGRES_TEST_URL` (e.g. an isolated ephemeral PG17 cluster).

Verifies:
  1. Backward-compatible schema migration on pre-existing customer data:
     - Existing active subscriptions & payment history preserved untouched
     - Existing bound device backfilled into `device_trials`
     - Existing `expires_at` NEVER reset or shortened
     - Re-running `init_db()` is 100% idempotent
  2. Multi-threaded concurrent activation race on the SAME unbound license key
     (`SELECT ... FOR UPDATE`): strictly 1 device succeeds, all other devices
     receive `device_mismatch`!
  3. Multi-threaded concurrent activation race with MULTIPLE trial keys on the
     SAME `device_id` (`device_trials` PRIMARY KEY + `ON CONFLICT DO NOTHING`):
     strictly 1 trial key activates, all others receive `trial_already_used`!
  4. Duplicate `create_license()` rejected with 409 Conflict; blank key
     auto-generates high-entropy `ANPR-XXXX-XXXX-XXXX-XXXX`.
  5. Concurrent renewal serialization (`FOR UPDATE`) adds both renewals cleanly
     without losing days or changing `device_id`.
  6. Approving an old pending payment after license revocation fails with 409
     until SystemOwner explicitly reactivates it.
  7. Ed25519 signed offline lease generation & verification end-to-end.
  8. Migration recovery / rollback verification (transaction rollback leaves DB clean).
  9. Reset Plan (Handover) endpoint remains intact and functional on real PostgreSQL.
"""

from __future__ import annotations

import base64
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import psycopg2
import psycopg2.extras
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

REAL_PG_URL = os.environ.get("REAL_POSTGRES_TEST_URL", "").strip()
pytestmark = pytest.mark.skipif(
    not REAL_PG_URL,
    reason="REAL_POSTGRES_TEST_URL not set; skipping real PostgreSQL test suite.",
)


@pytest.fixture
def pg_env(monkeypatch):
    """Prepare a clean real PostgreSQL schema + Ed25519 signing key for each test."""
    os.environ["SKIP_INIT_DB_ON_IMPORT"] = "1"
    monkeypatch.setenv("DATABASE_URL", REAL_PG_URL)
    monkeypatch.setenv("LICENSE_ADMIN_TOKEN", "real-pg-admin-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "pg-owner")
    monkeypatch.setenv("ADMIN_PASSWORD", "PgOwnerStrong!2026")
    monkeypatch.setenv("UPI_VPA", "pgmerchant@upi")
    monkeypatch.setenv("UPI_PAYEE_NAME", "ANPR PG Test")

    priv = Ed25519PrivateKey.generate()
    priv_b64 = base64.b64encode(
        priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    ).decode("ascii")
    pub = priv.public_key()
    monkeypatch.setenv("LICENSE_SIGNING_PRIVATE_KEY_B64", priv_b64)

    import license_server as srv

    monkeypatch.setattr(srv, "DATABASE_URL", REAL_PG_URL)
    monkeypatch.setattr(srv, "ADMIN_TOKEN", "real-pg-admin-secret")
    srv._LOGIN_ATTEMPTS.clear()
    srv._UNKNOWN_KEY_ATTEMPTS.clear()
    srv._EMAIL_RELAY_ATTEMPTS.clear()

    # Drop and recreate clean public schema tables before each test
    conn = psycopg2.connect(REAL_PG_URL)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    finally:
        conn.close()

    return srv, TestClient(srv.app), pub


ADMIN_HDR = {"X-Admin-Token": "real-pg-admin-secret"}


def test_real_pg_backward_compatible_migration_preserves_existing_customers(pg_env):
    """Simulate a pre-migration Render DB with active customers & payments, run init_db(), verify zero data loss."""
    srv, client, _pub = pg_env

    # 1. Create legacy schema (BEFORE our P0 columns/tables existed)
    existing_exp = datetime(2027, 4, 15, 12, 0, 0, tzinfo=timezone.utc)
    existing_seen = datetime(2026, 11, 20, 8, 30, 0, tzinfo=timezone.utc)
    with psycopg2.connect(REAL_PG_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE licenses (
                    license_key TEXT PRIMARY KEY,
                    status TEXT NOT NULL DEFAULT 'active',
                    device_id TEXT,
                    app_version TEXT,
                    last_seen TIMESTAMPTZ,
                    note TEXT,
                    expires_at TIMESTAMPTZ,
                    plan TEXT NOT NULL DEFAULT 'trial',
                    has_paid_renewal BOOLEAN NOT NULL DEFAULT FALSE
                );
                CREATE TABLE payment_submissions (
                    id SERIAL PRIMARY KEY,
                    license_key TEXT NOT NULL REFERENCES licenses(license_key) ON DELETE CASCADE,
                    device_id TEXT NOT NULL,
                    claimed_plan TEXT NOT NULL,
                    image_data TEXT NOT NULL,
                    content_type TEXT NOT NULL DEFAULT 'image/png',
                    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    status TEXT NOT NULL DEFAULT 'pending'
                );
            """)
            cur.execute(
                """
                INSERT INTO licenses (license_key, status, device_id, app_version, last_seen, note, expires_at, plan, has_paid_renewal)
                VALUES (%s, 'active', %s, '1.0.0', %s, 'Legacy Customer', %s, 'annual', TRUE)
                """,
                ("LEGACY-CUST-001", "legacy-hw-001", existing_seen, existing_exp),
            )
            cur.execute(
                """
                INSERT INTO payment_submissions (license_key, device_id, claimed_plan, image_data, status)
                VALUES ('LEGACY-CUST-001', 'legacy-hw-001', 'annual', 'aW1hZ2U=', 'approved')
                """
            )

    # 2. Run our new init_db() twice (verifying idempotency)
    srv.init_db()
    srv.init_db()

    # 3. Verify existing customer subscription, expiry, device binding, and payment history are preserved verbatim
    with psycopg2.connect(REAL_PG_URL, cursor_factory=psycopg2.extras.RealDictCursor) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM licenses WHERE license_key = 'LEGACY-CUST-001'")
            lic = cur.fetchone()
            assert lic["expires_at"] == existing_exp
            assert lic["device_id"] == "legacy-hw-001"
            assert lic["plan"] == "annual"
            assert lic["has_paid_renewal"] is True
            assert lic["activated_at"] == existing_seen

            cur.execute("SELECT * FROM device_trials WHERE device_id = 'legacy-hw-001'")
            dt = cur.fetchone()
            assert dt is not None
            assert dt["first_license_key"] == "LEGACY-CUST-001"

            cur.execute("SELECT COUNT(*) AS cnt FROM payment_submissions WHERE license_key = 'LEGACY-CUST-001'")
            assert cur.fetchone()["cnt"] == 1

    # 4. Creating a brand-new trial key must NOT grant another trial to legacy-hw-001!
    c_resp = client.post("/api/v1/admin/create", json={"note": "Second trial attempt"}, headers=ADMIN_HDR)
    assert c_resp.status_code == 200
    new_trial_key = c_resp.json()["license_key"]
    assert new_trial_key.startswith("ANPR-")
    assert c_resp.json()["expires_at"] is None

    v_second = client.post(
        "/api/v1/validate",
        json={"license_key": new_trial_key, "device_id": "legacy-hw-001", "app_version": "1.0.0"},
    )
    assert v_second.status_code == 200
    assert v_second.json()["status"] == "trial_already_used"


def test_real_pg_concurrent_same_key_activation_race(pg_env):
    """10 threads racing to activate the SAME unbound key from 10 distinct devices -> strictly 1 binds!"""
    srv, client, pub = pg_env
    srv.init_db()

    cr = client.post("/api/v1/admin/create", json={"license_key": "RACE-KEY-001", "note": "Race test"}, headers=ADMIN_HDR)
    assert cr.status_code == 200
    assert cr.json()["expires_at"] is None  # Trial has NOT started yet!

    barrier = threading.Barrier(8)

    def worker(idx: int):
        c = TestClient(srv.app)
        barrier.wait()
        r = c.post(
            "/api/v1/validate",
            json={"license_key": "RACE-KEY-001", "device_id": f"race-device-{idx}", "app_version": "1.0.0"},
        )
        return idx, r.status_code, r.json()

    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(worker, range(8)))

    actives = [r for r in results if r[2]["status"] == "active"]
    mismatches = [r for r in results if r[2]["status"] == "device_mismatch"]
    assert len(actives) == 1, f"Expected strictly 1 winner, got {len(actives)}: {results}"
    assert len(mismatches) == 7

    # Winner received a cryptographically valid Ed25519 offline lease!
    winner_body = actives[0][2]
    lease = winner_body["offline_lease"]
    assert lease is not None and lease["alg"] == "Ed25519"
    payload_bytes = base64.b64decode(lease["payload_b64"])
    sig_bytes = base64.b64decode(lease["signature_b64"])
    pub.verify(sig_bytes, payload_bytes)
    claims = json.loads(payload_bytes.decode("utf-8"))
    assert claims["device_id"] == f"race-device-{actives[0][0]}"
    assert claims["expires_at"] is not None


def test_real_pg_concurrent_multiple_trial_keys_same_device_race(pg_env):
    """6 distinct trial keys racing to activate on the SAME device_id -> strictly 1 trial granted!"""
    srv, client, _pub = pg_env
    srv.init_db()

    keys = []
    for i in range(6):
        r = client.post("/api/v1/admin/create", json={"note": f"Trial {i}"}, headers=ADMIN_HDR)
        assert r.status_code == 200
        keys.append(r.json()["license_key"])

    barrier = threading.Barrier(len(keys))

    def worker(lic_key: str):
        c = TestClient(srv.app)
        barrier.wait()
        r = c.post(
            "/api/v1/validate",
            json={"license_key": lic_key, "device_id": "same-pc-race-001", "app_version": "1.0.0"},
        )
        return lic_key, r.status_code, r.json()["status"]

    with ThreadPoolExecutor(max_workers=len(keys)) as ex:
        results = list(ex.map(worker, keys))

    actives = [r for r in results if r[2] == "active"]
    rejected = [r for r in results if r[2] == "trial_already_used"]
    assert len(actives) == 1, f"Expected strictly 1 trial winner, got {results}"
    assert len(rejected) == len(keys) - 1


def test_real_pg_duplicate_key_409_concurrent_renewals_and_revoked_payment_guard(pg_env):
    """Test duplicate create 409, concurrent renewals preserving device_id, and revoked payment block."""
    srv, client, _pub = pg_env
    srv.init_db()

    # 1. Create key, reject duplicate with 409
    r1 = client.post("/api/v1/admin/create", json={"license_key": "UNIQ-PG-001", "note": "Orig"}, headers=ADMIN_HDR)
    assert r1.status_code == 200
    r_dup = client.post("/api/v1/admin/create", json={"license_key": "UNIQ-PG-001", "note": "Overwrite"}, headers=ADMIN_HDR)
    assert r_dup.status_code == 409

    # Bind to device and start 180-day trial
    v1 = client.post("/api/v1/validate", json={"license_key": "UNIQ-PG-001", "device_id": "pg-dev-1", "app_version": "1.0.0"})
    assert v1.json()["status"] == "active"
    initial_exp = datetime.fromisoformat(v1.json()["expires_at"])

    # 2. Two concurrent monthly (+30d) renewals -> serialized by FOR UPDATE -> total +60d, device_id preserved!
    barrier = threading.Barrier(2)

    def do_renew(_):
        c = TestClient(srv.app)
        barrier.wait()
        return c.post("/api/v1/admin/renew", params={"license_key": "UNIQ-PG-001", "plan": "monthly"}, headers=ADMIN_HDR)

    with ThreadPoolExecutor(max_workers=2) as ex:
        resps = list(ex.map(do_renew, range(2)))
    assert all(r.status_code == 200 for r in resps)

    with psycopg2.connect(REAL_PG_URL, cursor_factory=psycopg2.extras.RealDictCursor) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT device_id, expires_at, has_paid_renewal FROM licenses WHERE license_key = 'UNIQ-PG-001'")
            row = cur.fetchone()
            assert row["device_id"] == "pg-dev-1"
            assert row["has_paid_renewal"] is True
            added_days = (row["expires_at"] - initial_exp).total_seconds() / 86400.0
            assert 59.9 <= added_days <= 60.1, f"Lost update detected! Expected +60d, got +{added_days:.2f}d"

    # 3. Submit payment, revoke license, verify approval is blocked (409) until owner explicitly reactivates
    png = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01"
        b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    up = client.post(
        "/api/v1/payment-screenshot",
        data={"license_key": "UNIQ-PG-001", "device_id": "pg-dev-1", "claimed_plan": "quarterly"},
        files={"image": ("upi.png", png, "image/png")},
    )
    assert up.status_code == 200
    sub_id = up.json()["submission_id"]

    assert client.post("/api/v1/admin/revoke", params={"license_key": "UNIQ-PG-001"}, headers=ADMIN_HDR).status_code == 200

    # Approving pending payment while revoked -> 409 Conflict (submission stays pending, license stays revoked!)
    app_blocked = client.post(f"/api/v1/admin/payment-submissions/{sub_id}/approve", headers=ADMIN_HDR)
    assert app_blocked.status_code == 409
    assert client.post("/api/v1/validate", json={"license_key": "UNIQ-PG-001", "device_id": "pg-dev-1", "app_version": "1.0.0"}).json()["status"] == "revoked"

    # Explicit owner reactivation -> now approval succeeds cleanly!
    assert client.post("/api/v1/admin/reactivate", params={"license_key": "UNIQ-PG-001"}, headers=ADMIN_HDR).status_code == 200
    app_ok = client.post(f"/api/v1/admin/payment-submissions/{sub_id}/approve", headers=ADMIN_HDR)
    assert app_ok.status_code == 200

    # 4. Verify Reset Plan (Handover) remains untouched and works cleanly on real PostgreSQL
    reset_r = client.post("/api/v1/admin/reset-plan", params={"license_key": "UNIQ-PG-001", "plan": "trial"}, headers=ADMIN_HDR)
    assert reset_r.status_code == 200
    assert reset_r.json()["action"] == "reset_plan"
    assert reset_r.json()["days_reset"] == 180


def test_real_pg_transaction_rollback_and_recovery(pg_env):
    """Verify failed DB transaction rolls back cleanly without corrupting license or trial records."""
    srv, client, _pub = pg_env
    srv.init_db()

    client.post("/api/v1/admin/create", json={"license_key": "ROLLBACK-001"}, headers=ADMIN_HDR)
    client.post("/api/v1/validate", json={"license_key": "ROLLBACK-001", "device_id": "rb-dev-1", "app_version": "1.0.0"})

    with pytest.raises(RuntimeError, match="simulated failure"):
        with srv.get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE licenses SET status = 'revoked' WHERE license_key = 'ROLLBACK-001'")
                raise RuntimeError("simulated failure")

    # Status must still be 'active' because get_db() rolled back cleanly
    v = client.post("/api/v1/validate", json={"license_key": "ROLLBACK-001", "device_id": "rb-dev-1", "app_version": "1.0.0"})
    assert v.json()["status"] == "active"



def test_real_pg_silent_activate_device_concurrency_idempotency_and_owner_ops(pg_env):
    """
    Real PostgreSQL 17 end-to-end verification for POST /api/v1/activate-device:
      1. 8 concurrent first-launch threads from the SAME brand-new device_id race on
         /api/v1/activate-device -> strictly ONE license row created, ONE device_trials row,
         all 8 threads receive the SAME key & expiry (no duplicate licenses!).
      2. Re-calling /api/v1/activate-device after expiry or revocation returns exact existing
         state without resetting, extending, or creating a new license.
      3. A genuinely different device_id gets its own independent 180-day trial license.
      4. SystemOwner actions (revoke, reactivate, reset-plan handover, unbind-device,
         device-trials/override) work identically on auto-provisioned licenses!
    """
    srv, client, pub = pg_env
    srv.init_db()
    srv._ACTIVATE_DEVICE_ATTEMPTS.clear()

    barrier = threading.Barrier(8)

    def first_launch_worker(_idx: int):
        c = TestClient(srv.app)
        barrier.wait()
        r = c.post(
            "/api/v1/activate-device",
            json={"device_id": "fresh-win-pc-alpha-0001", "app_version": "1.0.0"},
        )
        return r.status_code, r.json()

    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(first_launch_worker, range(8)))

    assert all(code == 200 for code, _ in results)
    assert all(body["status"] == "active" for _, body in results)
    keys = {body["license_key"] for _, body in results}
    assert len(keys) == 1, f"Expected strictly 1 auto-provisioned key across 8 racing threads, got {keys}"
    key_alpha = next(iter(keys))
    assert key_alpha.startswith("ANPR-")
    newly_flags = [body["newly_provisioned"] for _, body in results]
    assert newly_flags.count(True) == 1
    assert newly_flags.count(False) == 7

    # Verify DB has strictly 1 license and 1 device_trials record for alpha, plus valid Ed25519 lease
    with psycopg2.connect(REAL_PG_URL, cursor_factory=psycopg2.extras.RealDictCursor) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM licenses WHERE device_id = 'fresh-win-pc-alpha-0001'")
            assert cur.fetchone()["cnt"] == 1
            cur.execute("SELECT * FROM device_trials WHERE device_id = 'fresh-win-pc-alpha-0001'")
            dt = cur.fetchone()
            assert dt is not None and dt["first_license_key"] == key_alpha

    lease = results[0][1]["offline_lease"]
    assert lease is not None and lease["alg"] == "Ed25519"
    pub.verify(base64.b64decode(lease["signature_b64"]), base64.b64decode(lease["payload_b64"]))

    # Genuinely different PC gets its own independent 180-day trial
    r_beta = client.post(
        "/api/v1/activate-device",
        json={"device_id": "fresh-win-pc-beta-0002", "app_version": "1.0.0"},
    )
    assert r_beta.status_code == 200
    b_beta = r_beta.json()
    assert b_beta["status"] == "active" and b_beta["newly_provisioned"] is True
    assert b_beta["license_key"] != key_alpha

    # Revoke alpha -> re-calling activate-device returns 'revoked' (no new trial!)
    assert client.post("/api/v1/admin/revoke", params={"license_key": key_alpha}, headers=ADMIN_HDR).status_code == 200
    r_rev = client.post(
        "/api/v1/activate-device",
        json={"device_id": "fresh-win-pc-alpha-0001", "app_version": "1.0.0"},
    )
    assert r_rev.status_code == 200
    assert r_rev.json()["status"] == "revoked"
    assert r_rev.json()["license_key"] == key_alpha
    assert r_rev.json()["offline_lease"] is None

    # Owner reactivates -> force expire -> re-calling activate-device returns 'expired' untouched!
    assert client.post("/api/v1/admin/reactivate", params={"license_key": key_alpha}, headers=ADMIN_HDR).status_code == 200
    assert client.post("/api/v1/admin/expire", params={"license_key": key_alpha}, headers=ADMIN_HDR).status_code == 200
    r_exp = client.post(
        "/api/v1/activate-device",
        json={"device_id": "fresh-win-pc-alpha-0001", "app_version": "1.0.0"},
    )
    assert r_exp.status_code == 200
    assert r_exp.json()["status"] == "expired"
    assert r_exp.json()["license_key"] == key_alpha

    # Reset Plan (Handover) works identically on the auto-provisioned license
    r_rst = client.post(
        "/api/v1/admin/reset-plan",
        params={"license_key": key_alpha, "plan": "trial"},
        headers=ADMIN_HDR,
    )
    assert r_rst.status_code == 200 and r_rst.json()["days_reset"] == 180

    # Owner unbinds alpha's license -> alpha calling activate-device MUST get trial_already_used (no 2nd free trial!)
    assert client.post("/api/v1/admin/unbind-device", params={"license_key": key_alpha}, headers=ADMIN_HDR).status_code == 200
    r_used = client.post(
        "/api/v1/activate-device",
        json={"device_id": "fresh-win-pc-alpha-0001", "app_version": "1.0.0"},
    )
    assert r_used.status_code == 200
    assert r_used.json()["status"] == "trial_already_used"

    # Owner trial override clears device_trials -> alpha can now legitimately auto-provision a fresh trial!
    ov = client.post(
        "/api/v1/admin/device-trials/override",
        json={"device_id": "fresh-win-pc-alpha-0001", "note": "RMA override"},
        headers=ADMIN_HDR,
    )
    assert ov.status_code == 200 and ov.json()["cleared"] is True
    r_fresh = client.post(
        "/api/v1/activate-device",
        json={"device_id": "fresh-win-pc-alpha-0001", "app_version": "1.0.0"},
    )
    assert r_fresh.status_code == 200
    assert r_fresh.json()["status"] == "active" and r_fresh.json()["newly_provisioned"] is True


def test_real_pg_contact_messages_keepalive_and_dynamic_trial_days(pg_env, monkeypatch):
    """
    Real PostgreSQL 17 end-to-end verification for:
      1. GET/HEAD /health and /ping keep-alive endpoints.
      2. POST /api/v1/contact-message persisted in Postgres `contact_messages` (separate from
         `payment_submissions`) with 2-minute DB rate limit enforcement.
      3. Dynamic `system_settings.trial_days`: 180 -> 7 -> new device gets 7-day trial ->
         7 -> 180 -> second new device gets 180-day trial while first device retains 7-day expiry!
    """
    from unittest.mock import MagicMock, patch

    srv, client, _pub = pg_env
    srv.init_db()
    srv._ACTIVATE_DEVICE_ATTEMPTS.clear()

    # 1. Keep-alive probes
    for path in ("/health", "/ping"):
        assert client.get(path).status_code == 200
        assert client.head(path).status_code == 200

    # 2. Contact message persisted in Postgres `contact_messages` + 2-min rate limit
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "11111:REAL_PG_MOCK_BOT")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "777666555")
    sent_tg = []

    def _mock_tg(url, data=None, timeout=None, **_kw):
        sent_tg.append((url, data))
        m = MagicMock()
        m.status_code = 200
        return m

    with patch.object(srv.requests, "post", side_effect=_mock_tg):
        cm1 = client.post(
            "/api/v1/contact-message",
            json={
                "license_key": "ANPR-DEMO-TEST-0001",
                "device_id": "pg-contact-dev-01",
                "message": "Gate camera 2 setup inquiry",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
    assert cm1.status_code == 200
    assert cm1.json()["telegram_notified"] is True
    assert len(sent_tg) == 1 and "📩 Message from [ANPR-DEMO-TEST-0001 / pg-contact-dev-01]:" in sent_tg[0][1]["text"]

    # Immediate repeat from same device -> 429 rate-limited via Postgres `received_at`
    cm_rl = client.post(
        "/api/v1/contact-message",
        json={"device_id": "pg-contact-dev-01", "message": "Immediate retry"},
    )
    assert cm_rl.status_code == 429

    with psycopg2.connect(REAL_PG_URL, cursor_factory=psycopg2.extras.RealDictCursor) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM contact_messages WHERE device_id = 'pg-contact-dev-01'")
            rows = cur.fetchall()
            assert len(rows) == 1
            assert rows[0]["message"] == "Gate camera 2 setup inquiry"
            assert rows[0]["telegram_notified"] is True
            cur.execute("SELECT COUNT(*) AS cnt FROM payment_submissions")
            assert cur.fetchone()["cnt"] == 0

    # 3. Dynamic trial_days in real PostgreSQL: 180 -> 7 -> 180 (non-retroactive!)
    s_init = client.get("/api/v1/admin/settings", headers=ADMIN_HDR)
    assert s_init.status_code == 200 and s_init.json()["trial_days"] == 180

    # Change trial_days to 7
    s_7 = client.put("/api/v1/admin/settings", json={"trial_days": 7}, headers=ADMIN_HDR)
    assert s_7.status_code == 200 and s_7.json()["trial_days"] == 7

    # Auto-provision Device A -> gets 7-day expiry
    dev_a = client.post("/api/v1/activate-device", json={"device_id": "pg-dyn-dev-a-0001", "app_version": "1.0.0"})
    assert dev_a.status_code == 200
    body_a = dev_a.json()
    assert body_a["status"] == "active" and body_a["newly_provisioned"] is True
    exp_a = datetime.fromisoformat(body_a["expires_at"])
    days_a = (exp_a - datetime.now(timezone.utc)).total_seconds() / 86400.0
    assert 6.9 <= days_a <= 7.1

    # Change trial_days back to 180 (re-running init_db() must NOT overwrite owner settings either!)
    s_30 = client.put("/api/v1/admin/settings", json={"trial_days": 30}, headers=ADMIN_HDR)
    assert s_30.status_code == 200 and s_30.json()["trial_days"] == 30
    srv.init_db()
    assert client.get("/api/v1/admin/settings", headers=ADMIN_HDR).json()["trial_days"] == 30

    # Auto-provision Device B -> gets 30-day expiry
    dev_b = client.post("/api/v1/activate-device", json={"device_id": "pg-dyn-dev-b-0002", "app_version": "1.0.0"})
    assert dev_b.status_code == 200
    body_b = dev_b.json()
    assert body_b["status"] == "active" and body_b["newly_provisioned"] is True
    exp_b = datetime.fromisoformat(body_b["expires_at"])
    days_b = (exp_b - datetime.now(timezone.utc)).total_seconds() / 86400.0
    assert 29.9 <= days_b <= 30.1

    # Device A's expiry in Postgres MUST remain strictly 7 days (non-retroactive!)
    with psycopg2.connect(REAL_PG_URL, cursor_factory=psycopg2.extras.RealDictCursor) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT expires_at, trial_days FROM licenses WHERE license_key = %s", (body_a["license_key"],))
            row_a = cur.fetchone()
            assert row_a["trial_days"] == 7
            assert abs((row_a["expires_at"] - exp_a).total_seconds()) < 1.0
            cur.execute("SELECT expires_at, trial_days FROM licenses WHERE license_key = %s", (body_b["license_key"],))
            row_b = cur.fetchone()
            assert row_b["trial_days"] == 30


def test_real_pg_remote_credential_provisions_one_shot_and_isolation(pg_env):
    """
    Real PostgreSQL 17 verification for `remote_credential_provisions`:
      1. SystemOwner queues credentials for Device A -> bcrypt-hashed in Postgres, consumed_at IS NULL.
      2. Device B calling `/api/v1/validate` receives `[]` (strict device isolation).
      3. Device A calling `/api/v1/validate` receives the pending provision once.
      4. Device A calls `/api/v1/credential-provisions/consume` -> `consumed_at` stamped in Postgres,
         server audit log updated, and subsequent `/api/v1/validate` returns `[]`.
    """
    srv, client, _pub = pg_env
    srv.init_db()
    srv._ACTIVATE_DEVICE_ATTEMPTS.clear()

    ra = client.post("/api/v1/activate-device", json={"device_id": "pg-prov-dev-a-001", "app_version": "1.0.0"})
    rb = client.post("/api/v1/activate-device", json={"device_id": "pg-prov-dev-b-002", "app_version": "1.0.0"})
    assert ra.status_code == 200 and rb.status_code == 200
    key_a = ra.json()["license_key"]
    key_b = rb.json()["license_key"]

    pr = client.post(
        "/api/v1/admin/credential-provisions",
        json={
            "device_id": "pg-prov-dev-a-001",
            "username": "pg_recovery",
            "email": "pg.recovery@facility.local",
            "password": "PgRecovery!2026",
            "role": "ADMIN",
        },
        headers=ADMIN_HDR,
    )
    assert pr.status_code == 200
    prov_id = pr.json()["id"]

    # Confirm real Postgres row stores ONLY bcrypt hash and consumed_at IS NULL
    with psycopg2.connect(REAL_PG_URL, cursor_factory=psycopg2.extras.RealDictCursor) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM remote_credential_provisions WHERE id = %s", (prov_id,))
            row = cur.fetchone()
            assert row is not None
            assert row["password_hash"].startswith("$2b$")
            assert "PgRecovery!2026" not in row["password_hash"]
            assert row["consumed_at"] is None

    # Device B sees nothing; Device A sees its pending provision
    assert client.post(
        "/api/v1/validate",
        json={"license_key": key_b, "device_id": "pg-prov-dev-b-002", "app_version": "1.0.0"},
    ).json()["pending_credential_provisions"] == []

    va1 = client.post(
        "/api/v1/validate",
        json={"license_key": key_a, "device_id": "pg-prov-dev-a-001", "app_version": "1.0.0"},
    ).json()
    assert len(va1["pending_credential_provisions"]) == 1
    assert va1["pending_credential_provisions"][0]["id"] == prov_id

    # Mark consumed
    c1 = client.post(
        "/api/v1/credential-provisions/consume",
        json={
            "provision_id": prov_id,
            "device_id": "pg-prov-dev-a-001",
            "license_key": key_a,
            "applied": True,
            "outcome": "created:ADMIN",
        },
    )
    assert c1.status_code == 200 and c1.json()["already_consumed"] is False

    # Idempotent re-consume returns already_consumed=True
    c2 = client.post(
        "/api/v1/credential-provisions/consume",
        json={"provision_id": prov_id, "device_id": "pg-prov-dev-a-001", "license_key": key_a, "applied": True},
    )
    assert c2.status_code == 200 and c2.json()["already_consumed"] is True

    # Next validate returns [] and Postgres shows consumed_at NOT NULL + audit entries
    va2 = client.post(
        "/api/v1/validate",
        json={"license_key": key_a, "device_id": "pg-prov-dev-a-001", "app_version": "1.0.0"},
    ).json()
    assert va2["pending_credential_provisions"] == []

    with psycopg2.connect(REAL_PG_URL, cursor_factory=psycopg2.extras.RealDictCursor) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT consumed_at FROM remote_credential_provisions WHERE id = %s", (prov_id,))
            assert cur.fetchone()["consumed_at"] is not None
            cur.execute(
                "SELECT action, note FROM license_audit_log WHERE action IN ('remote_credentials_provisioned', 'remote_credentials_consumed') ORDER BY id ASC"
            )
            audits = cur.fetchall()
            assert [a["action"] for a in audits] == ["remote_credentials_provisioned", "remote_credentials_consumed"]
            assert all("remotely provisioned by systemowner" in (a["note"] or "").lower() for a in audits)


def test_real_pg_label_delete_trial_clear_and_rbac_directory_end_to_end(pg_env):
    """
    Real PostgreSQL 17 end-to-end verification for all three new additions:
      1. License label saved in Postgres `licenses.label`, returned in `/admin/list` & `/admin/summary`.
      2. Hard-delete via `POST /api/v1/admin/delete` removes license row while keeping `device_trials`
         (so device receives `trial_already_used`), then explicit `POST /api/v1/admin/device-trials/override`
         clears the trial block and allows fresh device auto-provisioning!
      3. Client RBAC directory sync (`POST /api/v1/device-rbac/sync`) + owner portal listing
         (`GET /api/v1/admin/device-rbac-accounts`, zero passwords) + one-time password push
         (`password=None` auto-gen, `must_change_password=TRUE` in Postgres, bcrypt hash only).
    """
    srv, client, _pub = pg_env
    srv.init_db()
    srv._ACTIVATE_DEVICE_ATTEMPTS.clear()

    # 1. Auto-provision device + set label
    act1 = client.post("/api/v1/activate-device", json={"device_id": "pg-3feat-pc-001", "app_version": "1.0.0"})
    assert act1.status_code == 200
    key1 = act1.json()["license_key"]

    lbl = client.post(
        "/api/v1/admin/label",
        params={"license_key": key1, "label": "Vivek's Dev PC"},
        headers=ADMIN_HDR,
    )
    assert lbl.status_code == 200 and lbl.json()["label"] == "Vivek's Dev PC"

    with psycopg2.connect(REAL_PG_URL, cursor_factory=psycopg2.extras.RealDictCursor) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT label FROM licenses WHERE license_key = %s", (key1,))
            assert cur.fetchone()["label"] == "Vivek's Dev PC"

    lst = client.get("/api/v1/admin/list", headers=ADMIN_HDR).json()
    assert next(r for r in lst if r["license_key"] == key1)["label"] == "Vivek's Dev PC"
    summ = client.get("/api/v1/admin/summary", headers=ADMIN_HDR).json()
    assert next(r for r in summ["active_licenses"] if r["license_key"] == key1)["label"] == "Vivek's Dev PC"

    # 2. Delete license (Step 1: default keeps device_trials -> blocks repeat trial!)
    del_r = client.post("/api/v1/admin/delete", params={"license_key": key1}, headers=ADMIN_HDR)
    assert del_r.status_code == 200
    assert del_r.json()["had_device_trial"] is True
    assert del_r.json()["device_trial_cleared"] is False

    with psycopg2.connect(REAL_PG_URL, cursor_factory=psycopg2.extras.RealDictCursor) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM licenses WHERE license_key = %s", (key1,))
            assert cur.fetchone() is None
            cur.execute("SELECT 1 FROM device_trials WHERE device_id = 'pg-3feat-pc-001'")
            assert cur.fetchone() is not None

    assert client.post(
        "/api/v1/activate-device", json={"device_id": "pg-3feat-pc-001", "app_version": "1.0.0"}
    ).json()["status"] == "trial_already_used"

    # Step 2 (Explicit clear): clear device_trials -> device gets a fresh trial license!
    ov = client.post(
        "/api/v1/admin/device-trials/override",
        json={"device_id": "pg-3feat-pc-001", "note": "Explicit reset for re-provisioning test"},
        headers=ADMIN_HDR,
    )
    assert ov.status_code == 200 and ov.json()["cleared"] is True

    act2 = client.post("/api/v1/activate-device", json={"device_id": "pg-3feat-pc-001", "app_version": "1.0.0"})
    assert act2.status_code == 200
    assert act2.json()["status"] == "active" and act2.json()["newly_provisioned"] is True
    key2 = act2.json()["license_key"]
    assert key2 != key1
    client.post("/api/v1/admin/label", params={"license_key": key2, "label": "Vivek's Dev PC (Fresh)"}, headers=ADMIN_HDR)

    # 3. Sync RBAC roster + inspect owner portal + push auto-generated one-time password
    sync_r = client.post(
        "/api/v1/device-rbac/sync",
        json={
            "license_key": key2,
            "device_id": "pg-3feat-pc-001",
            "accounts": [
                {"username": "admin", "email": "admin@dev.local", "role": "ADMIN", "is_active": True, "must_change_password": False},
                {"username": "auditor1", "email": "auditor@dev.local", "role": "AUDITOR", "is_active": True, "must_change_password": False},
            ],
        },
    )
    assert sync_r.status_code == 200 and sync_r.json()["synced_count"] == 2

    dir_r = client.get("/api/v1/admin/device-rbac-accounts", headers=ADMIN_HDR)
    assert dir_r.status_code == 200
    dev_rec = next(d for d in dir_r.json() if d["device_id"] == "pg-3feat-pc-001")
    assert dev_rec["label"] == "Vivek's Dev PC (Fresh)"
    assert {a["username"] for a in dev_rec["accounts"]} == {"admin", "auditor1"}

    # Push auto-generated one-time password
    push = client.post(
        "/api/v1/admin/credential-provisions",
        json={
            "device_id": "pg-3feat-pc-001",
            "username": "admin",
            "email": "admin@dev.local",
            "password": None,
            "role": "ADMIN",
        },
        headers=ADMIN_HDR,
    )
    assert push.status_code == 200
    pb = push.json()
    otp = pb["one_time_password"]
    assert otp.startswith("Tmp!") and pb["must_change_password"] is True

    # Real Postgres row stores bcrypt hash + must_change_password=TRUE, NEVER plaintext
    with psycopg2.connect(REAL_PG_URL, cursor_factory=psycopg2.extras.RealDictCursor) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash, must_change_password FROM remote_credential_provisions WHERE id = %s", (pb["id"],))
            row = cur.fetchone()
            assert row["password_hash"].startswith("$2b$")
            assert otp not in row["password_hash"]
            assert row["must_change_password"] is True
            cur.execute("SELECT must_change_password FROM device_rbac_accounts WHERE device_id = 'pg-3feat-pc-001' AND username = 'admin'")
            assert cur.fetchone()["must_change_password"] is True

    # GET endpoints NEVER return the one-time password
    dir_after = client.get("/api/v1/admin/device-rbac-accounts", headers=ADMIN_HDR).json()
    assert otp not in json.dumps(dir_after)
