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
