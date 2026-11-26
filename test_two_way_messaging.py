"""
Server-Side Two-Way License-Linked Messaging Test Suite (Simulated FakePostgresDB)
==================================================================================
Tests all security, isolation, status-transition, rate-limiting, idempotency,
audit-trail, log-redaction, RBAC, and device-lifecycle invariants of the
individual two-way messaging endpoints in `license_server.py`.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

os.environ["SKIP_INIT_DB_ON_IMPORT"] = "1"
os.environ["DATABASE_URL"] = "postgresql://mock/test"
os.environ["LICENSE_ADMIN_TOKEN"] = "test-admin-secret"
os.environ["ADMIN_USERNAME"] = "test-owner"
os.environ["ADMIN_PASSWORD"] = "OwnerSecret!2026"

import license_server as srv
from test_license_server import FakePostgresDB

ADMIN_HDR = {"X-Admin-Token": "test-admin-secret"}


@pytest.fixture
def msg_env(monkeypatch):
    db = FakePostgresDB()
    now = datetime.now(timezone.utc)
    db.licenses["LIC-ALPHA-001"] = {
        "license_key": "LIC-ALPHA-001",
        "status": "active",
        "device_id": "dev-alpha-1111111111111111",
        "app_version": "2.1.0",
        "last_seen": now,
        "note": "Alpha Gate Customer",
        "label": "Alpha Main Gate",
        "plan": "annual",
        "expires_at": now + timedelta(days=120),
        "has_paid_renewal": True,
        "activated_at": now - timedelta(days=5),
        "trial_days": 180,
        "allow_repeat_trial": False,
    }
    db.licenses["LIC-BETA-002"] = {
        "license_key": "LIC-BETA-002",
        "status": "active",
        "device_id": "dev-beta-2222222222222222",
        "app_version": "2.1.0",
        "last_seen": now,
        "note": "Beta Warehouse Customer",
        "label": "Beta West Gate",
        "plan": "monthly",
        "expires_at": now + timedelta(days=25),
        "has_paid_renewal": True,
        "activated_at": now - timedelta(days=3),
        "trial_days": 180,
        "allow_repeat_trial": False,
    }
    db.licenses["LIC-UNBOUND-003"] = {
        "license_key": "LIC-UNBOUND-003",
        "status": "active",
        "device_id": None,
        "app_version": None,
        "last_seen": None,
        "note": "Unbound Key",
        "label": "Unbound Staging",
        "plan": "trial",
        "expires_at": None,
        "has_paid_renewal": False,
        "activated_at": None,
        "trial_days": 180,
        "allow_repeat_trial": False,
    }
    db.licenses["LIC-EXPIRED-004"] = {
        "license_key": "LIC-EXPIRED-004",
        "status": "active",
        "device_id": "dev-expired-44444444444444",
        "app_version": "2.0.0",
        "last_seen": now - timedelta(days=10),
        "note": "Expired Site",
        "label": "Expired Gate",
        "plan": "trial",
        "expires_at": now - timedelta(hours=2),
        "has_paid_renewal": False,
        "activated_at": now - timedelta(days=181),
        "trial_days": 180,
        "allow_repeat_trial": False,
    }

    monkeypatch.setenv("ADMIN_USERNAME", "test-owner")
    monkeypatch.setenv("ADMIN_PASSWORD", "OwnerSecret!2026")
    monkeypatch.setenv("LICENSE_ADMIN_TOKEN", "test-admin-secret")
    monkeypatch.setattr(srv, "get_db", db.connect)
    monkeypatch.setattr(srv, "ADMIN_TOKEN", "test-admin-secret")
    srv._LOGIN_ATTEMPTS.clear()
    srv._UNKNOWN_KEY_ATTEMPTS.clear()
    srv._CLIENT_MESSAGE_ATTEMPTS.clear()
    srv.init_db()

    # Seed a non-owner 'admin' user as well to test RBAC distinction
    db.admin_users.append(
        {
            "id": db._next_admin_id,
            "username": "support-admin",
            "email": "support@example.com",
            "password_hash": srv._hash_password("SupportAdmin!2026"),
            "role": "admin",
            "created_at": now,
            "updated_at": now,
        }
    )
    db._next_admin_id += 1

    return srv, db, TestClient(srv.app)


def _login_session(client: TestClient, username: str, password: str) -> dict:
    r = client.post("/api/v1/admin/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_01_02_03_06_full_two_way_flow_and_status_transitions(msg_env, caplog):
    _, db, client = msg_env
    caplog.set_level(logging.INFO, logger="license_server")

    secret_client_phrase = "CONFIDENTIAL_GATE_ALERT_9911"
    secret_admin_phrase = "PRIVATE_ADMIN_INSTRUCTIONS_7744"

    # 1. Client -> Server
    r_send = client.post(
        "/api/v1/messages/send",
        json={
            "license_key": "LIC-ALPHA-001",
            "device_id": "dev-alpha-1111111111111111",
            "body": f"Hello admin, gate 1 camera needs check ({secret_client_phrase})",
            "idempotency_key": "cli-idem-1",
            "operator_name": "gate_op",
        },
    )
    assert r_send.status_code == 200, r_send.text
    s_data = r_send.json()
    assert s_data["ok"] is True and s_data["deduplicated"] is False
    c_msg = s_data["message"]
    assert c_msg["license_key"] == "LIC-ALPHA-001"
    assert c_msg["sender_type"] == "client"
    assert c_msg["status"] == "received"
    assert c_msg["created_at"] is not None
    assert c_msg["read_at"] is None

    # Duplicate idempotency_key returns same record without inserting duplicate
    r_dup = client.post(
        "/api/v1/messages/send",
        json={
            "license_key": "LIC-ALPHA-001",
            "device_id": "dev-alpha-1111111111111111",
            "body": f"Hello admin, gate 1 camera needs check ({secret_client_phrase})",
            "idempotency_key": "cli-idem-1",
        },
    )
    assert r_dup.status_code == 200
    assert r_dup.json()["deduplicated"] is True
    assert r_dup.json()["message"]["id"] == c_msg["id"]
    assert len(db.license_messages) == 1

    # Admin Inbox lists thread as unread with exact license metadata
    owner_hdr = _login_session(client, "test-owner", "OwnerSecret!2026")
    r_inbox = client.get("/api/v1/admin/messages/inbox?filter=unread", headers=owner_hdr)
    assert r_inbox.status_code == 200
    inbox = r_inbox.json()
    assert inbox["total_unread"] == 1
    assert len(inbox["conversations"]) == 1
    conv_item = inbox["conversations"][0]
    assert conv_item["license_key"] == "LIC-ALPHA-001"
    assert conv_item["label"] == "Alpha Main Gate"
    assert conv_item["note"] == "Alpha Gate Customer"
    assert conv_item["device_id"] == "dev-alpha-1111111111111111"
    assert conv_item["unread_count"] == 1

    # Opening conversation marks incoming client message received -> read with read_at
    r_open = client.get("/api/v1/admin/messages/conversation/LIC-ALPHA-001", headers=owner_hdr)
    assert r_open.status_code == 200
    opened = r_open.json()
    assert opened["marked_read_ids"] == [c_msg["id"]]
    assert opened["messages"][0]["status"] == "read"
    assert opened["messages"][0]["read_at"] is not None
    assert opened["messages"][0]["read_by"] == "test-owner"

    # 2. Admin -> Specific Client (queued, NOT delivered yet!)
    r_adm_send = client.post(
        "/api/v1/admin/messages/send",
        json={
            "license_key": "LIC-ALPHA-001",
            "body": f"Copy that, checking now ({secret_admin_phrase})",
            "idempotency_key": "adm-idem-1",
        },
        headers=owner_hdr,
    )
    assert r_adm_send.status_code == 200, r_adm_send.text
    a_msg = r_adm_send.json()["message"]
    assert a_msg["sender_type"] == "admin"
    assert a_msg["status"] == "queued"
    assert a_msg["target_device_id"] == "dev-alpha-1111111111111111"
    assert a_msg["delivered_at"] is None
    assert a_msg["read_at"] is None

    # Client sync fetches queued message WITHOUT prematurely marking it delivered
    r_sync = client.post(
        "/api/v1/messages/sync",
        json={"license_key": "LIC-ALPHA-001", "device_id": "dev-alpha-1111111111111111"},
    )
    assert r_sync.status_code == 200
    sync_body = r_sync.json()
    assert sync_body["pending_delivery_ids"] == [a_msg["id"]]
    assert sync_body["unread_count"] == 1
    synced_admin_msg = next(m for m in sync_body["messages"] if m["id"] == a_msg["id"])
    assert synced_admin_msg["status"] == "queued"
    assert synced_admin_msg["delivered_at"] is None

    # Client explicitly acknowledges delivery -> queued -> delivered + delivered_at
    r_ack = client.post(
        "/api/v1/messages/ack-delivered",
        json={
            "license_key": "LIC-ALPHA-001",
            "device_id": "dev-alpha-1111111111111111",
            "message_ids": [a_msg["id"]],
        },
    )
    assert r_ack.status_code == 200
    ack_data = r_ack.json()
    assert ack_data["acknowledged_ids"] == [a_msg["id"]]
    assert ack_data["delivered_at"] is not None
    assert ack_data["messages"][0]["status"] == "delivered"
    assert ack_data["messages"][0]["delivered_at"] is not None
    assert ack_data["messages"][0]["read_at"] is None

    # Client opens message -> delivered -> read + read_at
    r_read = client.post(
        "/api/v1/messages/mark-read",
        json={
            "license_key": "LIC-ALPHA-001",
            "device_id": "dev-alpha-1111111111111111",
            "message_ids": [a_msg["id"]],
        },
    )
    assert r_read.status_code == 200
    read_data = r_read.json()
    assert read_data["read_ids"] == [a_msg["id"]]
    assert read_data["read_at"] is not None
    assert read_data["messages"][0]["status"] == "read"
    assert read_data["messages"][0]["delivered_at"] is not None
    assert read_data["messages"][0]["read_at"] is not None

    # 3. Client replies in same thread
    r_reply = client.post(
        "/api/v1/messages/send",
        json={
            "license_key": "LIC-ALPHA-001",
            "device_id": "dev-alpha-1111111111111111",
            "body": "Thanks, camera stream recovered!",
            "idempotency_key": "cli-idem-2",
        },
    )
    assert r_reply.status_code == 200

    # Verify audit trail captured send/read/delivery/client_read WITHOUT leaking private bodies
    audit_actions = [a["action"] for a in db.audit_log]
    assert "messages_read" in audit_actions
    assert "message_sent" in audit_actions
    assert "messages_delivered" in audit_actions
    assert "messages_client_read" in audit_actions
    for a in db.audit_log:
        assert secret_client_phrase not in (a.get("note") or "")
        assert secret_admin_phrase not in (a.get("note") or "")

    # Verify application logs NEVER dump private message contents
    full_log_text = "\n".join(rec.getMessage() for rec in caplog.records)
    assert secret_client_phrase not in full_log_text
    assert secret_admin_phrase not in full_log_text


def test_04_07_multi_license_isolation_and_authorization_rejection(msg_env):
    _, _, client = msg_env

    # Admin sends distinct private messages to Alpha and Beta
    r_a = client.post(
        "/api/v1/admin/messages/send",
        json={"license_key": "LIC-ALPHA-001", "body": "SECRET_FOR_ALPHA_ONLY"},
        headers=ADMIN_HDR,
    )
    r_b = client.post(
        "/api/v1/admin/messages/send",
        json={"license_key": "LIC-BETA-002", "body": "SECRET_FOR_BETA_ONLY"},
        headers=ADMIN_HDR,
    )
    assert r_a.status_code == 200 and r_b.status_code == 200
    alpha_msg_id = r_a.json()["message"]["id"]

    # Alpha only sees Alpha's messages; Beta only sees Beta's messages
    sync_a = client.post(
        "/api/v1/messages/sync",
        json={"license_key": "LIC-ALPHA-001", "device_id": "dev-alpha-1111111111111111"},
    ).json()
    sync_b = client.post(
        "/api/v1/messages/sync",
        json={"license_key": "LIC-BETA-002", "device_id": "dev-beta-2222222222222222"},
    ).json()
    assert [m["body"] for m in sync_a["messages"]] == ["SECRET_FOR_ALPHA_ONLY"]
    assert [m["body"] for m in sync_b["messages"]] == ["SECRET_FOR_BETA_ONLY"]

    # Beta attempts to read Alpha's conversation via path param -> 403
    r_forbid_path = client.get(
        "/api/v1/messages/conversation/LIC-ALPHA-001",
        headers={
            "X-License-Key": "LIC-BETA-002",
            "X-Device-Id": "dev-beta-2222222222222222",
        },
    )
    assert r_forbid_path.status_code == 403

    # Beta attempts to spoof target_license_key in sync body -> 403
    r_forbid_target = client.post(
        "/api/v1/messages/sync",
        json={
            "license_key": "LIC-BETA-002",
            "device_id": "dev-beta-2222222222222222",
            "target_license_key": "LIC-ALPHA-001",
        },
    )
    assert r_forbid_target.status_code == 403

    # Beta attempts conflicting header vs body license_key -> 403
    r_conflict = client.post(
        "/api/v1/messages/send",
        headers={"X-License-Key": "LIC-BETA-002", "X-Device-Id": "dev-beta-2222222222222222"},
        json={"license_key": "LIC-ALPHA-001", "device_id": "dev-beta-2222222222222222", "body": "Spoof attempt"},
    )
    assert r_conflict.status_code == 403

    # Beta attempts to acknowledge Alpha's message_id -> ignored (0 acknowledged, Alpha untouched)
    r_cross_ack = client.post(
        "/api/v1/messages/ack-delivered",
        json={
            "license_key": "LIC-BETA-002",
            "device_id": "dev-beta-2222222222222222",
            "message_ids": [alpha_msg_id],
        },
    )
    assert r_cross_ack.status_code == 200
    assert r_cross_ack.json()["acknowledged_ids"] == []
    assert r_cross_ack.json()["messages"] == []

    # Wrong device_id for Alpha -> 403
    r_wrong_dev = client.post(
        "/api/v1/messages/sync",
        json={"license_key": "LIC-ALPHA-001", "device_id": "attacker-device-99999999"},
    )
    assert r_wrong_dev.status_code == 403

    # Unknown license key -> 401
    r_unknown = client.post(
        "/api/v1/messages/sync",
        json={"license_key": "NO-SUCH-KEY", "device_id": "dev-alpha-1111111111111111"},
    )
    assert r_unknown.status_code == 401

    # Unbound license -> 403 for client, 409 for admin send
    r_unbound_cli = client.post(
        "/api/v1/messages/sync",
        json={"license_key": "LIC-UNBOUND-003", "device_id": "any-device-123456"},
    )
    assert r_unbound_cli.status_code == 403
    r_unbound_adm = client.post(
        "/api/v1/admin/messages/send",
        json={"license_key": "LIC-UNBOUND-003", "body": "Should fail while unbound"},
        headers=ADMIN_HDR,
    )
    assert r_unbound_adm.status_code == 409

    # Expired license -> 403 for client (honors existing licensing rules)
    r_exp = client.post(
        "/api/v1/messages/sync",
        json={"license_key": "LIC-EXPIRED-004", "device_id": "dev-expired-44444444444444"},
    )
    assert r_exp.status_code == 403

    # Broadcast wildcard prevented in individual messaging endpoint -> 400
    for bad_target in ("*", "all", "broadcast", "LIC-ALPHA-001,LIC-BETA-002"):
        r_bad = client.post(
            "/api/v1/admin/messages/send",
            json={"license_key": bad_target, "body": "Not allowed"},
            headers=ADMIN_HDR,
        )
        assert r_bad.status_code == 400

    # Unauthenticated admin inbox access -> 401
    assert client.get("/api/v1/admin/messages/inbox").status_code == 401
    assert client.post("/api/v1/admin/messages/send", json={"license_key": "LIC-ALPHA-001", "body": "x"}).status_code == 401


def test_08_device_unbind_transfer_retarget_and_revocation_lifecycle(msg_env):
    _, db, client = msg_env
    owner_hdr = _login_session(client, "test-owner", "OwnerSecret!2026")
    admin_hdr = _login_session(client, "support-admin", "SupportAdmin!2026")

    # Device A sends a message and admin queues a sensitive reply for Device A
    assert client.post(
        "/api/v1/messages/send",
        json={"license_key": "LIC-ALPHA-001", "device_id": "dev-alpha-1111111111111111", "body": "From Old PC A"},
    ).status_code == 200
    r_q = client.post(
        "/api/v1/admin/messages/send",
        json={"license_key": "LIC-ALPHA-001", "body": "Queued strictly for Old PC A"},
        headers=admin_hdr,
    )
    assert r_q.status_code == 200
    queued_id = r_q.json()["message"]["id"]

    # Owner unbinds Device A -> queued message automatically held as 'held_device_changed'
    r_unbind = client.post("/api/v1/admin/unbind-device?license_key=LIC-ALPHA-001", headers=owner_hdr)
    assert r_unbind.status_code == 200
    assert r_unbind.json()["held_message_count"] == 1

    # While unbound, Old PC A is blocked (403)
    assert client.post(
        "/api/v1/messages/sync",
        json={"license_key": "LIC-ALPHA-001", "device_id": "dev-alpha-1111111111111111"},
    ).status_code == 403

    # Replacement PC C activates the transferred license via standard /api/v1/validate
    r_val_c = client.post(
        "/api/v1/validate",
        json={"license_key": "LIC-ALPHA-001", "device_id": "dev-newpc-3333333333333333", "app_version": "2.1.0"},
    )
    assert r_val_c.status_code == 200 and r_val_c.json()["status"] == "active"

    # Replacement PC C syncs -> receives ZERO of Old PC A's messages or held queued messages!
    r_sync_c = client.post(
        "/api/v1/messages/sync",
        json={"license_key": "LIC-ALPHA-001", "device_id": "dev-newpc-3333333333333333"},
    )
    assert r_sync_c.status_code == 200
    assert r_sync_c.json()["messages"] == []

    # Non-owner admin CANNOT retarget held messages (403); SystemOwner CAN explicitly retarget!
    r_retarget_denied = client.post(
        f"/api/v1/admin/messages/{queued_id}/retarget",
        json={"action": "retarget"},
        headers=admin_hdr,
    )
    assert r_retarget_denied.status_code == 403

    r_retarget_ok = client.post(
        f"/api/v1/admin/messages/{queued_id}/retarget",
        json={"action": "retarget"},
        headers=owner_hdr,
    )
    assert r_retarget_ok.status_code == 200
    rt_msg = r_retarget_ok.json()["message"]
    assert rt_msg["status"] == "queued"
    assert rt_msg["target_device_id"] == "dev-newpc-3333333333333333"
    assert rt_msg["retargeted_from_device_id"] == "dev-alpha-1111111111111111"

    # Now Replacement PC C sees the explicitly retargeted message
    r_sync_c2 = client.post(
        "/api/v1/messages/sync",
        json={"license_key": "LIC-ALPHA-001", "device_id": "dev-newpc-3333333333333333"},
    )
    assert r_sync_c2.status_code == 200
    assert [m["id"] for m in r_sync_c2.json()["messages"]] == [queued_id]

    # Revoking the license immediately blocks both client sync/send (403) and admin send (409)
    assert client.post("/api/v1/admin/revoke?license_key=LIC-ALPHA-001", headers=owner_hdr).status_code == 200
    assert client.post(
        "/api/v1/messages/sync",
        json={"license_key": "LIC-ALPHA-001", "device_id": "dev-newpc-3333333333333333"},
    ).status_code == 403
    assert client.post(
        "/api/v1/admin/messages/send",
        json={"license_key": "LIC-ALPHA-001", "body": "Blocked after revoke"},
        headers=owner_hdr,
    ).status_code == 409


def test_validation_length_rate_limit_and_dashboard_xss_escaping(msg_env):
    _, _, client = msg_env

    # Empty / over-limit / null-byte payloads rejected
    assert client.post(
        "/api/v1/messages/send",
        json={"license_key": "LIC-ALPHA-001", "device_id": "dev-alpha-1111111111111111", "body": "   "},
    ).status_code == 400
    assert client.post(
        "/api/v1/messages/send",
        json={"license_key": "LIC-ALPHA-001", "device_id": "dev-alpha-1111111111111111", "body": "x" * 2001},
    ).status_code == 400
    assert client.post(
        "/api/v1/messages/send",
        json={"license_key": "LIC-ALPHA-001", "device_id": "dev-alpha-1111111111111111", "body": "bad\x00byte"},
    ).status_code == 400

    # Rate limit enforcement (20/min allowed, 21st rejected with 429)
    for i in range(srv.CLIENT_MESSAGE_RATE_LIMIT_MAX):
        r = client.post(
            "/api/v1/messages/send",
            json={"license_key": "LIC-BETA-002", "device_id": "dev-beta-2222222222222222", "body": f"msg {i}"},
        )
        assert r.status_code == 200
    r_over = client.post(
        "/api/v1/messages/send",
        json={"license_key": "LIC-BETA-002", "device_id": "dev-beta-2222222222222222", "body": "too fast"},
    )
    assert r_over.status_code == 429

    # Verify dashboard HTML uses escapeHtml() for all inbox fields (XSS protection)
    html_src = (srv.ADMIN_UI_DIR / "dashboard.html").read_text(encoding="utf-8")
    assert 'data-tab="inbox"' in html_src
    assert 'id="panel-inbox"' in html_src
    assert 'escapeHtml(m.body)' in html_src
    assert 'escapeHtml(senderPrefix + (c.last_message_preview || ""))' in html_src
