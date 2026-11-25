"""
Comprehensive test suite for ANPR License & Subscription Server (`license_server.py`)
Tests trial creation, VIVEK-ANPR-0001 180-day migration, plans & launch90 eligibility,
expired vs revoked precedence, base64 Postgres screenshot upload, 10-minute rate limit,
Telegram sendPhoto dispatch, and admin approve/reject atomic workflows.
"""

import base64
import importlib.util
import os
import re
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import psycopg2
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
        self.device_trials: dict[str, dict] = {}
        self.submissions: list[dict] = []
        self.sessions: dict[str, dict] = {}
        self.admin_users: list[dict] = []
        self.audit_log: list[dict] = []
        self.subscription_plans: dict[str, dict] = {}
        self.broadcast_messages: list[dict] = []
        self.broadcast_acks: set[tuple[int, str]] = set()
        self.system_settings: dict[str, dict] = {}
        self.contact_messages: list[dict] = []
        self.remote_credential_provisions: list[dict] = []
        self.device_rbac_accounts: dict[tuple[str, str], dict] = {}
        self.license_messages: list[dict] = []
        self._next_sub_id = 1
        self._next_admin_id = 1
        self._next_audit_id = 1
        self._next_broadcast_id = 1
        self._next_contact_id = 1
        self._next_prov_id = 1
        self._next_message_id = 1
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

        if norm.startswith(("CREATE TABLE", "ALTER TABLE", "CREATE INDEX", "CREATE UNIQUE INDEX")):
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

        if norm.startswith("UPDATE licenses SET activated_at = COALESCE(last_seen, NOW()) WHERE device_id IS NOT NULL"):
            for row in self.db.licenses.values():
                if row.get("device_id") and row.get("activated_at") is None:
                    row["activated_at"] = row.get("last_seen") or datetime.now(timezone.utc)
                    self.rowcount += 1
            return

        if norm.startswith("INSERT INTO device_trials") and "SELECT DISTINCT ON (device_id)" in norm:
            for row in self.db.licenses.values():
                dev = row.get("device_id")
                if dev and dev not in self.db.device_trials:
                    self.db.device_trials[dev] = {
                        "device_id": dev,
                        "first_license_key": row["license_key"],
                        "first_activated_at": row.get("activated_at") or row.get("last_seen") or datetime.now(timezone.utc),
                        "note": "Backfilled from existing bound license",
                    }
                    self.rowcount += 1
            return

        if norm.startswith("INSERT INTO device_trials"):
            dev, first_key, first_at, note = params
            if dev not in self.db.device_trials:
                self.db.device_trials[dev] = {
                    "device_id": dev,
                    "first_license_key": first_key,
                    "first_activated_at": first_at,
                    "note": note,
                }
                self._rows = [{"device_id": dev, "first_license_key": first_key}]
                self.rowcount = 1
            else:
                self._rows = []
                self.rowcount = 0
            return

        if norm.startswith("UPDATE device_trials SET first_license_key = %s WHERE device_id = %s"):
            new_key, dev = params
            if dev in self.db.device_trials:
                self.db.device_trials[dev]["first_license_key"] = new_key
                self.rowcount = 1
            return

        if norm.startswith("DELETE FROM device_trials WHERE device_id = %s"):
            if params[0] in self.db.device_trials:
                del self.db.device_trials[params[0]]
                self.rowcount = 1
            return

        if norm.startswith("SELECT") and "FROM device_trials WHERE device_id = %s" in norm:
            dt_row = self.db.device_trials.get(params[0])
            self._rows = [dict(dt_row)] if dt_row else []
            return

        if norm.startswith("SELECT") and "FROM device_trials ORDER BY first_activated_at DESC" in norm:
            limit = int(params[0]) if params else 100
            ordered = sorted(
                self.db.device_trials.values(),
                key=lambda r: (r["first_activated_at"], r["device_id"]),
                reverse=True,
            )
            self._rows = [dict(r) for r in ordered[:limit]]
            return

        if norm.startswith("DELETE FROM licenses WHERE license_key = %s"):
            key = params[0]
            if key in self.db.licenses:
                del self.db.licenses[key]
                self.rowcount = 1
            return

        if norm.startswith("UPDATE licenses SET label = %s WHERE license_key = %s"):
            new_label, key = params
            if key in self.db.licenses:
                self.db.licenses[key]["label"] = new_label
                self.rowcount = 1
            return

        if norm.startswith("SELECT") and "FROM licenses WHERE device_id IS NOT NULL ORDER BY" in norm:
            self._rows = [
                dict(self.db.licenses[k])
                for k in sorted(self.db.licenses)
                if self.db.licenses[k].get("device_id") is not None
            ]
            return

        if norm.startswith("SELECT") and "FROM licenses WHERE device_id = %s" in norm:
            dev = params[0]
            matches = [dict(r) for r in self.db.licenses.values() if r.get("device_id") == dev]
            matches.sort(
                key=lambda r: r.get("activated_at") or r.get("last_seen") or datetime.min.replace(tzinfo=timezone.utc),
                reverse=True,
            )
            self._rows = matches[:1]
            return

        if norm.startswith("SELECT") and "FROM licenses WHERE license_key = %s" in norm:
            row = self.db.licenses.get(params[0])
            self._rows = [dict(row)] if row else []
            return

        if norm.startswith("SELECT") and "FROM licenses ORDER BY" in norm:
            self._rows = [dict(self.db.licenses[k]) for k in sorted(self.db.licenses)]
            return

        if norm.startswith("INSERT INTO licenses"):
            label_val = None
            if "VALUES (%s, 'active', %s, 'trial', NULL, FALSE, NULL, %s, FALSE)" in norm:
                key, note, trial_days = params
                plan, exp, has_paid, allow_repeat = "trial", None, False, False
            elif len(params) == 8:
                key, note, label_val, plan, exp, has_paid, trial_days, allow_repeat = params
            elif len(params) == 7:
                key, note, plan, exp, has_paid, trial_days, allow_repeat = params
            else:
                key, note, plan, exp, has_paid = params
                trial_days, allow_repeat = 180, False
            if "ON CONFLICT (license_key) DO NOTHING" in norm and key in self.db.licenses:
                self._rows = []
                self.rowcount = 0
                return
            self.db.licenses[key] = {
                "license_key": key,
                "status": "active",
                "device_id": None,
                "app_version": None,
                "last_seen": None,
                "note": note,
                "label": label_val,
                "plan": plan,
                "expires_at": exp,
                "has_paid_renewal": has_paid,
                "activated_at": None,
                "trial_days": trial_days,
                "allow_repeat_trial": allow_repeat,
            }
            if "RETURNING license_key" in norm:
                self._rows = [{"license_key": key}]
            self.rowcount = 1
            return

        if norm.startswith("UPDATE licenses SET app_version = %s, last_seen = %s WHERE license_key = %s"):
            ver, seen, key = params
            if key in self.db.licenses:
                self.db.licenses[key].update(app_version=ver, last_seen=seen)
                self.rowcount = 1
            return

        if norm.startswith("UPDATE licenses SET device_id = NULL WHERE license_key = %s"):
            key = params[0]
            if key in self.db.licenses:
                self.db.licenses[key]["device_id"] = None
                self.rowcount = 1
            return

        if norm.startswith("UPDATE licenses SET device_id = %s, app_version = %s, last_seen = %s, activated_at = %s, expires_at = %s"):
            dev, ver, seen, act_at, exp, key = params
            if key in self.db.licenses:
                self.db.licenses[key].update(
                    device_id=dev,
                    app_version=ver,
                    last_seen=seen,
                    activated_at=act_at,
                    expires_at=exp,
                )
                self.rowcount = 1
            return

        if norm.startswith("UPDATE licenses SET device_id = %s"):
            dev, ver, seen, key = params
            if key in self.db.licenses:
                self.db.licenses[key].update(device_id=dev, app_version=ver, last_seen=seen)
                self.rowcount = 1
            return

        if norm.startswith("UPDATE licenses SET status = 'active', plan = %s, expires_at = %s, has_paid_renewal = %s"):
            plan, exp, has_paid, key = params
            if key in self.db.licenses:
                self.db.licenses[key].update(
                    status="active", plan=plan, expires_at=exp, has_paid_renewal=bool(has_paid)
                )
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

        if norm.startswith("INSERT INTO license_audit_log"):
            (
                lic_key, action, actor,
                prev_plan, new_plan,
                prev_exp, new_exp,
                prev_paid, new_paid,
                note, created_at,
            ) = params
            self.db.audit_log.append({
                "id": self.db._next_audit_id,
                "license_key": lic_key,
                "action": action,
                "actor": actor,
                "previous_plan": prev_plan,
                "new_plan": new_plan,
                "previous_expires_at": prev_exp,
                "new_expires_at": new_exp,
                "previous_has_paid_renewal": prev_paid,
                "new_has_paid_renewal": new_paid,
                "note": note,
                "created_at": created_at,
            })
            self.db._next_audit_id += 1
            self.rowcount = 1
            return

        if "FROM license_audit_log ORDER BY created_at DESC" in norm:
            limit = int(params[0]) if params else 50
            ordered = sorted(self.db.audit_log, key=lambda r: (r["created_at"], r["id"]), reverse=True)
            self._rows = [dict(r) for r in ordered[:limit]]
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
            if len(params) == 8:
                key, dev, plan, b64, mime, price_inr, days, submitted_at = params
            else:
                key, dev, plan, b64, mime, submitted_at = params
                price_inr, days = None, None
            sub = {
                "id": self.db._next_sub_id,
                "license_key": key,
                "device_id": dev,
                "claimed_plan": plan,
                "image_data": b64,
                "content_type": mime,
                "price_inr": price_inr,
                "days": days,
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

        if norm == "SELECT COUNT(*) AS cnt FROM admin_users":
            self._rows = [{"cnt": len(self.db.admin_users)}]
            return

        if norm.startswith("INSERT INTO admin_users"):
            username, pw_hash, email, created_at, updated_at = params
            row = {
                "id": self.db._next_admin_id,
                "username": username,
                "password_hash": pw_hash,
                "email": email,
                "role": "owner",
                "created_at": created_at,
                "updated_at": updated_at,
            }
            self.db._next_admin_id += 1
            self.db.admin_users.append(row)
            self.rowcount = 1
            return

        if "FROM admin_users WHERE LOWER(username) = LOWER(%s) AND id != %s" in norm:
            uname, exclude_id = params
            match = next(
                (u for u in self.db.admin_users if u["username"].lower() == str(uname).lower() and u["id"] != int(exclude_id)),
                None,
            )
            self._rows = [dict(match)] if match else []
            return

        if "FROM admin_users WHERE LOWER(username) = LOWER(%s)" in norm:
            uname = params[0]
            match = next((u for u in self.db.admin_users if u["username"].lower() == str(uname).lower()), None)
            self._rows = [dict(match)] if match else []
            return

        if "FROM admin_users WHERE id = %s" in norm:
            uid = int(params[0])
            match = next((u for u in self.db.admin_users if u["id"] == uid), None)
            self._rows = [dict(match)] if match else []
            return

        if "FROM admin_users ORDER BY id ASC" in norm:
            self._rows = [dict(u) for u in sorted(self.db.admin_users, key=lambda x: x["id"])]
            return

        if "FROM admin_users ORDER BY id LIMIT 3" in norm:
            self._rows = [
                {
                    "id": u["id"],
                    "username": u["username"],
                    "role": u["role"],
                    "hp": (u.get("password_hash") or "")[:12],
                    "hl": len(u.get("password_hash") or ""),
                    "password_hash": u.get("password_hash") or "",
                }
                for u in sorted(self.db.admin_users, key=lambda x: x["id"])[:3]
            ]
            return

        if norm.startswith("UPDATE admin_users SET username = %s"):
            new_u, new_e, new_h, upd_at, uid = params
            match = next((u for u in self.db.admin_users if u["id"] == int(uid)), None)
            if match:
                match["username"] = new_u
                match["email"] = new_e
                match["password_hash"] = new_h
                match["updated_at"] = upd_at
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
            if len(params) == 6:
                jti, user_id, username, role, created_at, expires_at = params
            else:
                jti, username, created_at, expires_at = params
                user_id, role = None, "owner"
            self.db.sessions[jti] = {
                "jti": jti,
                "user_id": user_id,
                "username": username,
                "role": role,
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

        if norm.startswith("UPDATE admin_sessions SET revoked_at = %s WHERE user_id = %s"):
            revoked_at, uid = params
            count = 0
            for sess in self.db.sessions.values():
                if sess.get("user_id") == int(uid) and sess.get("revoked_at") is None:
                    sess["revoked_at"] = revoked_at
                    count += 1
            self.rowcount = count
            return

        if norm.startswith("UPDATE admin_sessions SET revoked_at = %s WHERE jti = %s"):
            revoked_at, jti = params
            sess = self.db.sessions.get(jti)
            if sess and sess.get("revoked_at") is None:
                sess["revoked_at"] = revoked_at
                self.rowcount = 1
            return

        if norm == "SELECT COUNT(*) AS cnt FROM subscription_plans":
            self._rows = [{"cnt": len(self.db.subscription_plans)}]
            return

        if norm.startswith("INSERT INTO subscription_plans"):
            pk, label, days, price_inr, active, sort_order, updated_at = params
            if pk not in self.db.subscription_plans:
                self.db.subscription_plans[pk] = {
                    "plan_key": pk,
                    "label": label,
                    "days": int(days),
                    "price_inr": int(price_inr),
                    "active": bool(active),
                    "sort_order": int(sort_order),
                    "updated_at": updated_at,
                }
                self.rowcount = 1
            return

        if "FROM subscription_plans WHERE active = TRUE ORDER BY" in norm:
            rows = [dict(p) for p in self.db.subscription_plans.values() if p.get("active", True)]
            rows.sort(key=lambda p: (int(p.get("sort_order", 100)), p["plan_key"]))
            self._rows = rows
            return

        if "FROM subscription_plans ORDER BY" in norm:
            rows = [dict(p) for p in self.db.subscription_plans.values()]
            rows.sort(key=lambda p: (int(p.get("sort_order", 100)), p["plan_key"]))
            self._rows = rows
            return

        if "FROM subscription_plans WHERE plan_key = %s" in norm:
            p = self.db.subscription_plans.get(params[0])
            self._rows = [dict(p)] if p else []
            return

        if norm.startswith("UPDATE subscription_plans SET label = %s"):
            new_label, new_days, new_price, new_active, upd_at, pk = params
            if pk in self.db.subscription_plans:
                self.db.subscription_plans[pk].update(
                    label=new_label,
                    days=int(new_days),
                    price_inr=int(new_price),
                    active=bool(new_active),
                    updated_at=upd_at,
                )
                self.rowcount = 1
            return

        if "FROM broadcast_messages b LEFT JOIN broadcast_acknowledgments a ON a.broadcast_id = b.id AND a.device_id = %s" in norm:
            dev_id = params[0]
            rows = [
                dict(b)
                for b in self.db.broadcast_messages
                if b.get("active", False) and (b["id"], dev_id) not in self.db.broadcast_acks
            ]
            rows.sort(key=lambda b: (b["created_at"], b["id"]))
            self._rows = rows
            return

        if "FROM broadcast_messages b LEFT JOIN broadcast_acknowledgments a ON a.broadcast_id = b.id GROUP BY b.id" in norm:
            rows = []
            for b in self.db.broadcast_messages:
                r = dict(b)
                r["ack_count"] = sum(1 for (bid, _d) in self.db.broadcast_acks if bid == b["id"])
                rows.append(r)
            rows.sort(key=lambda b: (b["created_at"], b["id"]), reverse=True)
            self._rows = rows
            return

        if norm.startswith("INSERT INTO broadcast_messages"):
            msg, tone, created_at, created_by = params
            row = {
                "id": self.db._next_broadcast_id,
                "message": msg,
                "tone": tone,
                "created_at": created_at,
                "active": True,
                "created_by": created_by,
            }
            self.db._next_broadcast_id += 1
            self.db.broadcast_messages.append(row)
            self._rows = [dict(row)]
            self.rowcount = 1
            return

        if norm.startswith("UPDATE broadcast_messages SET active = FALSE WHERE id = %s"):
            bid = int(params[0])
            for b in self.db.broadcast_messages:
                if b["id"] == bid:
                    b["active"] = False
                    self.rowcount = 1
            return

        if norm.startswith("UPDATE broadcast_messages SET active = TRUE WHERE id = %s"):
            bid = int(params[0])
            for b in self.db.broadcast_messages:
                if b["id"] == bid:
                    b["active"] = True
                    self.rowcount = 1
            return

        if "SELECT id FROM broadcast_messages WHERE id = %s" in norm:
            bid = int(params[0])
            m = next((b for b in self.db.broadcast_messages if b["id"] == bid), None)
            self._rows = [{"id": m["id"]}] if m else []
            return

        if norm.startswith("INSERT INTO broadcast_acknowledgments"):
            bid, dev_id, _acked_at = params
            self.db.broadcast_acks.add((int(bid), str(dev_id)))
            self.rowcount = 1
            return

        if norm.startswith("INSERT INTO system_settings"):
            if "ON CONFLICT (key) DO UPDATE" in norm:
                val, upd_at, upd_by = params
                self.db.system_settings["trial_days"] = {
                    "key": "trial_days",
                    "value": str(val),
                    "updated_at": upd_at,
                    "updated_by": upd_by,
                }
                self.rowcount = 1
            else:
                val, upd_at = params
                if "trial_days" not in self.db.system_settings:
                    self.db.system_settings["trial_days"] = {
                        "key": "trial_days",
                        "value": str(val),
                        "updated_at": upd_at,
                        "updated_by": "system",
                    }
                    self.rowcount = 1
            return

        if norm == "SELECT value FROM system_settings WHERE key = 'trial_days'":
            row = self.db.system_settings.get("trial_days")
            self._rows = [{"value": row["value"]}] if row else []
            return

        if "FROM system_settings ORDER BY key ASC" in norm:
            rows = [dict(self.db.system_settings[k]) for k in sorted(self.db.system_settings)]
            self._rows = rows
            return

        if "FROM contact_messages WHERE device_id = %s ORDER BY received_at DESC LIMIT 1" in norm:
            matches = [m for m in self.db.contact_messages if m["device_id"] == params[0]]
            matches.sort(key=lambda m: (m["received_at"], m["id"]), reverse=True)
            self._rows = [{"received_at": matches[0]["received_at"]}] if matches else []
            return

        if norm.startswith("INSERT INTO contact_messages"):
            lic_key, dev_id, msg_text, client_ts, received_at = params
            row = {
                "id": self.db._next_contact_id,
                "license_key": lic_key,
                "device_id": dev_id,
                "message": msg_text,
                "client_timestamp": client_ts,
                "received_at": received_at,
                "telegram_notified": False,
            }
            self.db._next_contact_id += 1
            self.db.contact_messages.append(row)
            self._rows = [{"id": row["id"], "received_at": row["received_at"]}]
            self.rowcount = 1
            return

        if norm.startswith("UPDATE contact_messages SET telegram_notified = TRUE WHERE id = %s"):
            mid = int(params[0])
            for m in self.db.contact_messages:
                if m["id"] == mid:
                    m["telegram_notified"] = True
                    self.rowcount = 1
            return

        if "FROM contact_messages ORDER BY received_at DESC" in norm:
            limit = int(params[0]) if params else 50
            ordered = sorted(self.db.contact_messages, key=lambda m: (m["received_at"], m["id"]), reverse=True)
            self._rows = [dict(m) for m in ordered[:limit]]
            return

        if "FROM remote_credential_provisions WHERE device_id = %s AND consumed_at IS NULL" in norm:
            dev = params[0]
            matches = [
                dict(p)
                for p in self.db.remote_credential_provisions
                if p["device_id"] == dev and p.get("consumed_at") is None
            ]
            matches.sort(key=lambda p: (p["created_at"], p["id"]))
            self._rows = matches
            return

        if "FROM remote_credential_provisions WHERE id = %s AND device_id = %s" in norm:
            pid, dev = int(params[0]), params[1]
            match = next(
                (p for p in self.db.remote_credential_provisions if p["id"] == pid and p["device_id"] == dev),
                None,
            )
            self._rows = [dict(match)] if match else []
            return

        if "FROM remote_credential_provisions WHERE device_id = %s ORDER BY created_at DESC" in norm:
            dev, limit = params[0], int(params[1])
            matches = [dict(p) for p in self.db.remote_credential_provisions if p["device_id"] == dev]
            matches.sort(key=lambda p: (p["created_at"], p["id"]), reverse=True)
            self._rows = matches[:limit]
            return

        if "FROM remote_credential_provisions ORDER BY created_at DESC" in norm:
            limit = int(params[0]) if params else 100
            ordered = sorted(
                self.db.remote_credential_provisions,
                key=lambda p: (p["created_at"], p["id"]),
                reverse=True,
            )
            self._rows = [dict(p) for p in ordered[:limit]]
            return

        if norm.startswith("INSERT INTO remote_credential_provisions"):
            if len(params) == 8:
                dev_id, uname, email, pw_hash, role, must_change, created_at, created_by = params
            else:
                dev_id, uname, email, pw_hash, role, created_at, created_by = params
                must_change = True
            row = {
                "id": self.db._next_prov_id,
                "device_id": dev_id,
                "username": uname,
                "email": email,
                "password_hash": pw_hash,
                "role": role,
                "must_change_password": bool(must_change),
                "created_at": created_at,
                "consumed_at": None,
                "created_by": created_by,
            }
            self.db._next_prov_id += 1
            self.db.remote_credential_provisions.append(row)
            self._rows = [{"id": row["id"], "created_at": row["created_at"]}]
            self.rowcount = 1
            return

        if norm.startswith("UPDATE remote_credential_provisions SET consumed_at = %s WHERE id = %s AND device_id = %s"):
            cons_at, pid, dev_id = params
            for p in self.db.remote_credential_provisions:
                if p["id"] == int(pid) and p["device_id"] == dev_id and p.get("consumed_at") is None:
                    p["consumed_at"] = cons_at
                    self.rowcount = 1
            return

        if norm.startswith("DELETE FROM device_rbac_accounts WHERE device_id = %s"):
            dev_id = params[0]
            to_del = [k for k in self.db.device_rbac_accounts if k[0] == dev_id]
            for k in to_del:
                del self.db.device_rbac_accounts[k]
            self.rowcount = len(to_del)
            return

        if norm.startswith("INSERT INTO device_rbac_accounts"):
            if len(params) == 7:
                dev_id, uname, email, role, is_active, must_change, synced_at = params
            else:
                dev_id, uname, email, role, must_change, synced_at = params
                is_active = True
            self.db.device_rbac_accounts[(dev_id, uname)] = {
                "device_id": dev_id,
                "username": uname,
                "email": email,
                "role": role,
                "is_active": bool(is_active),
                "must_change_password": bool(must_change),
                "last_synced_at": synced_at,
            }
            self.rowcount = 1
            return

        if "FROM device_rbac_accounts ORDER BY device_id ASC, username ASC" in norm:
            ordered = sorted(self.db.device_rbac_accounts.values(), key=lambda r: (r["device_id"], r["username"]))
            self._rows = [dict(r) for r in ordered]
            return

        if norm.startswith("UPDATE license_messages SET status = 'held_device_changed'"):
            key, prev_dev = params
            for m in self.db.license_messages:
                if (
                    m["license_key"] == key
                    and m["sender_type"] == "admin"
                    and m["status"] == "queued"
                    and (m.get("target_device_id") is None or m.get("target_device_id") == prev_dev)
                ):
                    m["status"] = "held_device_changed"
                    self.rowcount += 1
            return

        if norm.startswith("INSERT INTO license_messages"):
            if "'client'" in norm:
                lic_key, sender_id, target_dev, body_text, idem_key, created_at = params
                sender_type, status = "client", "received"
            else:
                lic_key, sender_id, target_dev, body_text, idem_key, created_at = params
                sender_type, status = "admin", "queued"
            row = {
                "id": self.db._next_message_id,
                "license_key": lic_key,
                "sender_type": sender_type,
                "sender_identity": sender_id,
                "target_device_id": target_dev,
                "body": body_text,
                "status": status,
                "idempotency_key": idem_key,
                "created_at": created_at,
                "delivered_at": None,
                "read_at": None,
                "read_by": None,
                "retargeted_from_device_id": None,
                "retargeted_by": None,
                "retargeted_at": None,
            }
            self.db._next_message_id += 1
            self.db.license_messages.append(row)
            self._rows = [dict(row)]
            self.rowcount = 1
            return

        if "FROM license_messages WHERE license_key = %s AND sender_type = 'client' AND idempotency_key = %s" in norm:
            key, idem = params
            m = next((r for r in self.db.license_messages if r["license_key"] == key and r["sender_type"] == "client" and r.get("idempotency_key") == idem), None)
            self._rows = [dict(m)] if m else []
            return

        if "FROM license_messages WHERE license_key = %s AND sender_type = 'admin' AND idempotency_key = %s" in norm:
            key, idem = params
            m = next((r for r in self.db.license_messages if r["license_key"] == key and r["sender_type"] == "admin" and r.get("idempotency_key") == idem), None)
            self._rows = [dict(m)] if m else []
            return

        if "FROM license_messages WHERE license_key = %s AND target_device_id = %s AND status NOT IN" in norm:
            if "AND id > %s" in norm:
                key, dev, since_id = params
            else:
                key, dev = params
                since_id = 0
            rows = [
                dict(m)
                for m in self.db.license_messages
                if m["license_key"] == key
                and m.get("target_device_id") == dev
                and m["status"] not in ("held_device_changed", "cancelled")
                and m["id"] > int(since_id)
            ]
            rows.sort(key=lambda r: (r["created_at"], r["id"]))
            self._rows = rows
            return

        if norm.startswith("UPDATE license_messages SET status = 'delivered'"):
            now_dt, key, dev, id_list = params
            id_set = {int(x) for x in id_list}
            out = []
            for m in self.db.license_messages:
                if m["license_key"] == key and m.get("target_device_id") == dev and m["sender_type"] == "admin" and m["status"] == "queued" and m["id"] in id_set:
                    m["status"] = "delivered"
                    m["delivered_at"] = now_dt
                    out.append(dict(m))
            self._rows = out
            self.rowcount = len(out)
            return

        if norm.startswith("UPDATE license_messages SET status = 'read', delivered_at = COALESCE"):
            now_dt, read_dt, reader, key, dev, id_list = params
            id_set = {int(x) for x in id_list}
            out = []
            for m in self.db.license_messages:
                if m["license_key"] == key and m.get("target_device_id") == dev and m["sender_type"] == "admin" and m["status"] in ("queued", "delivered") and m["id"] in id_set:
                    m["status"] = "read"
                    m["delivered_at"] = m["delivered_at"] or now_dt
                    m["read_at"] = read_dt
                    m["read_by"] = reader
                    out.append(dict(m))
            self._rows = out
            self.rowcount = len(out)
            return

        if "FROM license_messages WHERE license_key = %s AND target_device_id = %s AND sender_type = 'admin' AND id = ANY(%s)" in norm:
            key, dev, id_list = params
            id_set = {int(x) for x in id_list}
            rows = [dict(m) for m in self.db.license_messages if m["license_key"] == key and m.get("target_device_id") == dev and m["sender_type"] == "admin" and m["id"] in id_set]
            rows.sort(key=lambda r: (r["created_at"], r["id"]))
            self._rows = rows
            return

        if norm.startswith("UPDATE license_messages SET status = 'read', read_at = %s, read_by = %s"):
            now_dt, actor, key = params
            out = []
            for m in self.db.license_messages:
                if m["license_key"] == key and m["sender_type"] == "client" and m["status"] == "received":
                    m["status"] = "read"
                    m["read_at"] = now_dt
                    m["read_by"] = actor
                    out.append({"id": m["id"]})
            self._rows = out
            self.rowcount = len(out)
            return

        if "FROM license_messages WHERE license_key = %s ORDER BY created_at ASC, id ASC" in norm:
            key = params[0]
            rows = [dict(m) for m in self.db.license_messages if m["license_key"] == key]
            rows.sort(key=lambda r: (r["created_at"], r["id"]))
            self._rows = rows
            return

        if "FROM license_messages ORDER BY created_at ASC, id ASC" in norm:
            rows = [dict(m) for m in self.db.license_messages]
            rows.sort(key=lambda r: (r["created_at"], r["id"]))
            self._rows = rows
            return

        if "FROM license_messages WHERE id = %s" in norm:
            mid = int(params[0])
            m = next((r for r in self.db.license_messages if r["id"] == mid), None)
            self._rows = [dict(m)] if m else []
            return

        if norm.startswith("UPDATE license_messages SET status = 'cancelled'"):
            actor, now_dt, mid = params
            for m in self.db.license_messages:
                if m["id"] == int(mid):
                    m["status"] = "cancelled"
                    m["retargeted_by"] = actor
                    m["retargeted_at"] = now_dt
                    self._rows = [dict(m)]
                    self.rowcount = 1
            return

        if norm.startswith("UPDATE license_messages SET status = 'queued', retargeted_from_device_id = %s"):
            prev_dev, curr_dev, actor, now_dt, mid = params
            for m in self.db.license_messages:
                if m["id"] == int(mid):
                    m["status"] = "queued"
                    m["retargeted_from_device_id"] = prev_dev
                    m["target_device_id"] = curr_dev
                    m["retargeted_by"] = actor
                    m["retargeted_at"] = now_dt
                    self._rows = [dict(m)]
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
        "device_id": None,
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
    # 180-day free trial starts at FIRST successful device activation (NULL expires_at before activation)
    assert body["expires_at"] is None
    assert body["starts_on_activation"] is True
    assert body["trial_days"] == 180

    # First activation starts the 180-day countdown immediately
    v = client.post("/api/v1/validate", json={"license_key": "NEW-USER-001", "device_id": "abc", "app_version": "1.0.0"})
    assert v.status_code == 200
    vb = v.json()
    assert vb["status"] == "active"
    assert vb["plan"] == "trial"
    assert vb["expires_at"] is not None
    exp = datetime.fromisoformat(vb["expires_at"])
    assert 179 <= (exp - datetime.now(timezone.utc)).days <= 180


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
    client, db = env_client

    # Clear seeded admin_users to simulate fresh unconfigured deployment
    db.admin_users.clear()

    # Missing ADMIN_PASSWORD with empty admin_users -> 503
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    r_no_pw = client.post(
        "/api/v1/admin/login",
        json={"username": "test-admin-user", "password": "test-admin-password"},
    )
    assert r_no_pw.status_code == 503

    # Missing ADMIN_USERNAME with empty admin_users -> 503
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


def test_system_owner_admin_users_seeding_env_independence_and_credential_update(env_client, monkeypatch):
    """
    Verify SystemOwner tier backed by Postgres admin_users:
      1. Seeded once from ADMIN_USERNAME/ADMIN_PASSWORD with bcrypt hash & role='owner'
      2. Removing ADMIN_USERNAME/ADMIN_PASSWORD env vars still lets DB owner sign in
      3. Non-owner 'admin' account cannot access /api/v1/admin/account (403)
      4. Owner can update username, email, and password with current-password confirmation
      5. Wrong current password is rejected (403); old credentials rejected (401) after change
      6. Re-running init_db() preserves updated owner credentials (never re-seeds)
      7. New username + new password logs in cleanly and dashboard serves Manage Admin Account
    """
    client, db = env_client

    # 1. Verify initial seed created bcrypt-hashed owner row (never plaintext)
    assert len(db.admin_users) == 1
    seeded = db.admin_users[0]
    assert seeded["username"] == "test-admin-user"
    assert seeded["role"] == "owner"
    assert seeded["password_hash"].startswith("$2b$")
    assert seeded["password_hash"] != "test-admin-password"

    # 2. Remove ADMIN_USERNAME / ADMIN_PASSWORD from env -> DB-backed login still works!
    monkeypatch.delenv("ADMIN_USERNAME", raising=False)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)

    login1 = client.post(
        "/api/v1/admin/login",
        json={"username": "test-admin-user", "password": "test-admin-password"},
    )
    assert login1.status_code == 200
    body1 = login1.json()
    assert body1["role"] == "owner"
    old_token = body1["token"]

    sess = client.get("/api/v1/admin/session").json()
    assert sess["role"] == "owner"
    assert sess["is_owner"] is True

    # Dashboard HTML contains Manage Admin Account & account API endpoint
    dash = client.get("/admin")
    assert dash.status_code == 200
    assert "Manage Admin Account" in dash.text
    assert "/api/v1/admin/account" in dash.text

    # 3. GET /api/v1/admin/account returns profile without password_hash
    acct_r = client.get("/api/v1/admin/account")
    assert acct_r.status_code == 200
    acct_body = acct_r.json()
    assert acct_body["account"]["username"] == "test-admin-user"
    assert "password_hash" not in acct_body["account"]

    # 4. Wrong current password rejected (403)
    bad_upd = client.put(
        "/api/v1/admin/account",
        json={
            "current_password": "wrong-current-password",
            "username": "VivekanandOwner",
            "email": "vivekanandnaik333@gmail.com",
            "new_password": "BrandNewStrongPassword!99",
        },
    )
    assert bad_upd.status_code == 403

    # 5. Valid current password updates username, email, and password & rotates session
    good_upd = client.put(
        "/api/v1/admin/account",
        json={
            "current_password": "test-admin-password",
            "username": "VivekanandOwner",
            "email": "vivekanandnaik333@gmail.com",
            "new_password": "BrandNewStrongPassword!99",
        },
    )
    assert good_upd.status_code == 200
    upd_json = good_upd.json()
    assert upd_json["ok"] is True
    assert set(upd_json["changed_fields"]) == {"username", "email", "password"}
    assert upd_json["account"]["username"] == "VivekanandOwner"
    assert upd_json["account"]["email"] == "vivekanandnaik333@gmail.com"
    assert db.admin_users[0]["password_hash"].startswith("$2b$")
    assert "BrandNewStrongPassword!99" not in db.admin_users[0]["password_hash"]

    # Previous session token must be revoked after password change
    assert TestClient(srv.app).get(
        "/api/v1/admin/account", headers={"Authorization": f"Bearer {old_token}"}
    ).status_code == 401

    # Fresh session cookie/token returned by PUT works immediately
    assert client.get("/api/v1/admin/session").json()["username"] == "VivekanandOwner"

    # 6. Re-running init_db() even with old env vars restored must NOT overwrite updated owner!
    monkeypatch.setenv("ADMIN_USERNAME", "test-admin-user")
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-password")
    srv.init_db()
    assert len(db.admin_users) == 1
    assert db.admin_users[0]["username"] == "VivekanandOwner"

    # 7. Old credentials rejected (401); new credentials log in cleanly (200)
    fresh_client = TestClient(srv.app)
    assert fresh_client.post(
        "/api/v1/admin/login",
        json={"username": "test-admin-user", "password": "test-admin-password"},
    ).status_code == 401
    assert fresh_client.post(
        "/api/v1/admin/login",
        json={"username": "VivekanandOwner", "password": "test-admin-password"},
    ).status_code == 401

    new_login = fresh_client.post(
        "/api/v1/admin/login",
        json={"username": "VivekanandOwner", "password": "BrandNewStrongPassword!99"},
    )
    assert new_login.status_code == 200
    assert new_login.json()["username"] == "VivekanandOwner"
    assert new_login.json()["email"] == "vivekanandnaik333@gmail.com"
    assert new_login.json()["role"] == "owner"

    # 8. Non-owner 'admin' user can view dashboard/licenses but gets 403 on owner-only account endpoints
    now = datetime.now(timezone.utc)
    db.admin_users.append({
        "id": db._next_admin_id,
        "username": "secondary-admin",
        "password_hash": srv._hash_password("SecondaryPass!42"),
        "email": "ops@example.com",
        "role": "admin",
        "created_at": now,
        "updated_at": now,
    })
    db._next_admin_id += 1
    sec_client = TestClient(srv.app)
    sec_login = sec_client.post(
        "/api/v1/admin/login",
        json={"username": "secondary-admin", "password": "SecondaryPass!42"},
    )
    assert sec_login.status_code == 200
    assert sec_login.json()["role"] == "admin"
    assert sec_client.get("/api/v1/admin/session").json()["is_owner"] is False
    assert sec_client.get("/api/v1/admin/list").status_code == 200
    assert sec_client.get("/api/v1/admin/account").status_code == 403
    assert sec_client.put(
        "/api/v1/admin/account",
        json={"current_password": "SecondaryPass!42", "username": "hijack"},
    ).status_code == 403


def test_handover_reset_plan_vs_renew_audit_trail_and_vivek_180d_fresh_trial(env_client):
    """
    Verify SystemOwner handover reset (`POST /api/v1/admin/reset-plan`):
      1. Distinct from `/renew`: discards elapsed/remaining time and sets expires_at = now + plan_days
      2. Resetting to 'trial' restores `has_paid_renewal = False` so `launch90` becomes eligible again
      3. Resetting to a paid plan (e.g. 'quarterly') sets `has_paid_renewal = True` and expires_at = now + 90d
      4. Non-owner 'admin' session is rejected (403); SystemOwner session and X-Admin-Token succeed
      5. Audit trail (`/api/v1/admin/audit-log`) distinctly tags 'reset_plan' vs 'renew'
      6. VIVEK-ANPR-0001 reset to fresh 180-day trial reflects 180 days_remaining on Home `/api/v1/admin/summary`
      7. Dashboard HTML exposes clearly separated "Reset Plan (Handover)" button and confirmation modal
    """
    client, db = env_client

    # Sign in as SystemOwner
    login_r = client.post(
        "/api/v1/admin/login",
        json={"username": "test-admin-user", "password": "test-admin-password"},
    )
    assert login_r.status_code == 200

    # Simulate VIVEK-ANPR-0001 after dev/testing: partially elapsed paid renewal (200d left, has_paid_renewal=True)
    now_before = datetime.now(timezone.utc)
    db.licenses["VIVEK-ANPR-0001"]["plan"] = "annual"
    db.licenses["VIVEK-ANPR-0001"]["expires_at"] = now_before + timedelta(days=200)
    db.licenses["VIVEK-ANPR-0001"]["has_paid_renewal"] = True

    # Confirm launch90 is NOT eligible while has_paid_renewal=True
    p_before = client.get("/api/v1/plans", params={"license_key": "VIVEK-ANPR-0001"}).json()
    assert p_before["is_first_paid_renewal"] is False

    # 1. Execute handover reset to fresh 180-day trial
    r_reset = client.post(
        "/api/v1/admin/reset-plan",
        params={"license_key": "VIVEK-ANPR-0001", "plan": "trial"},
    )
    assert r_reset.status_code == 200
    body = r_reset.json()
    assert body["ok"] is True
    assert body["action"] == "reset_plan"
    assert body["plan"] == "trial"
    assert body["days_reset"] == 180
    assert body["has_paid_renewal"] is False

    # Verify expires_at is EXACTLY ~180 days from NOW (NOT 200 + 180 = 380 days!)
    new_exp = datetime.fromisoformat(body["expires_at"])
    delta_sec = (new_exp - datetime.now(timezone.utc)).total_seconds()
    assert abs(delta_sec - (180 * 86400)) < 15, f"Expected ~180d from now, got {delta_sec / 86400:.4f}d"

    # 2. launch90 eligibility is restored because has_paid_renewal was reset to False!
    p_after = client.get("/api/v1/plans", params={"license_key": "VIVEK-ANPR-0001"}).json()
    assert p_after["is_first_paid_renewal"] is True

    # 3. Home summary reflects fresh 180 days_remaining on Free Trial
    summary = client.get("/api/v1/admin/summary").json()
    assert summary["overall_state"] == "all_good"
    assert summary["primary_license"]["license_key"] == "VIVEK-ANPR-0001"
    assert summary["primary_license"]["plan"] == "trial"
    assert summary["primary_license"]["days_remaining"] == 180

    # 4. Compare with /renew: renewing adds +30d ON TOP of the 180d (-> ~210d) and sets has_paid_renewal=True
    r_renew = client.post(
        "/api/v1/admin/renew",
        params={"license_key": "VIVEK-ANPR-0001", "plan": "monthly"},
    )
    assert r_renew.status_code == 200
    renew_exp = datetime.fromisoformat(r_renew.json()["expires_at"])
    assert abs((renew_exp - datetime.now(timezone.utc)).total_seconds() - (210 * 86400)) < 15

    # 5. Resetting to paid plan ('quarterly') discards remaining 210d -> sets ~90d from now & has_paid_renewal=True
    r_reset_q = client.post(
        "/api/v1/admin/reset-plan",
        params={"license_key": "VIVEK-ANPR-0001", "plan": "quarterly"},
    )
    assert r_reset_q.status_code == 200
    assert r_reset_q.json()["has_paid_renewal"] is True
    q_exp = datetime.fromisoformat(r_reset_q.json()["expires_at"])
    assert abs((q_exp - datetime.now(timezone.utc)).total_seconds() - (90 * 86400)) < 15

    # 6. Audit log distinguishes 'reset_plan' from 'renew'
    audit = client.get("/api/v1/admin/audit-log").json()
    actions = [a["action"] for a in audit]
    assert actions == ["reset_plan", "renew", "reset_plan"]
    assert audit[0]["actor"] == "test-admin-user"
    assert audit[2]["new_has_paid_renewal"] is False

    # 7. Non-owner 'admin' user gets 403 on /api/v1/admin/reset-plan
    now = datetime.now(timezone.utc)
    db.admin_users.append({
        "id": db._next_admin_id,
        "username": "ops-admin",
        "password_hash": srv._hash_password("OpsPass!2026"),
        "email": "ops@example.com",
        "role": "admin",
        "created_at": now,
        "updated_at": now,
    })
    db._next_admin_id += 1
    ops_client = TestClient(srv.app)
    assert ops_client.post(
        "/api/v1/admin/login", json={"username": "ops-admin", "password": "OpsPass!2026"}
    ).status_code == 200
    assert ops_client.post(
        "/api/v1/admin/reset-plan", params={"license_key": "VIVEK-ANPR-0001", "plan": "trial"}
    ).status_code == 403

    # 8. Dashboard HTML contains clearly distinct Reset Plan (Handover) UI + confirmation modal
    dash_html = client.get("/admin").text
    assert "Reset Plan (Handover)" in dash_html
    assert "/api/v1/admin/reset-plan" in dash_html
    assert "reset-plan-modal" in dash_html
    assert "HANDOVER RESET" in dash_html


def test_import_time_init_db_runs_without_name_error(monkeypatch):
    """Importing license_server without SKIP_INIT_DB_ON_IMPORT runs init_db() + owner seeding cleanly."""
    db = FakePostgresDB()

    class _ImportFakeConn:
        def __init__(self):
            self.cursor_factory = None

        def cursor(self):
            return _FakeCursor(db)

        def commit(self):
            pass

        def rollback(self):
            pass

        def close(self):
            pass

    monkeypatch.delenv("SKIP_INIT_DB_ON_IMPORT", raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgresql://mock/test")
    monkeypatch.setenv("ADMIN_USERNAME", "test-admin-user")
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setattr(psycopg2, "connect", lambda *args, **kwargs: _ImportFakeConn())

    mod_name = "license_server_import_test"
    spec = importlib.util.spec_from_file_location(mod_name, Path(srv.__file__))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(mod_name, None)

    assert len(db.admin_users) == 1
    assert db.admin_users[0]["username"] == "test-admin-user"
    assert db.admin_users[0]["role"] == "owner"
    assert db.admin_users[0]["password_hash"].startswith("$2b$")


def test_dashboard_uses_flat_enterprise_styling_without_gradients_or_glows(env_client):
    """Ensure login and dashboard UI avoid gradients, glow keyframes, and text shadows."""
    client, _ = env_client

    login_html_r = client.get("/admin/login")
    assert login_html_r.status_code == 200

    login_r = client.post(
        "/api/v1/admin/login",
        json={"username": "test-admin-user", "password": "test-admin-password"},
    )
    assert login_r.status_code == 200

    dash_html_r = client.get("/admin")
    assert dash_html_r.status_code == 200

    disallowed_styles = [
        "radial-gradient",
        "linear-gradient",
        "homeGlowBreath",
        "homeAmbientShift",
        "text-shadow",
    ]
    for body in (login_html_r.text, dash_html_r.text):
        for pattern in disallowed_styles:
            assert pattern not in body, f"Disallowed template style found: {pattern}"


def test_broadcast_notifications_owner_only_ack_and_deactivate(env_client):
    client, db = env_client
    headers_owner = {"X-Admin-Token": "test-admin-secret"}

    # Create a non-owner admin user and verify broadcast management is strictly SystemOwner-only
    now = datetime.now(timezone.utc)
    db.admin_users.append(
        {
            "id": 99,
            "username": "subadmin",
            "password_hash": srv._hash_password("SubAdminPass!99"),
            "email": "sub@example.com",
            "role": "admin",
            "created_at": now,
            "updated_at": now,
        }
    )
    sub_login = client.post("/api/v1/admin/login", json={"username": "subadmin", "password": "SubAdminPass!99"})
    assert sub_login.status_code == 200
    sub_hdrs = {"Authorization": f"Bearer {sub_login.json()['token']}"}
    assert client.post("/api/v1/admin/broadcasts", json={"message": "Blocked"}, headers=sub_hdrs).status_code == 403
    client.cookies.clear()

    # Log in as SystemOwner (owner) and create broadcast #1
    owner_login = client.post("/api/v1/admin/login", json={"username": "test-admin-user", "password": "test-admin-password"})
    assert owner_login.status_code == 200
    b1 = client.post(
        "/api/v1/admin/broadcasts",
        json={"message": "Scheduled maintenance tonight at 11 PM IST", "tone": "notice"},
        headers=headers_owner,
    )
    assert b1.status_code == 200
    b1_id = b1.json()["id"]

    # Provision separate keys for Device B and Device C (1-key = 1-device locking)
    assert client.post("/api/v1/admin/create", json={"license_key": "LIC-DEV-B", "note": "PC B"}, headers=headers_owner).status_code == 200
    assert client.post("/api/v1/admin/create", json={"license_key": "LIC-DEV-C", "note": "PC C"}, headers=headers_owner).status_code == 200

    # Device A and Device B both receive broadcast #1 on /api/v1/validate
    v_a1 = client.post(
        "/api/v1/validate",
        json={"license_key": "VIVEK-ANPR-0001", "device_id": "device-A", "app_version": "1.0.0"},
    )
    assert v_a1.status_code == 200
    assert [b["id"] for b in v_a1.json()["broadcasts"]] == [b1_id]

    # Device A acknowledges broadcast #1 -> no longer returned to Device A, still returned to Device B
    ack_a = client.post(
        f"/api/v1/broadcasts/{b1_id}/ack",
        json={"license_key": "VIVEK-ANPR-0001", "device_id": "device-A"},
    )
    assert ack_a.status_code == 200

    v_a2 = client.post(
        "/api/v1/validate",
        json={"license_key": "VIVEK-ANPR-0001", "device_id": "device-A", "app_version": "1.0.0"},
    )
    assert v_a2.json()["broadcasts"] == []

    v_b1 = client.post(
        "/api/v1/validate",
        json={"license_key": "LIC-DEV-B", "device_id": "device-B", "app_version": "1.0.0"},
    )
    assert [b["id"] for b in v_b1.json()["broadcasts"]] == [b1_id]

    # Owner sends broadcast #2 -> Device A receives ONLY #2
    b2 = client.post(
        "/api/v1/admin/broadcasts",
        json={"message": "Price update effective next renewal", "tone": "warning"},
        headers=headers_owner,
    )
    b2_id = b2.json()["id"]
    v_a3 = client.post(
        "/api/v1/validate",
        json={"license_key": "VIVEK-ANPR-0001", "device_id": "device-A", "app_version": "1.0.0"},
    )
    assert [b["id"] for b in v_a3.json()["broadcasts"]] == [b2_id]

    # Owner deactivates #2 -> stops being sent to devices that haven't seen it
    deact = client.post(f"/api/v1/admin/broadcasts/{b2_id}/deactivate", headers=headers_owner)
    assert deact.status_code == 200 and deact.json()["active"] is False
    v_c = client.post(
        "/api/v1/validate",
        json={"license_key": "LIC-DEV-C", "device_id": "device-C", "app_version": "1.0.0"},
    )
    assert [b["id"] for b in v_c.json()["broadcasts"]] == [b1_id]

    # Dashboard list shows ack_count accurately
    all_b = client.get("/api/v1/admin/broadcasts", headers=headers_owner).json()
    b1_row = next(x for x in all_b if x["id"] == b1_id)
    b2_row = next(x for x in all_b if x["id"] == b2_id)
    assert b1_row["ack_count"] == 1 and b1_row["active"] is True
    assert b2_row["active"] is False


def test_live_editable_subscription_plans_and_launch90_eligibility(env_client):
    client, db = env_client
    headers_owner = {"X-Admin-Token": "test-admin-secret"}

    # Initial plans seeded from DEFAULT_PLANS (Quarterly = ₹300)
    p0 = client.get("/api/v1/plans?license_key=VIVEK-ANPR-0001")
    assert p0.status_code == 200
    assert p0.json()["plans"]["quarterly"]["price_inr"] == 300
    assert p0.json()["is_first_paid_renewal"] is True
    assert "launch90" in p0.json()["plans"]

    # Non-owner admin cannot edit plans
    now = datetime.now(timezone.utc)
    db.admin_users.append(
        {
            "id": 98,
            "username": "staffadmin",
            "password_hash": srv._hash_password("StaffPass!98"),
            "email": "staff@example.com",
            "role": "admin",
            "created_at": now,
            "updated_at": now,
        }
    )
    st_login = client.post("/api/v1/admin/login", json={"username": "staffadmin", "password": "StaffPass!98"})
    st_hdrs = {"Authorization": f"Bearer {st_login.json()['token']}"}
    assert client.put("/api/v1/admin/plans/quarterly", json={"price_inr": 450}, headers=st_hdrs).status_code == 403
    client.cookies.clear()

    # Log in as SystemOwner and edit Quarterly price live: ₹300 -> ₹375 + updated label
    owner_login = client.post("/api/v1/admin/login", json={"username": "test-admin-user", "password": "test-admin-password"})
    assert owner_login.status_code == 200
    upd = client.put(
        "/api/v1/admin/plans/quarterly",
        json={"label": "Quarterly Pro", "price_inr": 375},
        headers=headers_owner,
    )
    assert upd.status_code == 200
    assert upd.json()["price_inr"] == 375
    assert upd.json()["label"] == "Quarterly Pro"

    # Public /api/v1/plans reflects the change immediately
    p1 = client.get("/api/v1/plans?license_key=VIVEK-ANPR-0001").json()
    assert p1["plans"]["quarterly"]["price_inr"] == 375
    assert p1["plans"]["quarterly"]["label"] == "Quarterly Pro"

    # Owner adds a new plan ('semiannual', 180d, ₹550) & renews using it
    add = client.post(
        "/api/v1/admin/plans",
        json={"plan_key": "semiannual", "label": "Half-Yearly", "days": 180, "price_inr": 550, "active": True},
        headers=headers_owner,
    )
    assert add.status_code == 200
    p2 = client.get("/api/v1/plans?license_key=VIVEK-ANPR-0001").json()
    assert p2["plans"]["semiannual"] == {"days": 180, "price_inr": 550, "label": "Half-Yearly"}

    ren = client.post("/api/v1/admin/renew?license_key=VIVEK-ANPR-0001&plan=semiannual", headers=headers_owner)
    assert ren.status_code == 200 and ren.json()["days_added"] == 180

    # After paid renewal, launch90 first-renewal eligibility becomes False
    p3 = client.get("/api/v1/plans?license_key=VIVEK-ANPR-0001").json()
    assert p3["is_first_paid_renewal"] is False

    # Owner deactivates 'monthly' -> hidden from /api/v1/plans, still preserved in /api/v1/admin/plans
    deact = client.put("/api/v1/admin/plans/monthly", json={"active": False}, headers=headers_owner)
    assert deact.status_code == 200 and deact.json()["active"] is False
    p4 = client.get("/api/v1/plans").json()
    assert "monthly" not in p4["plans"]
    admin_plans = client.get("/api/v1/admin/plans", headers=headers_owner).json()
    monthly_row = next(x for x in admin_plans if x["plan_key"] == "monthly")
    assert monthly_row["active"] is False and monthly_row["price_inr"] == 150


def test_strict_single_device_binding_mismatch_and_owner_unbind_transfer(env_client):
    """
    Verify strict 1-key = 1-PC binding:
      1. First PC locks the unbound license key to its hardware device_id
      2. Second PC attempting to reuse the same key gets status='device_mismatch' (no overwrite!)
      3. Second PC is also rejected (403) from payment-screenshot and broadcast ack for that key
      4. Non-owner admin gets 403 on /api/v1/admin/unbind-device
      5. SystemOwner unbinds the device -> audit logged -> PC #2 can now bind & PC #1 gets device_mismatch
    """
    client, db = env_client
    headers_owner = {"X-Admin-Token": "test-admin-secret"}

    assert client.post(
        "/api/v1/admin/create",
        json={"license_key": "GATE-PC-001", "note": "Customer Gate 1"},
        headers=headers_owner,
    ).status_code == 200
    assert db.licenses["GATE-PC-001"]["device_id"] is None

    # 1. PC #1 activates and binds permanently
    v1 = client.post(
        "/api/v1/validate",
        json={"license_key": "GATE-PC-001", "device_id": "hw-pc-001", "app_version": "1.0.0"},
    )
    assert v1.status_code == 200 and v1.json()["status"] == "active"
    assert db.licenses["GATE-PC-001"]["device_id"] == "hw-pc-001"

    # 2. PC #2 tries copying the same key -> rejected with device_mismatch, device_id NOT overwritten!
    v2 = client.post(
        "/api/v1/validate",
        json={"license_key": "GATE-PC-001", "device_id": "hw-pc-002", "app_version": "1.0.0"},
    )
    assert v2.status_code == 200
    assert v2.json()["status"] == "device_mismatch"
    assert "another computer" in (v2.json()["message"] or "").lower()
    assert db.licenses["GATE-PC-001"]["device_id"] == "hw-pc-001"

    # PC #2 cannot submit payment screenshot for PC #1's bound key
    pay_r = client.post(
        "/api/v1/payment-screenshot",
        data={"license_key": "GATE-PC-001", "device_id": "hw-pc-002", "claimed_plan": "monthly"},
        files={"image": ("proof.png", PNG_1X1, "image/png")},
    )
    assert pay_r.status_code == 403

    # PC #1 continues working seamlessly
    v1_again = client.post(
        "/api/v1/validate",
        json={"license_key": "GATE-PC-001", "device_id": "hw-pc-001", "app_version": "1.0.0"},
    )
    assert v1_again.json()["status"] == "active"

    # 3. Non-owner admin cannot unbind a device
    db.admin_users.append(
        {
            "id": 98,
            "username": "subadmin2",
            "email": "sub2@example.com",
            "password_hash": srv._hash_password("SubPass!2026"),
            "role": "admin",
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }
    )
    sub_login = client.post("/api/v1/admin/login", json={"username": "subadmin2", "password": "SubPass!2026"})
    assert sub_login.status_code == 200
    assert client.post("/api/v1/admin/unbind-device", params={"license_key": "GATE-PC-001"}).status_code == 403

    # 4. SystemOwner unbinds device for hardware transfer -> PC #2 binds, PC #1 is now blocked
    client.cookies.clear()
    unbind_r = client.post(
        "/api/v1/admin/unbind-device",
        params={"license_key": "GATE-PC-001"},
        headers=headers_owner,
    )
    assert unbind_r.status_code == 200
    assert unbind_r.json()["previous_device_id"] == "hw-pc-001"
    assert unbind_r.json()["device_id"] is None
    assert db.licenses["GATE-PC-001"]["device_id"] is None
    assert any(a["action"] == "unbind_device" and a["license_key"] == "GATE-PC-001" for a in db.audit_log)

    v2_after = client.post(
        "/api/v1/validate",
        json={"license_key": "GATE-PC-001", "device_id": "hw-pc-002", "app_version": "1.0.0"},
    )
    assert v2_after.json()["status"] == "active"
    assert db.licenses["GATE-PC-001"]["device_id"] == "hw-pc-002"

    v1_after = client.post(
        "/api/v1/validate",
        json={"license_key": "GATE-PC-001", "device_id": "hw-pc-001", "app_version": "1.0.0"},
    )
    assert v1_after.json()["status"] == "device_mismatch"



def test_one_free_trial_per_device_owner_override_and_reinstall_persistence(env_client):
    """
    Verify Part D trial lifecycle:
      1. Trial countdown starts on first successful activation (NULL expires_at before activation).
      2. Reinstall (re-validating the same key on the same device) preserves original expires_at.
      3. Creating another trial key does NOT grant a second trial to the same device (`trial_already_used`).
      4. Owner exception (`allow_repeat_trial=True` or `/api/v1/admin/device-trials/override`) works cleanly.
    """
    client, db = env_client

    c1 = client.post("/api/v1/admin/create", json={"note": "Customer PC 1"}, headers=ADMIN_HDR)
    assert c1.status_code == 200
    k1 = c1.json()["license_key"]
    assert k1.startswith("ANPR-") and len(k1) == 24
    assert c1.json()["expires_at"] is None

    v1 = client.post("/api/v1/validate", json={"license_key": k1, "device_id": "pc-trial-01", "app_version": "1.0.0"})
    assert v1.status_code == 200 and v1.json()["status"] == "active"
    orig_exp = v1.json()["expires_at"]
    assert orig_exp is not None

    # Simulate uninstall/reinstall re-validating same key on same device -> exact original expiry preserved!
    v1_re = client.post("/api/v1/validate", json={"license_key": k1, "device_id": "pc-trial-01", "app_version": "1.0.0"})
    assert v1_re.json()["status"] == "active"
    assert v1_re.json()["expires_at"] == orig_exp

    # Issue second trial key -> MUST be rejected for pc-trial-01!
    c2 = client.post("/api/v1/admin/create", json={"note": "Second trial attempt"}, headers=ADMIN_HDR)
    k2 = c2.json()["license_key"]
    v2 = client.post("/api/v1/validate", json={"license_key": k2, "device_id": "pc-trial-01", "app_version": "1.0.0"})
    assert v2.status_code == 200
    assert v2.json()["status"] == "trial_already_used"
    assert db.licenses[k2]["device_id"] is None
    assert db.licenses[k2]["expires_at"] is None

    # Paid plan key on the same device is allowed even after trial was consumed
    c_paid = client.post("/api/v1/admin/create", json={"plan": "monthly", "note": "Paid"}, headers=ADMIN_HDR)
    k_paid = c_paid.json()["license_key"]
    v_paid = client.post("/api/v1/validate", json={"license_key": k_paid, "device_id": "pc-trial-01", "app_version": "1.0.0"})
    assert v_paid.json()["status"] == "active" and v_paid.json()["plan"] == "monthly"

    # Owner override clears device_trials record and allows k2 to activate cleanly
    ov = client.post(
        "/api/v1/admin/device-trials/override",
        json={"device_id": "pc-trial-01", "note": "Owner approved RMA replacement"},
        headers=ADMIN_HDR,
    )
    assert ov.status_code == 200 and ov.json()["cleared"] is True
    v2_after = client.post("/api/v1/validate", json={"license_key": k2, "device_id": "pc-trial-01", "app_version": "1.0.0"})
    assert v2_after.json()["status"] == "active"
    assert any(a["action"] == "trial_override" for a in db.audit_log)


def test_duplicate_key_409_revoked_payment_guard_owner_reactivation_and_price_snapshot(env_client):
    """Verify Part E safeguards and payment price snapshot accuracy."""
    client, db = env_client

    # 1. Duplicate key rejected with 409 Conflict (never overwrites!)
    r1 = client.post("/api/v1/admin/create", json={"license_key": "NO-DUP-001", "note": "First"}, headers=ADMIN_HDR)
    assert r1.status_code == 200
    r2 = client.post("/api/v1/admin/create", json={"license_key": "NO-DUP-001", "note": "Overwrite"}, headers=ADMIN_HDR)
    assert r2.status_code == 409
    assert db.licenses["NO-DUP-001"]["note"] == "First"
    assert any(a["action"] == "license_created" and a["license_key"] == "NO-DUP-001" for a in db.audit_log)

    # Activate and submit a quarterly payment (snapshot price_inr = 300)
    client.post("/api/v1/validate", json={"license_key": "NO-DUP-001", "device_id": "dev-dup-1", "app_version": "1.0.0"})
    up = client.post(
        "/api/v1/payment-screenshot",
        data={"license_key": "NO-DUP-001", "device_id": "dev-dup-1", "claimed_plan": "quarterly"},
        files={"image": ("proof.png", PNG_1X1, "image/png")},
    )
    assert up.status_code == 200
    sub_id = up.json()["submission_id"]

    # Edit quarterly plan price live to ₹500 BEFORE approval -> historical submission snapshot MUST stay ₹300!
    assert client.put("/api/v1/admin/plans/quarterly", json={"price_inr": 500}, headers=ADMIN_HDR).status_code == 200

    # Revoke license -> audit logged -> approving old pending payment MUST fail with 409!
    assert client.post("/api/v1/admin/revoke", params={"license_key": "NO-DUP-001"}, headers=ADMIN_HDR).status_code == 200
    assert any(a["action"] == "revoked" and a["license_key"] == "NO-DUP-001" for a in db.audit_log)
    assert client.post(f"/api/v1/admin/payment-submissions/{sub_id}/approve", headers=ADMIN_HDR).status_code == 409
    assert client.post("/api/v1/admin/renew", params={"license_key": "NO-DUP-001", "plan": "monthly"}, headers=ADMIN_HDR).status_code == 409

    # Non-owner admin cannot reactivate a revoked license (403)
    now = datetime.now(timezone.utc)
    db.admin_users.append({
        "id": 77,
        "username": "staff-no-reactivate",
        "password_hash": srv._hash_password("StaffPass!77"),
        "email": "s@example.com",
        "role": "admin",
        "created_at": now,
        "updated_at": now,
    })
    st_login = client.post("/api/v1/admin/login", json={"username": "staff-no-reactivate", "password": "StaffPass!77"})
    st_hdr = {"Authorization": f"Bearer {st_login.json()['token']}"}
    assert client.post("/api/v1/admin/reactivate", params={"license_key": "NO-DUP-001"}, headers=st_hdr).status_code == 403
    client.cookies.clear()

    # Owner reactivates -> audit logged -> approval now succeeds & preserves device_id & uses snapshotted ₹300!
    assert client.post("/api/v1/admin/reactivate", params={"license_key": "NO-DUP-001"}, headers=ADMIN_HDR).status_code == 200
    assert any(a["action"] == "reactivated" and a["license_key"] == "NO-DUP-001" for a in db.audit_log)
    assert client.post(f"/api/v1/admin/payment-submissions/{sub_id}/approve", headers=ADMIN_HDR).status_code == 200
    assert db.licenses["NO-DUP-001"]["device_id"] == "dev-dup-1"

    summary = client.get("/api/v1/admin/summary", headers=ADMIN_HDR).json()
    assert summary["counts"]["revenue_this_month_inr"] == 300


def test_ed25519_offline_lease_and_server_password_reset_email_relay(env_client, monkeypatch):
    """Verify Ed25519 signed offline lease claims & authenticated server-side password-reset email relay."""
    import json as _json
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    client, _db = env_client
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
    srv._EMAIL_RELAY_ATTEMPTS.clear()

    v = client.post("/api/v1/validate", json={"license_key": "VIVEK-ANPR-0001", "device_id": "relay-dev-1", "app_version": "1.0.0"})
    assert v.status_code == 200
    lease = v.json()["offline_lease"]
    assert lease is not None and lease["alg"] == "Ed25519"
    payload_bytes = base64.b64decode(lease["payload_b64"])
    sig_bytes = base64.b64decode(lease["signature_b64"])
    pub.verify(sig_bytes, payload_bytes)
    claims = _json.loads(payload_bytes.decode("utf-8"))
    assert claims["device_id"] == "relay-dev-1"
    assert claims["plan"] == "trial"
    assert claims["grace_until_epoch"] <= claims["issued_at_epoch"] + 72 * 3600

    # Email relay rejects unbound/wrong device (403)
    bad_dev = client.post(
        "/api/v1/email/password-reset",
        json={
            "license_key": "VIVEK-ANPR-0001",
            "device_id": "wrong-device",
            "to_email": "ops@example.com",
            "username": "admin",
            "reset_code": "123456",
            "ttl_minutes": 15,
        },
    )
    assert bad_dev.status_code == 403

    # Bound device relays successfully via server-only SMTP helper
    sent = []
    with patch.object(srv, "_send_password_reset_smtp", side_effect=lambda **kw: sent.append(kw)):
        ok_relay = client.post(
            "/api/v1/email/password-reset",
            json={
                "license_key": "VIVEK-ANPR-0001",
                "device_id": "relay-dev-1",
                "to_email": "ops@example.com",
                "username": "admin",
                "reset_code": "654321",
                "ttl_minutes": 15,
            },
        )
    assert ok_relay.status_code == 200 and ok_relay.json()["relayed"] is True
    assert len(sent) == 1 and sent[0]["to_email"] == "ops@example.com"



def test_silent_activate_device_auto_provisions_recovers_and_enforces_one_trial_per_device(env_client, monkeypatch):
    """
    Verify POST /api/v1/activate-device unit/integration behavior:
      1. Never-seen device receives auto-generated key, 180d trial, Ed25519 lease, device_trials row.
      2. Re-calling with same device returns exact existing license & expiry (zero duplicates, newly_provisioned=False).
      3. Different device receives its own independent 180-day trial license.
      4. Revoked/expired existing device returns revoked/expired untouched (no reset/new key).
      5. Unbound device already in device_trials gets trial_already_used until owner override.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    client, db = env_client
    srv._ACTIVATE_DEVICE_ATTEMPTS.clear()

    priv = Ed25519PrivateKey.generate()
    priv_b64 = base64.b64encode(
        priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    ).decode("ascii")
    monkeypatch.setenv("LICENSE_SIGNING_PRIVATE_KEY_B64", priv_b64)

    # 1. First launch for new PC-A -> auto-provisions 180d trial
    r1 = client.post("/api/v1/activate-device", json={"device_id": "auto-dev-pc-a", "app_version": "1.0.0"})
    assert r1.status_code == 200
    b1 = r1.json()
    assert b1["status"] == "active"
    assert b1["plan"] == "trial"
    assert b1["newly_provisioned"] is True
    assert b1["license_key"].startswith("ANPR-")
    assert b1["expires_at"] is not None
    assert b1["offline_lease"] is not None and b1["offline_lease"]["alg"] == "Ed25519"
    key_a = b1["license_key"]
    assert db.device_trials["auto-dev-pc-a"]["first_license_key"] == key_a

    # 2. Second call for same PC-A -> returns exact same key & expiry, no second license created
    r2 = client.post("/api/v1/activate-device", json={"device_id": "auto-dev-pc-a", "app_version": "1.0.0"})
    assert r2.status_code == 200
    b2 = r2.json()
    assert b2["status"] == "active"
    assert b2["newly_provisioned"] is False
    assert b2["license_key"] == key_a
    assert b2["expires_at"] == b1["expires_at"]
    assert sum(1 for lic in db.licenses.values() if lic.get("device_id") == "auto-dev-pc-a") == 1

    # 3. Distinct PC-B -> gets its own independent key
    rb = client.post("/api/v1/activate-device", json={"device_id": "auto-dev-pc-b", "app_version": "1.0.0"})
    assert rb.status_code == 200 and rb.json()["newly_provisioned"] is True
    assert rb.json()["license_key"] != key_a

    # 4. Revoke PC-A -> returns revoked untouched (no offline lease)
    assert client.post("/api/v1/admin/revoke", params={"license_key": key_a}, headers=ADMIN_HDR).status_code == 200
    r_rev = client.post("/api/v1/activate-device", json={"device_id": "auto-dev-pc-a", "app_version": "1.0.0"})
    assert r_rev.json()["status"] == "revoked"
    assert r_rev.json()["license_key"] == key_a
    assert r_rev.json()["offline_lease"] is None

    # 5. Reactivate + expire -> returns expired untouched
    assert client.post("/api/v1/admin/reactivate", params={"license_key": key_a}, headers=ADMIN_HDR).status_code == 200
    assert client.post("/api/v1/admin/expire", params={"license_key": key_a}, headers=ADMIN_HDR).status_code == 200
    r_exp = client.post("/api/v1/activate-device", json={"device_id": "auto-dev-pc-a", "app_version": "1.0.0"})
    assert r_exp.json()["status"] == "expired" and r_exp.json()["license_key"] == key_a

    # 6. Unbind PC-A -> activate-device rejects with trial_already_used
    assert client.post("/api/v1/admin/unbind-device", params={"license_key": key_a}, headers=ADMIN_HDR).status_code == 200
    r_used = client.post("/api/v1/activate-device", json={"device_id": "auto-dev-pc-a", "app_version": "1.0.0"})
    assert r_used.json()["status"] == "trial_already_used" and r_used.json()["license_key"] is None


def test_health_and_ping_keepalive_endpoints_zero_db_queries(env_client):
    """GET and HEAD /health & /ping must return 200 OK immediately without touching Postgres."""
    client, db = env_client
    sql_before = len(db.executed_sql)
    for path in ("/health", "/ping"):
        r_get = client.get(path)
        assert r_get.status_code == 200
        assert r_get.json()["status"] == "ok"
        r_head = client.head(path)
        assert r_head.status_code == 200
    assert len(db.executed_sql) == sql_before, "Keep-alive endpoints must not run DB queries!"


def test_contact_message_relay_owner_telegram_rate_limit_and_table_isolation(env_client, monkeypatch):
    """
    Verify POST /api/v1/contact-message:
      - Relays strictly to owner's TELEGRAM_CHAT_ID via sendMessage with expected format
      - Persists to `contact_messages` (separate from `payment_submissions`)
      - Enforces max 1 message per 2 minutes per device_id (429)
      - Admin listing endpoint returns stored messages
    """
    client, db = env_client
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "98765:FAKE_OWNER_BOT")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "1122334455")

    tg_calls = []

    def fake_tg_post(url, data=None, timeout=None, **_kwargs):
        tg_calls.append({"url": url, "data": data})
        resp = MagicMock()
        resp.status_code = 200
        return resp

    with patch.object(srv.requests, "post", side_effect=fake_tg_post):
        r1 = client.post(
            "/api/v1/contact-message",
            json={
                "license_key": "VIVEK-ANPR-0001",
                "device_id": "gate-pc-support-01",
                "message": "Need help transferring license to new gate PC.",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
    assert r1.status_code == 200
    b1 = r1.json()
    assert b1["ok"] is True
    assert b1["telegram_notified"] is True
    assert len(tg_calls) == 1
    assert "/sendMessage" in tg_calls[0]["url"]
    assert tg_calls[0]["data"]["chat_id"] == "1122334455"
    assert "📩 Message from [VIVEK-ANPR-0001 / gate-pc-support-01]:" in tg_calls[0]["data"]["text"]
    assert "Need help transferring license to new gate PC." in tg_calls[0]["data"]["text"]

    # Stored in contact_messages ONLY (never touches payment_submissions)
    assert len(db.contact_messages) == 1
    assert db.contact_messages[0]["telegram_notified"] is True
    assert len(db.submissions) == 0

    # Immediate second message from same device within 2 minutes -> 429 rate limited
    r_rl = client.post(
        "/api/v1/contact-message",
        json={
            "license_key": "VIVEK-ANPR-0001",
            "device_id": "gate-pc-support-01",
            "message": "Spam follow-up",
        },
    )
    assert r_rl.status_code == 429
    assert len(db.contact_messages) == 1

    # Different device is NOT rate-limited by first device
    with patch.object(srv.requests, "post", side_effect=fake_tg_post):
        r_other = client.post(
            "/api/v1/contact-message",
            json={"device_id": "gate-pc-support-02", "message": "Hello from gate 2"},
        )
    assert r_other.status_code == 200
    assert "📩 Message from [unregistered / gate-pc-support-02]:" in tg_calls[-1]["data"]["text"]

    # After 2+ minutes elapse, first device can send again
    db.contact_messages[0]["received_at"] = datetime.now(timezone.utc) - timedelta(minutes=3)
    with patch.object(srv.requests, "post", side_effect=fake_tg_post):
        r_again = client.post(
            "/api/v1/contact-message",
            json={
                "license_key": "VIVEK-ANPR-0001",
                "device_id": "gate-pc-support-01",
                "message": "Follow-up after cooldown.",
            },
        )
    assert r_again.status_code == 200

    # Admin contact-messages list returns all 3 messages
    lst = client.get("/api/v1/admin/contact-messages", headers=ADMIN_HDR)
    assert lst.status_code == 200
    assert len(lst.json()) == 3


def test_dynamic_trial_days_settings_and_non_retroactive_auto_provisioning(env_client):
    """
    Verify dynamic `system_settings.trial_days`:
      - Seeded to 180 on init_db()
      - Owner-only access (non-owner admin gets 403)
      - Change 180 -> 7 -> newly auto-provisioned PC-1 gets exact 7-day trial
      - Change 7 -> 30 -> newly auto-provisioned PC-2 gets exact 30-day trial
      - PC-1 retains its original 7-day expiry (strictly non-retroactive!)
      - Change logged in `license_audit_log` as `setting_updated`
    """
    client, db = env_client
    srv._ACTIVATE_DEVICE_ATTEMPTS.clear()

    # Seeded default is 180
    s0 = client.get("/api/v1/admin/settings", headers=ADMIN_HDR)
    assert s0.status_code == 200
    assert s0.json()["trial_days"] == 180

    # Non-owner staff admin cannot read or change system settings (403)
    now = datetime.now(timezone.utc)
    db.admin_users.append({
        "id": 91,
        "username": "staff-no-settings",
        "password_hash": srv._hash_password("StaffSettings!91"),
        "email": "staff91@example.com",
        "role": "admin",
        "created_at": now,
        "updated_at": now,
    })
    st_login = client.post("/api/v1/admin/login", json={"username": "staff-no-settings", "password": "StaffSettings!91"})
    st_hdr = {"Authorization": f"Bearer {st_login.json()['token']}"}
    assert client.get("/api/v1/admin/settings", headers=st_hdr).status_code == 403
    assert client.put("/api/v1/admin/settings", json={"trial_days": 7}, headers=st_hdr).status_code == 403
    client.cookies.clear()

    # Invalid bounds rejected (400)
    assert client.put("/api/v1/admin/settings", json={"trial_days": 0}, headers=ADMIN_HDR).status_code == 400
    assert client.put("/api/v1/admin/settings", json={"trial_days": 4000}, headers=ADMIN_HDR).status_code == 400

    # Owner updates trial_days: 180 -> 7
    u1 = client.put("/api/v1/admin/settings", json={"trial_days": 7}, headers=ADMIN_HDR)
    assert u1.status_code == 200
    assert u1.json()["trial_days"] == 7
    assert u1.json()["previous_trial_days"] == 180
    assert any(a["action"] == "setting_updated" and a["new_plan"] == "7d" for a in db.audit_log)

    # Auto-provision PC-1 -> gets 7-day expiry!
    r_pc1 = client.post("/api/v1/activate-device", json={"device_id": "dyn-trial-pc-001", "app_version": "1.0.0"})
    assert r_pc1.status_code == 200
    b_pc1 = r_pc1.json()
    assert b_pc1["status"] == "active" and b_pc1["newly_provisioned"] is True
    exp_pc1 = datetime.fromisoformat(b_pc1["expires_at"])
    days_pc1 = (exp_pc1 - datetime.now(timezone.utc)).total_seconds() / 86400.0
    assert 6.9 <= days_pc1 <= 7.1

    # Owner updates trial_days: 7 -> 30
    u2 = client.put("/api/v1/admin/settings", json={"trial_days": 30}, headers=ADMIN_HDR)
    assert u2.status_code == 200 and u2.json()["trial_days"] == 30

    # Auto-provision PC-2 -> gets 30-day expiry!
    r_pc2 = client.post("/api/v1/activate-device", json={"device_id": "dyn-trial-pc-002", "app_version": "1.0.0"})
    assert r_pc2.status_code == 200
    b_pc2 = r_pc2.json()
    assert b_pc2["status"] == "active" and b_pc2["newly_provisioned"] is True
    exp_pc2 = datetime.fromisoformat(b_pc2["expires_at"])
    days_pc2 = (exp_pc2 - datetime.now(timezone.utc)).total_seconds() / 86400.0
    assert 29.9 <= days_pc2 <= 30.1

    # PC-1 re-check MUST still have its original 7-day expiry (non-retroactive!)
    r_pc1_again = client.post("/api/v1/activate-device", json={"device_id": "dyn-trial-pc-001", "app_version": "1.0.0"})
    assert r_pc1_again.status_code == 200
    assert r_pc1_again.json()["expires_at"] == b_pc1["expires_at"]
    assert db.licenses[b_pc1["license_key"]]["trial_days"] == 7
    assert db.licenses[b_pc2["license_key"]]["trial_days"] == 30


def test_remote_credential_provisioning_owner_only_one_shot_consume_and_audit(env_client):
    """
    Verify SystemOwner emergency remote credential provisioning:
      - Owner-only access (non-owner staff admin receives 403)
      - Password immediately bcrypt-hashed; plaintext never stored or returned in API responses
      - Delivered ONLY to the targeted bound device via `/api/v1/validate` (never leaked to other devices)
      - `/api/v1/credential-provisions/consume` rejects mismatched device/license key (403)
      - Once consumed, `consumed_at` is stamped, audit entries recorded, and subsequent `/validate` returns []
      - Dashboard HTML exposes "Provision Login Credentials" modal cleanly
    """
    client, db = env_client
    srv._ACTIVATE_DEVICE_ATTEMPTS.clear()

    # Bind two distinct devices via silent auto-provisioning
    ra = client.post("/api/v1/activate-device", json={"device_id": "prov-dev-alpha-01", "app_version": "1.0.0"})
    rb = client.post("/api/v1/activate-device", json={"device_id": "prov-dev-beta-02", "app_version": "1.0.0"})
    assert ra.status_code == 200 and rb.status_code == 200
    key_a = ra.json()["license_key"]
    key_b = rb.json()["license_key"]

    # Non-owner staff admin cannot create or list remote credential provisions (403)
    now = datetime.now(timezone.utc)
    db.admin_users.append({
        "id": 92,
        "username": "staff-no-prov",
        "password_hash": srv._hash_password("StaffProv!92"),
        "email": "staff92@example.com",
        "role": "admin",
        "created_at": now,
        "updated_at": now,
    })
    st_login = client.post("/api/v1/admin/login", json={"username": "staff-no-prov", "password": "StaffProv!92"})
    st_hdr = {"Authorization": f"Bearer {st_login.json()['token']}"}
    assert client.get("/api/v1/admin/credential-provisions", headers=st_hdr).status_code == 403
    assert client.post(
        "/api/v1/admin/credential-provisions",
        json={
            "device_id": "prov-dev-alpha-01",
            "username": "rescue_admin",
            "email": "rescue@facility.local",
            "password": "StrongPassword!1",
            "role": "ADMIN",
        },
        headers=st_hdr,
    ).status_code == 403
    client.cookies.clear()

    # SystemOwner queues one-shot credentials for Device Alpha
    p_resp = client.post(
        "/api/v1/admin/credential-provisions",
        json={
            "device_id": "prov-dev-alpha-01",
            "username": "Rescue_Admin",
            "email": "Rescue@Facility.Local",
            "password": "EmergencyLogin!2026",
            "role": "admin",
        },
        headers=ADMIN_HDR,
    )
    assert p_resp.status_code == 200
    pb = p_resp.json()
    prov_id = pb["id"]
    assert pb["username"] == "rescue_admin"
    assert pb["email"] == "rescue@facility.local"
    assert pb["role"] == "ADMIN"
    assert pb["consumed_at"] is None
    assert pb["must_change_password"] is True
    assert pb["one_time_password"] == "EmergencyLogin!2026"
    assert "password" not in pb and "password_hash" not in pb

    # Stored row in DB has bcrypt hash, NEVER plaintext
    stored = db.remote_credential_provisions[0]
    assert stored["password_hash"].startswith("$2b$")
    assert "EmergencyLogin!2026" not in stored["password_hash"]
    assert srv._verify_password("EmergencyLogin!2026", stored["password_hash"]) is True

    # Server audit log clearly marks "Remotely provisioned by SystemOwner"
    assert any(
        a["action"] == "remote_credentials_provisioned"
        and "remotely provisioned by systemowner" in (a.get("note") or "").lower()
        for a in db.audit_log
    )

    # Device Beta's validate call MUST NOT receive Alpha's pending provision
    vb = client.post("/api/v1/validate", json={"license_key": key_b, "device_id": "prov-dev-beta-02", "app_version": "1.0.0"})
    assert vb.status_code == 200
    assert vb.json()["pending_credential_provisions"] == []

    # Device Alpha's validate call receives the exact pending provision
    va = client.post("/api/v1/validate", json={"license_key": key_a, "device_id": "prov-dev-alpha-01", "app_version": "1.0.0"})
    assert va.status_code == 200
    pending_a = va.json()["pending_credential_provisions"]
    assert len(pending_a) == 1
    assert pending_a[0]["id"] == prov_id
    assert pending_a[0]["username"] == "rescue_admin"
    assert pending_a[0]["password_hash"] == stored["password_hash"]
    assert pending_a[0]["role"] == "ADMIN"

    # Spoofed consume with Beta's license key for Alpha's device -> 403
    bad_consume = client.post(
        "/api/v1/credential-provisions/consume",
        json={"provision_id": prov_id, "device_id": "prov-dev-alpha-01", "license_key": key_b, "applied": True},
    )
    assert bad_consume.status_code == 403

    # Legitimate consume from Device Alpha -> stamps consumed_at & logs server audit entry
    ok_consume = client.post(
        "/api/v1/credential-provisions/consume",
        json={
            "provision_id": prov_id,
            "device_id": "prov-dev-alpha-01",
            "license_key": key_a,
            "applied": True,
            "outcome": "created:ADMIN",
        },
    )
    assert ok_consume.status_code == 200
    assert ok_consume.json()["already_consumed"] is False
    assert ok_consume.json()["consumed_at"] is not None

    # Listing endpoint shows consumed_at set and NEVER exposes password_hash
    lst = client.get("/api/v1/admin/credential-provisions", params={"device_id": "prov-dev-alpha-01"}, headers=ADMIN_HDR)
    assert lst.status_code == 200
    items = lst.json()
    assert len(items) == 1
    assert items[0]["status"] == "consumed" and items[0]["consumed_at"] is not None
    assert "password_hash" not in items[0]

    # Next validate on Device Alpha returns NO pending provisions (strictly one-shot!)
    va2 = client.post("/api/v1/validate", json={"license_key": key_a, "device_id": "prov-dev-alpha-01", "app_version": "1.0.0"})
    assert va2.status_code == 200
    assert va2.json()["pending_credential_provisions"] == []

    # Consumed audit entry exists on server
    assert any(
        a["action"] == "remote_credentials_consumed"
        and "remotely provisioned by systemowner" in (a.get("note") or "").lower()
        for a in db.audit_log
    )

    # Dashboard HTML contains the SystemOwner modal & action button
    dash_html = (Path(__file__).resolve().parent / "admin_ui" / "dashboard.html").read_text(encoding="utf-8")
    assert "Provision Login Credentials" in dash_html
    assert 'id="provision-creds-modal"' in dash_html


def test_license_label_create_update_clear_and_summary_display(env_client):
    """
    Verify Feature 1 (License Label):
      - Optional `label` supported on POST /api/v1/admin/create
      - POST /api/v1/admin/label?license_key=...&label=... sets, updates, and clears label
      - Label returned prominently by /api/v1/admin/list and /api/v1/admin/summary
      - Audited as `label_updated` in license_audit_log
    """
    client, db = env_client

    cr = client.post(
        "/api/v1/admin/create",
        json={"license_key": "LABELED-KEY-01", "note": "Main entry", "label": "Customer — Main Gate"},
        headers=ADMIN_HDR,
    )
    assert cr.status_code == 200
    assert cr.json()["label"] == "Customer — Main Gate"

    lst = client.get("/api/v1/admin/list", headers=ADMIN_HDR).json()
    row = next(r for r in lst if r["license_key"] == "LABELED-KEY-01")
    assert row["label"] == "Customer — Main Gate"

    # Update label via POST /api/v1/admin/label
    upd = client.post(
        "/api/v1/admin/label",
        params={"license_key": "LABELED-KEY-01", "label": "Vivek's Dev PC"},
        headers=ADMIN_HDR,
    )
    assert upd.status_code == 200
    assert upd.json()["label"] == "Vivek's Dev PC"
    assert upd.json()["previous_label"] == "Customer — Main Gate"

    # Visible in /admin/summary
    summ = client.get("/api/v1/admin/summary", headers=ADMIN_HDR).json()
    summ_row = next(r for r in summ["active_licenses"] if r["license_key"] == "LABELED-KEY-01")
    assert summ_row["label"] == "Vivek's Dev PC"

    # Audited cleanly
    assert any(
        a["action"] == "label_updated"
        and a["license_key"] == "LABELED-KEY-01"
        and "Vivek's Dev PC" in (a.get("note") or "")
        for a in db.audit_log
    )

    # Clear label by passing blank string
    clr = client.post(
        "/api/v1/admin/label",
        params={"license_key": "LABELED-KEY-01", "label": ""},
        headers=ADMIN_HDR,
    )
    assert clr.status_code == 200
    assert clr.json()["label"] is None

    # Unknown key -> 404; >120 chars -> 400
    assert client.post("/api/v1/admin/label", params={"license_key": "NO-SUCH-KEY", "label": "X"}, headers=ADMIN_HDR).status_code == 404
    assert client.post("/api/v1/admin/label", params={"license_key": "LABELED-KEY-01", "label": "A" * 121}, headers=ADMIN_HDR).status_code == 400


def test_delete_license_preserves_device_trials_until_explicit_clear_then_allows_fresh_trial(env_client):
    """
    Verify Feature 2 (Delete License + Explicit Separate Trial-Clear Step):
      - POST /api/v1/admin/delete hard-deletes the license row
      - By default (`clear_device_trial=false`), preserves `device_trials` so the device gets
        `trial_already_used` on next launch until SystemOwner explicitly clears `device_trials`
      - Non-owner staff admin receives 403 if requesting `clear_device_trial=true`
      - After explicit `POST /api/v1/admin/device-trials/override`, the device receives a fresh trial!
    """
    client, db = env_client
    srv._ACTIVATE_DEVICE_ATTEMPTS.clear()

    # Auto-provision a bound trial device
    act1 = client.post("/api/v1/activate-device", json={"device_id": "del-test-pc-001", "app_version": "1.0.0"})
    assert act1.status_code == 200
    key1 = act1.json()["license_key"]
    assert key1 in db.licenses
    assert "del-test-pc-001" in db.device_trials

    # Non-owner staff admin cannot pass clear_device_trial=true (403)
    now = datetime.now(timezone.utc)
    db.admin_users.append({
        "id": 95,
        "username": "staff-del",
        "password_hash": srv._hash_password("StaffDel!95"),
        "email": "staff95@example.com",
        "role": "admin",
        "created_at": now,
        "updated_at": now,
    })
    st_hdr = {
        "Authorization": "Bearer " + client.post(
            "/api/v1/admin/login", json={"username": "staff-del", "password": "StaffDel!95"}
        ).json()["token"]
    }
    assert client.post(
        "/api/v1/admin/delete",
        params={"license_key": key1, "clear_device_trial": "true"},
        headers=st_hdr,
    ).status_code == 403
    client.cookies.clear()

    # Step 1: Hard-delete license row (default preserves device_trials!)
    del_r = client.post("/api/v1/admin/delete", params={"license_key": key1}, headers=ADMIN_HDR)
    assert del_r.status_code == 200
    del_b = del_r.json()
    assert del_b["action"] == "license_deleted"
    assert del_b["previous_device_id"] == "del-test-pc-001"
    assert del_b["had_device_trial"] is True
    assert del_b["device_trial_cleared"] is False
    assert key1 not in db.licenses
    assert "del-test-pc-001" in db.device_trials
    assert any(a["action"] == "license_deleted" and a["license_key"] == key1 for a in db.audit_log)

    # Device launching again BEFORE clearing trial record MUST still be blocked (one-trial-per-device intact!)
    act_blocked = client.post("/api/v1/activate-device", json={"device_id": "del-test-pc-001", "app_version": "1.0.0"})
    assert act_blocked.status_code == 200
    assert act_blocked.json()["status"] == "trial_already_used"

    # Step 2 (Explicit deliberate confirmation): Clear device_trials via override
    ov = client.post(
        "/api/v1/admin/device-trials/override",
        json={"device_id": "del-test-pc-001", "note": "Deliberate test reset"},
        headers=ADMIN_HDR,
    )
    assert ov.status_code == 200 and ov.json()["cleared"] is True
    assert "del-test-pc-001" not in db.device_trials

    # Now device re-provisions a brand-new active trial license cleanly!
    act_fresh = client.post("/api/v1/activate-device", json={"device_id": "del-test-pc-001", "app_version": "1.0.0"})
    assert act_fresh.status_code == 200
    b_fresh = act_fresh.json()
    assert b_fresh["status"] == "active"
    assert b_fresh["newly_provisioned"] is True
    assert b_fresh["license_key"] != key1


def test_client_rbac_directory_sync_one_time_password_shown_once_and_dashboard_elements(env_client):
    """
    Verify Feature 3 (Manage Client RBAC Login Credentials from Server Portal):
      - Device syncs local usernames/emails/roles via POST /api/v1/device-rbac/sync (403 on mismatch)
      - SystemOwner lists devices + labels + RBAC accounts via GET /api/v1/admin/device-rbac-accounts
        (403 for non-owner; ZERO passwords or password hashes exposed anywhere)
      - SystemOwner pushes a blank-password provision -> server auto-generates a strong one-time
        password, hashes it with bcrypt, returns `one_time_password` ONCE in POST response, marks
        `must_change_password=True`, and NEVER returns the password in any GET endpoint!
      - Dashboard HTML renders label editor, two-step delete modal, Client Accounts (RBAC) tab,
        and one-time password reveal box cleanly with flat enterprise styling.
    """
    client, db = env_client
    srv._ACTIVATE_DEVICE_ATTEMPTS.clear()

    act = client.post("/api/v1/activate-device", json={"device_id": "rbac-portal-pc-01", "app_version": "1.0.0"})
    key = act.json()["license_key"]
    client.post("/api/v1/admin/label", params={"license_key": key, "label": "Warehouse Gate 2"}, headers=ADMIN_HDR)

    # Mismatched device rejected (403)
    bad_sync = client.post(
        "/api/v1/device-rbac/sync",
        json={
            "license_key": key,
            "device_id": "other-spoof-pc-99",
            "accounts": [{"username": "admin", "email": "admin@gate.local", "role": "ADMIN"}],
        },
    )
    assert bad_sync.status_code == 403

    # Bound device syncs its local RBAC roster (usernames/emails/roles ONLY)
    ok_sync = client.post(
        "/api/v1/device-rbac/sync",
        json={
            "license_key": key,
            "device_id": "rbac-portal-pc-01",
            "accounts": [
                {"username": "admin", "email": "admin@wh2.local", "role": "ADMIN", "is_active": True, "must_change_password": False},
                {"username": "gate_op", "email": "op@wh2.local", "role": "OPERATOR", "is_active": True, "must_change_password": False},
            ],
        },
    )
    assert ok_sync.status_code == 200
    assert ok_sync.json()["synced_count"] == 2

    # Non-owner staff admin gets 403 on GET /api/v1/admin/device-rbac-accounts
    now = datetime.now(timezone.utc)
    db.admin_users.append({
        "id": 96,
        "username": "staff-rbac-view",
        "password_hash": srv._hash_password("StaffRbac!96"),
        "email": "staff96@example.com",
        "role": "admin",
        "created_at": now,
        "updated_at": now,
    })
    st_hdr = {
        "Authorization": "Bearer " + client.post(
            "/api/v1/admin/login", json={"username": "staff-rbac-view", "password": "StaffRbac!96"}
        ).json()["token"]
    }
    assert client.get("/api/v1/admin/device-rbac-accounts", headers=st_hdr).status_code == 403
    client.cookies.clear()

    # SystemOwner inspects Client Accounts directory -> sees label + both accounts, ZERO passwords/hashes
    dir_resp = client.get("/api/v1/admin/device-rbac-accounts", headers=ADMIN_HDR)
    assert dir_resp.status_code == 200
    dev_entry = next(d for d in dir_resp.json() if d["device_id"] == "rbac-portal-pc-01")
    assert dev_entry["label"] == "Warehouse Gate 2"
    assert dev_entry["license_key"] == key
    assert {a["username"] for a in dev_entry["accounts"]} == {"admin", "gate_op"}
    for acct in dev_entry["accounts"]:
        assert "password" not in acct and "password_hash" not in acct and "hashed_password" not in acct

    # SystemOwner pushes a one-time password with blank password -> server auto-generates strong OTP
    push = client.post(
        "/api/v1/admin/credential-provisions",
        json={
            "device_id": "rbac-portal-pc-01",
            "username": "admin",
            "email": "admin@wh2.local",
            "password": None,
            "role": "ADMIN",
        },
        headers=ADMIN_HDR,
    )
    assert push.status_code == 200
    pb = push.json()
    otp = pb["one_time_password"]
    assert pb["auto_generated_password"] is True
    assert pb["must_change_password"] is True
    assert otp.startswith("Tmp!") and len(otp) >= 14
    assert "password_hash" not in pb

    # Stored strictly as bcrypt hash; never returned in GET endpoints
    stored = db.remote_credential_provisions[-1]
    assert stored["password_hash"].startswith("$2b$")
    assert otp not in stored["password_hash"]
    assert srv._verify_password(otp, stored["password_hash"]) is True

    get_provs = client.get("/api/v1/admin/credential-provisions", headers=ADMIN_HDR).json()
    assert all("one_time_password" not in p and "password_hash" not in p for p in get_provs)
    dir_after = client.get("/api/v1/admin/device-rbac-accounts", headers=ADMIN_HDR).json()
    dev_after = next(d for d in dir_after if d["device_id"] == "rbac-portal-pc-01")
    assert all("one_time_password" not in p and "password_hash" not in p for p in dev_after["provisions"])
    admin_acct = next(a for a in dev_after["accounts"] if a["username"] == "admin")
    assert admin_acct["must_change_password"] is True

    # Dashboard HTML wires all three new UI features cleanly
    dash_html = (Path(__file__).resolve().parent / "admin_ui" / "dashboard.html").read_text(encoding="utf-8")
    for required_id in (
        'id="new-license-label"',
        'id="edit-label-modal"',
        'id="delete-license-modal"',
        'id="delete-step-1"',
        'id="delete-step-2"',
        'id="delete-step2-clear-trial"',
        'id="tab-client-rbac-btn"',
        'id="panel-client-rbac"',
        'id="prov-must-change"',
        'id="prov-otp-result"',
        'id="prov-otp-value"',
    ):
        assert required_id in dash_html, f"Missing {required_id} in dashboard.html"


def test_device_trials_lookup_and_dashboard_clear_unblocks_stuck_device(env_client):
    """
    Verify Dashboard 'Device Trials' panel backend + UI flow:
      1. Non-owner staff admin receives 403 on GET /api/v1/admin/device-trials.
      2. A device that auto-provisioned and then had its license deleted (without clearing trial)
         is stuck on `trial_already_used` with NO bound license row.
      3. GET /api/v1/admin/device-trials?device_id=<prefix> finds it and reports:
         `used=True`, `is_orphaned=True`, `first_activated_at`, `first_license_key`, `bound_license=None`.
      4. Clearing via POST /api/v1/admin/device-trials/override switches GET lookup to `used=False`.
      5. The same device immediately succeeds on POST /api/v1/activate-device with a fresh active trial!
      6. Dashboard HTML exposes the dedicated Device Trials lookup/clear panel inside the Licenses tab.
    """
    client, db = env_client
    srv._ACTIVATE_DEVICE_ATTEMPTS.clear()

    dev_id = "stuck-test-pc-f5293092de550099aa"

    # Non-owner staff admin blocked (403)
    now = datetime.now(timezone.utc)
    db.admin_users.append({
        "id": 97,
        "username": "staff-no-trials",
        "password_hash": srv._hash_password("StaffTrials!97"),
        "email": "staff97@example.com",
        "role": "admin",
        "created_at": now,
        "updated_at": now,
    })
    st_hdr = {
        "Authorization": "Bearer " + client.post(
            "/api/v1/admin/login", json={"username": "staff-no-trials", "password": "StaffTrials!97"}
        ).json()["token"]
    }
    assert client.get("/api/v1/admin/device-trials", headers=st_hdr).status_code == 403
    client.cookies.clear()

    # 1. Auto-provision then delete license (default preserves device_trials -> stuck!)
    a1 = client.post("/api/v1/activate-device", json={"device_id": dev_id, "app_version": "1.0.0"})
    assert a1.status_code == 200 and a1.json()["status"] == "active"
    first_key = a1.json()["license_key"]

    d1 = client.post("/api/v1/admin/delete", params={"license_key": first_key}, headers=ADMIN_HDR)
    assert d1.status_code == 200 and d1.json()["device_trial_cleared"] is False

    # Confirm device is stuck on trial_already_used
    stuck = client.post("/api/v1/activate-device", json={"device_id": dev_id, "app_version": "1.0.0"})
    assert stuck.status_code == 200 and stuck.json()["status"] == "trial_already_used"

    # 2. Dashboard Device Trials list & prefix lookup show full context before clearing
    lst = client.get("/api/v1/admin/device-trials", headers=ADMIN_HDR).json()
    assert lst["orphaned_count"] >= 1
    assert any(t["device_id"] == dev_id and t["is_orphaned"] is True for t in lst["trials"])

    lookup = client.get("/api/v1/admin/device-trials", params={"device_id": "stuck-test-pc-f529"}, headers=ADMIN_HDR).json()
    assert lookup["device_id"] == dev_id
    assert lookup["used"] is True
    assert lookup["is_orphaned"] is True
    assert lookup["first_license_key"] == first_key
    assert lookup["first_activated_at"] is not None
    assert lookup["bound_license"] is None

    # 3. Deliberate clear via /api/v1/admin/device-trials/override
    clr = client.post(
        "/api/v1/admin/device-trials/override",
        json={"device_id": dev_id, "note": "Cleared from Dashboard Device Trials panel"},
        headers=ADMIN_HDR,
    )
    assert clr.status_code == 200 and clr.json()["cleared"] is True

    # Lookup immediately shows NOT USED
    lookup_after = client.get("/api/v1/admin/device-trials", params={"device_id": dev_id}, headers=ADMIN_HDR).json()
    assert lookup_after["used"] is False
    assert lookup_after["first_activated_at"] is None

    # 4. Same device now cleanly auto-provisions a brand-new active trial!
    a2 = client.post("/api/v1/activate-device", json={"device_id": dev_id, "app_version": "1.0.0"})
    assert a2.status_code == 200
    assert a2.json()["status"] == "active"
    assert a2.json()["newly_provisioned"] is True
    assert a2.json()["license_key"] != first_key

    # 5. Dashboard HTML exposes the standalone Device Trials panel inside #panel-licenses
    dash_html = (Path(__file__).resolve().parent / "admin_ui" / "dashboard.html").read_text(encoding="utf-8")
    for required_id in (
        'id="device-trials-card"',
        'id="device-trial-lookup-form"',
        'id="device-trial-lookup-input"',
        'id="device-trial-status-box"',
        'id="device-trials-list"',
    ):
        assert required_id in dash_html, f"Missing {required_id} in dashboard.html"
    assert "Clear Trial Record" in dash_html
