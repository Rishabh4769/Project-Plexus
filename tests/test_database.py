"""Tests for backend/database.py — SQLite layer and parameterised queries.

All tests run against the `fresh_db` fixture (throwaway SQLite file),
so the real network_traffic.db is never touched.
"""

import time

PACKET = (
    "2026-01-01T00:00:00",  # timestamp
    "192.168.1.5",          # src_ip
    "192.168.1.10",         # dst_ip
    40000,                  # src_port
    80,                     # dst_port
    60,                     # length
    "TCP",                  # protocol
    "S",                    # flags
    64,                     # ttl
    12345,                  # checksum
    "deadbeef",             # payload preview
    "sess-1",               # session_id
)

ALERT = (
    "2026-01-01T00:00:01",  # timestamp
    "192.168.1.5",          # src_ip
    "Port Scanning",        # alert_type
    "6 distinct ports probed",
    "sess-1",               # session_id
)


def test_init_db_is_idempotent(fresh_db):
    fresh_db.init_db()  # second and third calls must not raise
    fresh_db.init_db()


def test_log_packet_and_get_packets_roundtrip(fresh_db):
    fresh_db.log_packet(PACKET)
    rows = fresh_db.get_packets("sess-1")
    assert len(rows) == 1
    assert rows[0]["src_ip"] == "192.168.1.5"
    assert rows[0]["dst_ip"] == "192.168.1.10"
    assert rows[0]["dst_port"] == 80
    assert rows[0]["protocol"] == "TCP"


def test_packets_isolated_by_session(fresh_db):
    fresh_db.log_packet(PACKET)
    assert fresh_db.get_packets("other-session") == []


def test_log_alert_and_get_alerts_roundtrip(fresh_db):
    fresh_db.log_alert(ALERT)
    rows = fresh_db.get_alerts("sess-1")
    assert len(rows) == 1
    assert rows[0]["alert_type"] == "Port Scanning"
    assert rows[0]["src_ip"] == "192.168.1.5"


def test_create_and_get_user(fresh_db):
    assert fresh_db.create_user("alice", "bcrypt-hash-1") is True
    user = fresh_db.get_user("alice")
    assert user is not None
    assert user["username"] == "alice"
    assert user["password_hash"] == "bcrypt-hash-1"


def test_duplicate_user_rejected(fresh_db):
    assert fresh_db.create_user("alice", "hash-1") is True
    assert fresh_db.create_user("alice", "hash-2") is False
    # original row untouched
    assert fresh_db.get_user("alice")["password_hash"] == "hash-1"


def test_get_missing_user_returns_none(fresh_db):
    assert fresh_db.get_user("nobody") is None


def test_tricky_username_stored_literally_and_safely(fresh_db):
    # If queries were string-interpolated, this would break out of the
    # statement. Parameterised queries must store it as plain data.
    evil = "o'brien OR 1=1 --"
    assert fresh_db.create_user(evil, "hash-x") is True
    user = fresh_db.get_user(evil)
    assert user is not None
    assert user["username"] == evil
    # the users table is intact — nothing was dropped or altered
    assert fresh_db.user_count() == 1


def test_session_row_crud(fresh_db):
    fresh_db.create_session_row("tokhash1", "alice", time.time() + 3600)
    row = fresh_db.get_session_row("tokhash1")
    assert row is not None and row["username"] == "alice"

    fresh_db.touch_session("tokhash1", time.time() + 7200)
    row2 = fresh_db.get_session_row("tokhash1")
    assert row2["expires_at"] > row["expires_at"]

    fresh_db.delete_session_row("tokhash1")
    assert fresh_db.get_session_row("tokhash1") is None


def test_purge_expired_sessions_keeps_live_ones(fresh_db):
    now = time.time()
    fresh_db.create_session_row("expired-row", "alice", now - 10)
    fresh_db.create_session_row("live-row", "alice", now + 3600)
    fresh_db.purge_expired_sessions(now)
    assert fresh_db.get_session_row("expired-row") is None
    assert fresh_db.get_session_row("live-row") is not None


def test_write_and_get_logs_roundtrip(fresh_db):
    fresh_db.write_log("backend", "info", "auth", "login ok",
                       session_id="s1", username="alice")
    logs = fresh_db.get_logs(source="backend")
    assert len(logs) == 1
    assert logs[0]["message"] == "login ok"
    assert logs[0]["level"] == "INFO"  # level is normalised to upper case
    assert logs[0]["username"] == "alice"


def test_get_logs_filtering(fresh_db):
    fresh_db.write_log("backend", "info", "auth", "first")
    fresh_db.write_log("backend", "error", "capture", "second")
    assert len(fresh_db.get_logs(level="ERROR")) == 1
    assert len(fresh_db.get_logs(category="auth")) == 1
    assert len(fresh_db.get_logs()) == 2
