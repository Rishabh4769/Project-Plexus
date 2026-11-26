"""Tests for v3.2.0 Block 2 — alert lifecycle + occurrence counting.

Covers backend/database.py: log_alert creation fields and dedupe,
update_alert lifecycle transitions and validation, list_alerts filters.
All tests run against the `fresh_db` fixture (throwaway SQLite file),
so the real network_traffic.db is never touched.
"""

import pytest

SCAN = (
    "2026-01-01T00:00:01",  # timestamp
    "192.168.1.5",          # src_ip
    "Port Scanning",        # alert_type
    "6 distinct ports probed",
    "sess-1",               # session_id
)

FLOOD = (
    "2026-01-01T00:01:00",
    "192.168.1.9",
    "Flooding",
    "1500 packets in window",
    "sess-1",
)


def _only_alert(db):
    rows = db.list_alerts()
    assert len(rows) == 1
    return rows[0]


# ── Creation fields ────────────────────────────────────────────────── #

def test_new_alert_gets_lifecycle_fields(fresh_db):
    fresh_db.log_alert(SCAN)
    a = _only_alert(fresh_db)
    assert a["status"] == "open"
    assert a["severity_id"] == 2                      # Port Scanning -> 2
    assert a["event_count"] == 1
    assert a["first_seen"] == SCAN[0]
    assert a["last_seen"] == SCAN[0]
    assert a["notes"] == ""


def test_new_alert_gets_mitre_tags(fresh_db):
    fresh_db.log_alert(SCAN)
    a = _only_alert(fresh_db)
    assert a["mitre_tactic"] == "reconnaissance"
    assert a["mitre_technique_id"] == "T1046"


def test_flood_alert_severity_and_mitre(fresh_db):
    fresh_db.log_alert(FLOOD)
    a = _only_alert(fresh_db)
    assert a["severity_id"] == 4                      # Flooding -> critical
    assert a["mitre_technique_id"] == "T1498"


# ── Occurrence counting (dedupe) ───────────────────────────────────── #

def test_repeat_fire_merges_into_open_alert(fresh_db):
    fresh_db.log_alert(SCAN)
    later = ("2026-01-01T00:05:00",) + SCAN[1:]
    fresh_db.log_alert(later)
    fresh_db.log_alert(later)
    a = _only_alert(fresh_db)
    assert a["event_count"] == 3
    assert a["first_seen"] == SCAN[0]
    assert a["last_seen"] == "2026-01-01T00:05:00"


def test_different_source_ip_does_not_merge(fresh_db):
    fresh_db.log_alert(SCAN)
    other = (SCAN[0], "192.168.1.77") + SCAN[2:]
    fresh_db.log_alert(other)
    assert len(fresh_db.list_alerts()) == 2


def test_refire_after_resolution_opens_fresh_alert(fresh_db):
    fresh_db.log_alert(SCAN)
    a = _only_alert(fresh_db)
    fresh_db.update_alert(a["id"], status="resolved", actor="analyst")
    fresh_db.log_alert(SCAN)
    rows = fresh_db.list_alerts()
    assert len(rows) == 2
    fresh = [r for r in rows if r["status"] == "open"]
    assert len(fresh) == 1
    assert fresh[0]["event_count"] == 1


# ── Lifecycle transitions ──────────────────────────────────────────── #

def test_valid_transitions(fresh_db):
    fresh_db.log_alert(SCAN)
    a = _only_alert(fresh_db)
    a = fresh_db.update_alert(a["id"], status="acknowledged", actor="rishabh")
    assert a["status"] == "acknowledged"
    assert a["acknowledged_by"] == "rishabh"
    a = fresh_db.update_alert(a["id"], status="resolved", actor="rishabh")
    assert a["status"] == "resolved"
    assert a["resolved_by"] == "rishabh"
    assert a["resolved_at"] is not None


def test_acknowledged_can_reopen(fresh_db):
    fresh_db.log_alert(SCAN)
    a = _only_alert(fresh_db)
    fresh_db.update_alert(a["id"], status="acknowledged")
    a = fresh_db.update_alert(a["id"], status="open")
    assert a["status"] == "open"


def test_terminal_state_rejects_further_transitions(fresh_db):
    fresh_db.log_alert(SCAN)
    a = _only_alert(fresh_db)
    fresh_db.update_alert(a["id"], status="resolved")
    with pytest.raises(ValueError):
        fresh_db.update_alert(a["id"], status="open")


def test_unknown_status_rejected(fresh_db):
    fresh_db.log_alert(SCAN)
    a = _only_alert(fresh_db)
    with pytest.raises(ValueError):
        fresh_db.update_alert(a["id"], status="banana")


def test_update_missing_alert_raises(fresh_db):
    with pytest.raises(ValueError):
        fresh_db.update_alert(9999, status="acknowledged")


# ── Severity + notes ───────────────────────────────────────────────── #

def test_severity_editable(fresh_db):
    fresh_db.log_alert(SCAN)
    a = _only_alert(fresh_db)
    a = fresh_db.update_alert(a["id"], severity_id=5)
    assert a["severity_id"] == 5


def test_severity_out_of_range_rejected(fresh_db):
    fresh_db.log_alert(SCAN)
    a = _only_alert(fresh_db)
    with pytest.raises(ValueError):
        fresh_db.update_alert(a["id"], severity_id=6)


def test_notes_set_and_clear(fresh_db):
    fresh_db.log_alert(SCAN)
    a = _only_alert(fresh_db)
    a = fresh_db.update_alert(a["id"], notes="known scanner, watching")
    assert a["notes"] == "known scanner, watching"
    a = fresh_db.update_alert(a["id"], notes="")
    assert a["notes"] == ""


def test_partial_update_leaves_other_fields_alone(fresh_db):
    fresh_db.log_alert(SCAN)
    a = _only_alert(fresh_db)
    fresh_db.update_alert(a["id"], notes="note only")
    a = _only_alert(fresh_db)
    assert a["status"] == "open"
    assert a["severity_id"] == 2


# ── List filters ───────────────────────────────────────────────────── #

def test_list_filters(fresh_db):
    fresh_db.log_alert(SCAN)
    fresh_db.log_alert(FLOOD)
    assert len(fresh_db.list_alerts()) == 2
    assert len(fresh_db.list_alerts(alert_type="Flooding")) == 1
    assert len(fresh_db.list_alerts(severity_id=2)) == 1
    assert len(fresh_db.list_alerts(src_ip="192.168.1.5")) == 1
    assert len(fresh_db.list_alerts(status="resolved")) == 0
    assert len(fresh_db.list_alerts(status="open")) == 2
