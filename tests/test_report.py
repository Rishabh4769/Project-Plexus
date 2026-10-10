"""Tests for backend/report.py — PDF incident-report generation.

Runs against the `fresh_db` fixture (throwaway SQLite file), so the
real network_traffic.db is never touched. No network access needed:
_capture_iface() degrades gracefully when the backend isn't running.
"""

from backend.report import generate_pdf


def _seed_session(db, session_id="report-sess"):
    db.log_packet((
        "2026-01-01T00:00:00", "192.168.1.5", "192.168.1.10",
        40000, 80, 60, "TCP", "S", 64, 12345, "deadbeef", session_id,
    ))
    db.log_packet((
        "2026-01-01T00:00:01", "192.168.1.5", "192.168.1.10",
        40001, 443, 120, "TCP", "SA", 64, 54321, "cafef00d", session_id,
    ))
    db.log_alert((
        "2026-01-01T00:00:02", "192.168.1.5", "Port Scanning",
        "6 distinct ports probed", session_id,
    ))


def test_generate_pdf_returns_pdf_bytes(fresh_db):
    _seed_session(fresh_db)
    pdf = generate_pdf("report-sess")
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF")


def test_generate_pdf_nonempty(fresh_db):
    _seed_session(fresh_db)
    pdf = generate_pdf("report-sess")
    assert len(pdf) > 1000  # a real document, not an empty shell


def test_generate_pdf_empty_session_still_renders(fresh_db):
    # A session with no packets/alerts must not crash the template.
    pdf = generate_pdf("ghost-session")
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF")
