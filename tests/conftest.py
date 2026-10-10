"""Shared pytest fixtures for the PLEXUS test suite.

- Puts the project root on sys.path so `backend` / `ml` import cleanly.
- `fresh_db`: points backend.database at a throwaway SQLite file per test
  and initialises the schema — no test ever touches network_traffic.db.
- `clean_ratelimit`: empties the in-memory rate-limit buckets between tests.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture()
def fresh_db(tmp_path, monkeypatch):
    import backend.database as db

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test_traffic.db")
    db.init_db()
    return db


@pytest.fixture()
def clean_ratelimit():
    import backend.ratelimit as rl

    rl._attempts.clear()
    yield rl
    rl._attempts.clear()
