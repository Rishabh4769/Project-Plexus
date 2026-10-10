"""Tests for backend/auth.py — bcrypt passwords and token sessions.

All tests run against the `fresh_db` fixture (throwaway SQLite file),
so the real network_traffic.db is never touched.
"""

import time

import pytest

import backend.auth as auth


# ── Password hashing ───────────────────────────────────────────────── #


def test_hash_verify_roundtrip():
    hashed = auth.hash_password("correct-horse-123")
    assert hashed != "correct-horse-123"  # never stored/returned in plaintext
    assert auth.verify_password("correct-horse-123", hashed) is True


def test_wrong_password_fails():
    hashed = auth.hash_password("right-password")
    assert auth.verify_password("wrong-password", hashed) is False


def test_hash_is_salted():
    # Same password hashed twice must differ (unique salt per hash).
    assert auth.hash_password("same-password") != auth.hash_password("same-password")


# ── Sessions ───────────────────────────────────────────────────────── #


def test_session_create_validate(fresh_db):
    token = auth.create_session("alice")
    assert isinstance(token, str) and len(token) == 64  # 32 random bytes, hex
    assert auth.validate_token(token) == "alice"


def test_revoke_token_invalidates(fresh_db):
    token = auth.create_session("alice")
    auth.revoke_token(token)
    assert auth.validate_token(token) is None


def test_expired_session_rejected(fresh_db):
    token = auth.create_session("alice")
    auth.touch_session(auth._hash_token(token), time.time() - 1)  # force expiry
    assert auth.validate_token(token) is None


@pytest.mark.parametrize("bad", ["", "abc", "g" * 64, "a" * 64, "a" * 63, "a" * 65])
def test_malformed_or_unknown_tokens_rejected(fresh_db, bad):
    # "g"*64 fails the hex check; "a"*64 is well-formed but unknown.
    assert auth.validate_token(bad) is None


# ── Login / first-user setup ───────────────────────────────────────── #


def test_login_success_returns_usable_token(fresh_db):
    ok, _ = auth.register_first_user("admin", "s3cure-password")
    assert ok is True
    ok, token = auth.login("admin", "s3cure-password")
    assert ok is True
    assert auth.validate_token(token) == "admin"


def test_login_wrong_password(fresh_db):
    auth.register_first_user("admin", "s3cure-password")
    assert auth.login("admin", "wrong-password") == (False, "Invalid credentials")


def test_login_unknown_user(fresh_db):
    # Must not leak whether the username exists (same message either way).
    assert auth.login("ghost", "whatever-123") == (False, "Invalid credentials")


def test_register_first_user_second_rejected(fresh_db):
    ok, _ = auth.register_first_user("admin", "s3cure-password")
    assert ok is True
    ok2, _ = auth.register_first_user("second", "another-password")
    assert ok2 is False


def test_register_short_username_rejected(fresh_db):
    ok, msg = auth.register_first_user("ab", "long-enough-password")
    assert ok is False
    assert "3" in msg  # message names the 3–32 character rule


def test_register_short_password_rejected(fresh_db):
    ok, msg = auth.register_first_user("admin", "short")
    assert ok is False
    assert "8" in msg  # message names the 8-character minimum
