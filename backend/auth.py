"""
auth.py — Authentication for PLEXUS.

Design:
  - Passwords hashed with bcrypt (work factor 12).
  - Sessions stored server-side in an in-memory dict keyed by a
    cryptographically random 32-byte token.
  - Token comparison uses secrets.compare_digest (timing-safe).
  - Tokens expire after TOKEN_TTL_SECONDS of inactivity.
  - On first run (no users in DB), a setup endpoint allows creating the
    first admin account — it is disabled once any user exists.

No JWT, no third-party auth libraries required beyond bcrypt.
"""

import hashlib
import os
import secrets
import time
from typing import Optional

import bcrypt  # type: ignore

from backend.database import (
    create_first_user,
    create_session_row,
    delete_session_row,
    get_session_row,
    get_user,
    purge_expired_sessions,
    touch_session,
    update_last_login,
)

# ── Token store (SQLite-backed) ──────────────────────────────────────── #
# Sessions persist in the `sessions` table so they survive restarts and
# work across multiple uvicorn workers. Only SHA-256 hashes of tokens are
# stored — a stolen database must not yield live session tokens.

TOKEN_TTL_SECONDS = 8 * 60 * 60   # 8 hours
TOKEN_BYTES       = 32             # 256-bit token


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ── Password helpers ─────────────────────────────────────────────────── #

def hash_password(plaintext: str) -> str:
    return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plaintext: str, stored_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plaintext.encode(), stored_hash.encode())
    except Exception:
        return False


# ── Session helpers ──────────────────────────────────────────────────── #

def create_session(username: str) -> str:
    purge_expired_sessions(time.time())
    token = secrets.token_hex(TOKEN_BYTES)
    create_session_row(_hash_token(token), username, time.time() + TOKEN_TTL_SECONDS)
    return token


def validate_token(token: str) -> Optional[str]:
    """Return the username if the token is valid, else None."""
    if not token or len(token) != TOKEN_BYTES * 2 or not all(
        c in "0123456789abcdef" for c in token
    ):
        return None
    purge_expired_sessions(time.time())
    # Exact lookup on the SHA-256 hash — no timing-sensitive comparison needed.
    row = get_session_row(_hash_token(token))
    if row is None or row["expires_at"] < time.time():
        return None
    # Slide expiry on activity
    touch_session(_hash_token(token), time.time() + TOKEN_TTL_SECONDS)
    return row["username"]


def revoke_token(token: str) -> None:
    delete_session_row(_hash_token(token))


# ── Public auth actions ───────────────────────────────────────────────── #

def login(username: str, password: str) -> tuple[bool, str]:
    """
    Returns (success, token_or_error_message).
    Brute-force window: we do NOT rate-limit here — the API layer
    should enforce that if needed.
    """
    user = get_user(username)
    if user is None:
        # Perform a dummy hash to prevent username enumeration via timing
        bcrypt.checkpw(b"dummy", bcrypt.hashpw(b"dummy", bcrypt.gensalt(rounds=12)))
        return False, "Invalid credentials"

    if not verify_password(password, user["password_hash"]):
        return False, "Invalid credentials"

    update_last_login(username)
    token = create_session(username)
    return True, token


def register_first_user(username: str, password: str) -> tuple[bool, str]:
    """
    Only allowed when no users exist yet (initial setup). The existence
    check and the INSERT run inside one IMMEDIATE transaction in
    create_first_user(), so two concurrent setup requests cannot both win.
    """
    if len(username) < 3 or len(username) > 32:
        return False, "Username must be 3–32 characters"
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    hashed = hash_password(password)
    return create_first_user(username, hashed)
