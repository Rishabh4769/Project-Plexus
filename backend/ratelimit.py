"""
ratelimit.py — Minimal in-memory sliding-window rate limiter.

Used to throttle authentication endpoints against brute-force attacks:
5 failed attempts per 60-second window, keyed by client IP + username.

Note: the window lives per-process. PLEXUS runs a single uvicorn worker
(the supported deployment), where this is exact. With multiple workers
each enforces its own window — the attack cost still rises substantially.
"""

import time
from collections import defaultdict, deque

MAX_ATTEMPTS   = 5   # failed attempts allowed...
WINDOW_SECONDS = 60  # ...per this window

_attempts: dict[str, deque[float]] = defaultdict(deque)


def _prune(key: str, now: float) -> deque[float]:
    q = _attempts[key]
    while q and q[0] <= now - WINDOW_SECONDS:
        q.popleft()
    return q


def is_rate_limited(key: str) -> bool:
    """True if `key` has exhausted its attempt budget (does not consume one)."""
    return len(_prune(key, time.time())) >= MAX_ATTEMPTS


def record_failed_attempt(key: str) -> None:
    """Consume one attempt from `key`'s budget."""
    _prune(key, time.time()).append(time.time())


def reset_attempts(key: str) -> None:
    """Clear `key`'s budget (e.g. after a successful login)."""
    _attempts.pop(key, None)
