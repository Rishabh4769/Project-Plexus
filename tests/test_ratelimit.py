"""Tests for backend/ratelimit.py — in-memory sliding-window rate limiter.

Policy under test: 5 failed attempts allowed per 60-second window,
keyed by client IP + username. The 6th attempt trips the limiter.
"""

import time

import pytest

import backend.ratelimit as rl


@pytest.fixture(autouse=True)
def _clean(clean_ratelimit):
    return clean_ratelimit


class FakeClock:
    """Deterministic clock so window-expiry tests don't sleep."""

    def __init__(self, start=1_000_000.0):
        self.now = start

    def time(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture()
def clock(monkeypatch):
    fake = FakeClock()
    monkeypatch.setattr(rl.time, "time", fake.time)
    return fake


def test_five_attempts_allowed():
    for _ in range(5):
        assert rl.is_rate_limited("10.0.0.1:alice") is False
        rl.record_failed_attempt("10.0.0.1:alice")


def test_sixth_attempt_is_limited():
    for _ in range(5):
        rl.record_failed_attempt("10.0.0.1:alice")
    assert rl.is_rate_limited("10.0.0.1:alice") is True


def test_check_does_not_consume_budget():
    # is_rate_limited must be a pure read — polling it must not burn attempts.
    for _ in range(20):
        assert rl.is_rate_limited("10.0.0.1:alice") is False
    rl.record_failed_attempt("10.0.0.1:alice")
    assert rl.is_rate_limited("10.0.0.1:alice") is False


def test_reset_clears_budget():
    for _ in range(5):
        rl.record_failed_attempt("10.0.0.1:alice")
    assert rl.is_rate_limited("10.0.0.1:alice") is True
    rl.reset_attempts("10.0.0.1:alice")
    assert rl.is_rate_limited("10.0.0.1:alice") is False


def test_keys_are_independent():
    for _ in range(5):
        rl.record_failed_attempt("10.0.0.1:alice")
    assert rl.is_rate_limited("10.0.0.1:alice") is True
    # different user, same IP — unaffected
    assert rl.is_rate_limited("10.0.0.1:bob") is False
    # same user, different IP — unaffected
    assert rl.is_rate_limited("10.0.0.2:alice") is False


def test_window_expiry_restores_budget(clock):
    for _ in range(5):
        rl.record_failed_attempt("10.0.0.1:alice")
    assert rl.is_rate_limited("10.0.0.1:alice") is True
    clock.advance(61)  # window is 60s
    assert rl.is_rate_limited("10.0.0.1:alice") is False


def test_partial_window_prunes_old_attempts(clock):
    for _ in range(3):
        rl.record_failed_attempt("10.0.0.1:alice")
    clock.advance(61)  # those 3 fall out of the window
    for _ in range(2):
        rl.record_failed_attempt("10.0.0.1:alice")
    assert rl.is_rate_limited("10.0.0.1:alice") is False
    for _ in range(3):
        rl.record_failed_attempt("10.0.0.1:alice")
    assert rl.is_rate_limited("10.0.0.1:alice") is True


def test_reset_unknown_key_is_safe():
    rl.reset_attempts("never-seen-key")  # must not raise
    assert rl.is_rate_limited("never-seen-key") is False
