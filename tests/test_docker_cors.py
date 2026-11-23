"""Tests for the Docker-packaging config: env-overridable CORS/WS origins.

backend.main.get_cors_origins() reads PLEXUS_CORS_ORIGINS (comma-separated)
and feeds both the CORS middleware and ALLOWED_WS_ORIGINS, so the app works
unchanged in vite dev and behind the docker nginx proxy.
"""

import importlib

import pytest


def _reload_main(monkeypatch, env_value):
    """Re-import backend.main with PLEXUS_CORS_ORIGINS set (or unset)."""
    if env_value is None:
        monkeypatch.delenv("PLEXUS_CORS_ORIGINS", raising=False)
    else:
        monkeypatch.setenv("PLEXUS_CORS_ORIGINS", env_value)
    import backend.main as main_mod
    return importlib.reload(main_mod)


def test_cors_origins_default_to_dev(monkeypatch):
    main = _reload_main(monkeypatch, None)
    assert main.get_cors_origins() == [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]
    # The WS handshake allowlist follows the same trusted set.
    assert main.ALLOWED_WS_ORIGINS == {
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    }


def test_cors_origins_from_env(monkeypatch):
    main = _reload_main(
        monkeypatch, "http://localhost:8080, http://127.0.0.1:8080 "
    )
    assert main.get_cors_origins() == [
        "http://localhost:8080",
        "http://127.0.0.1:8080",
    ]
    assert "http://localhost:8080" in main.ALLOWED_WS_ORIGINS


def test_cors_origins_ignores_blank_entries(monkeypatch):
    main = _reload_main(monkeypatch, "http://a:1,, ,http://b:2")
    assert main.get_cors_origins() == ["http://a:1", "http://b:2"]
