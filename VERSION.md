# PLEXUS — Version History

## v3.0.0 — Security Hardening Release (2026-09-22)

Full security audit and remediation of the v2.0.0 codebase.

### Fixed

- **HIGH** — `/ws/stream` now requires a valid session token (query param, validated
  *before* `accept()`) and rejects cross-origin handshakes. Previously any local
  process — or any website the user visited — could siphon the live packet feed.
- **HIGH** — Login brute-force protection: 5 failed attempts per 60s window, keyed by
  client IP + username (`429 Too Many Requests` beyond that). Successful logins
  reset the budget.
- **HIGH** — The backend no longer runs as root. Raw capture uses a one-time
  `sudo setcap cap_net_raw+ep .venv/bin/python3` instead of `sudo uvicorn`.
- **MEDIUM** — PCAP uploads are streamed to disk in 1 MB chunks and hard-capped at
  100 MB (was: whole file held in RAM, no limit).
- **MEDIUM** — Dependencies upgraded: `scapy 2.6.1 → 2.7.0`,
  `fastapi 0.115.5 → 0.141.1` (resolves 15 starlette/scapy CVEs incl. multipart
  DoS, Range-header CPU exhaustion, Host-header injection).
- **MEDIUM** — Sessions are now persisted in SQLite (only SHA-256 token hashes are
  stored). They survive restarts and are safe with multiple uvicorn workers.
- **MEDIUM** — `Content-Disposition` header injection closed via strict
  `session_id` allowlist on the PDF report endpoint.
- **LOW** — AppleScript notification escaping hardened (backslashes escaped before
  quotes — a trailing `\` could previously break out of the string literal).
- **LOW** — First-user setup is atomic (`BEGIN IMMEDIATE`): two concurrent
  `/api/auth/setup` requests can no longer both succeed.
- **LOW** — ML artifact loader warns when `model.joblib`/`scaler.joblib` are
  group/world-writable (joblib unpickles — a swapped file is code execution).

### Notes

- `GET /api/docs` (Swagger UI) is intentionally left enabled for local development;
  the API only binds `127.0.0.1`.
- The frontend `npm` dependency tree could not be audited in CI (registry blocked);
  run `npm audit` locally before release.

---

## v2.0.0 — ML-NIDS Release (2026-07-23)

Baseline release that was audited for the v3.0.0 hardening pass.

- Real-time Scapy packet capture with BPF filter + interface whitelisting
- Rule-based detection (port scan, flooding) with WebSocket alert streaming
- XGBoost classifier trained on CICIDS2017, with flow aggregation
- Token auth (bcrypt cost 12, 256-bit `secrets` tokens, 8h sliding expiry) —
  sessions kept in process memory (fixed in v3.0.0)
- React + Vite dashboard, SQLite storage, PDF reports, desktop notifications
