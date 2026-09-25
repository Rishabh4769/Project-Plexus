# PLEXUS — Version History

## v3.0.1 — Detection Reliability + Laya Beta (unreleased, 2026-09-24)

Deadline-driven repair pass on the v3.0.0 codebase. Not yet gated — do not
tag until the full Mac test gate passes.

### Fixed

- **Capture screen empty / no live data** — `useWebSocket` was defined but
  never called by `App.jsx`, so no socket ever opened; and `useCapture`'s
  `update` handler bumped the counters but discarded `msg.packets` /
  `msg.alerts`. Both wired up; packet rows now stream live.
- **Duplicate alerts (3–6× per detection)** — the WebSocket hook could open
  several concurrent sockets per tab (effect re-runs + a reconnect timer
  racing the cleanup), and every socket received the same broadcast.
  Rewrote `useWebSocket` (handler via ref, per-effect cancel flag, timer
  cleanup, reconnect only on auth change — exactly one socket per tab)
  and added a signature-based alert dedup safety net in `useCapture`.
- **Flood threshold default wrong** — `max_packets_flood` defaulted to 30;
  corrected to **1500** (frontend, `CaptureStartRequest`, `PacketSniffer`).
  With the 10 s window the rule fires past 1500 packets from one source
  (≈ >150 pkt/s).
- **Graph showed alert dots on zero-alert buckets** — alert points now
  render only where the alert count is non-zero.
- **False port-scan alerts from 127.0.0.1** — when capturing loopback/
  all interfaces, PLEXUS flagged its own dashboard chatter (browser ↔
  Vite, frontend ↔ backend API/WS over ephemeral ports) as a port scan.
  Loopback sources (`127.0.0.0/8`, `::1`) are now excluded from the
  scan/flood heuristics; their packets are still logged.

### Added

- **Traffic-graph severity colours** — alert dots are yellow for normal
  (Port Scanning) and red for critical (Flooding, ML NIDS Anomaly);
  critical wins when both share a time bucket (`get_graph_data` now
  returns `alert_severity`).
- **Laya second-opinion scorer (beta)** — `ml/inference/laya_scorer.py`:
  `convaiinnovations/laya-typed-decisions` (ModernBERT-large, 421M)
  re-scores XGBoost-flagged flows with an attack probability + category
  note. Lazy-loads on first flagged flow, failure-latched, kill switch
  `PLEXUS_DISABLE_LAYA=1`. Never replaces XGBoost; results labelled
  beta/experimental. See `flow.md` for the pipeline.
- **`flow.md`** — detection workflows, data-flow diagrams, severity
  mapping, and measured latency notes.

### Known issues (carried, not yet fixed)

- Laya scoring still runs synchronously inside the packet callback —
  move to a bounded worker queue before enabling it in the demo.
- `stop()` only flips a flag; a quiet interface can leave the sniff
  thread parked until the next packet (harmless: the callback no-ops
  once stopped).
- The frontend `max_packets` auto-stop setting is a leftover experiment,
  not an attack threshold — remove or relabel before release.
- Missing auth returns 422 (required header) instead of 401 on some
  routes; `/interfaces` failures are silently swallowed to `[]`.
- `PLEXUS.sh` still labels itself v2.0; macOS capture-privilege story
  (`setcap` is Linux-only) is unresolved.

---

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

---

## v1.0.0 — CLI Capture & Analysis (2026-07-13)

Original baseline: terminal-based packet capturing and offline analysis.
No web UI, no ML — raw Scapy capture from the command line with
text-based packet inspection and basic traffic analysis.
