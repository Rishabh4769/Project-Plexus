# CHANGES — Security Hardening Log

This file records security hardening work on PLEXUS driven by current
vulnerability intelligence: newly disclosed CVEs, CISA KEV additions and
supply-chain incidents, assessed against the configuration actually in this
repository. It is the security counterpart to `VERSION.md` (feature and
release history).

Each entry states what was disclosed, whether PLEXUS as configured is
exposed, what changed (or is scheduled to change), and how the change is
verified. Statuses used:

- **Applied** — the change is in the codebase.
- **Scheduled** — the change is decided and documented here; it lands with
  the named work phase.
- **Assessed — no action** — checked against the current configuration;
  not exposed, nothing to change.

---

## 2026-11-20 — NGINX "nginx2root" cluster

**Disclosure.** On 18 Nov 2026 F5 fixed five NGINX flaws. Fixed releases:
**1.30.7** (stable) and **1.31.9** (mainline). No in-the-wild exploitation
reported as of 19 Nov 2026; none of the five is in CISA KEV. A public
Rapid7 proof of concept exists for the lead flaw.

**Assessment** (against `frontend/nginx.conf` and `frontend/Dockerfile`):

| CVE | Requirement to trigger | PLEXUS configuration | Exposed |
|---|---|---|---|
| CVE-2026-123007 — HTTP/2 flow-control integer underflow, unauthenticated RCE (CVSS 4.0: 9.2) | HTTP/2 enabled | `listen 80;` only — no HTTP/2, no TLS, no 443 | No |
| CVE-2026-123633 — HTTP/2 proxy use-after-free (9.2) | HTTP/2 + `proxy_pass` + worker near `worker_connections` | `proxy_pass http://backend:8000` exists, but HTTP/2 is off, so the chain cannot start | No — becomes live if HTTP/2 is ever enabled |
| CVE-2026-123634 — resolver use-after-free | `resolver` directive + request-derived `proxy_pass` + mirror/SSI subrequest | Fixed `proxy_pass`; no `resolver`, no mirror/SSI | No |
| CVE-2026-121810 — HTTP/3 use-after-free | HTTP/3 enabled | Not enabled | No |
| CVE-2026-113425 — mail proxy use-after-free | Mail proxy (`proxy on` + `auth_http`) | No mail proxy | No |

**Verdict: PLEXUS as configured is not exposed to any of the five flaws.**

**Hardening change — pin the frontend base image.** `frontend/Dockerfile`
used the floating tag `nginx:alpine`, which pulls whatever that tag points
to at build time. It is pinned to the patched stable release:

```diff
-FROM nginx:alpine
+FROM nginx:1.30.7-alpine
```

1.30.7 (stable) is chosen over 1.31.9 (mainline): same fix, stable branch
is the right default for this frontend.
**Status: Scheduled** — lands in the same commit as the Docker phase work
(Docker Desktop reinstall is pending, so no image can build yet). The
documentation is committed first so the decision and its reasoning are on
record.

**Defence in depth — explicit `http2 off;`.** Adding `http2 off;` to the
`server` block of `frontend/nginx.conf` documents that HTTP/2 stays off
even if TLS is added later. Not required today (HTTP/2 is off by default);
it matters because `proxy_pass` is already present, so CVE-2026-123633
would become exploitable the moment HTTP/2 were enabled without it.
**Status: Scheduled**, same Docker phase commit.

**Verification** (when the Docker phase runs):

```bash
docker compose build --no-cache frontend
docker run --rm plexus-frontend nginx -v
# expect: nginx version: nginx/1.30.7
docker compose up -d
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/
# expect: 200
```

---

## 2026-11-20 — Same-cycle intelligence sweep

Other items from the 18–20 Nov 2026 vulnerability cycle, checked against
this project's stack. **Status for all: Assessed — no action.**

- **Java4Shell, CVE-2026-114938** (OpenJDK Base64 decoder RCE) —
  demonstrated against Jira, Jenkins and Keycloak on AVX-512 x86 systems.
  PLEXUS runs no Java and none of those products. Not applicable.
- **Microsoft agent-framework PyPI hijack** (malicious 1.26.1 / 1.26.2,
  17 Nov 2026, credential-stealing `.pth` hook) — the package is not a
  dependency of this project and appears nowhere in its sources. No
  credential rotation required.
- **CISA KEV additions, Nov 2026** — Synology DSM (CVE-2024-10441),
  Apache Axis (CVE-2026-90436), REDCap (CVE-2026-90817), LiteLLM
  (CVE-2026-40217) and Apache Roller RCE (CVE-2026-129448): none of these
  products is present in this stack.
- **VMware vCenter zero-day, CVE-2026-123890** (exploited since
  September 2026) — no vCenter in this environment. Not applicable.

---

## Baseline

The v3.0.0 release (22 Sep 2026) was the dedicated security hardening
release: authenticated WebSocket stream with Origin validation, login
brute-force rate limiting, backend running as non-root with `CAP_NET_RAW`
instead of sudo, streamed and size-capped PCAP uploads, dependency updates
leaving `pip-audit` clean, hashed persistent sessions, and a
Content-Disposition injection fix. Full detail in `VERSION.md` and commit
`6165111`. Entries above this line continue that record for vulnerabilities
disclosed after the release.
