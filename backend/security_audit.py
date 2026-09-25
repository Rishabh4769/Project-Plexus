"""
security_audit.py — Detection self-audit for PLEXUS.

Feeds crafted Scapy packets directly into PacketSniffer._packet_callback
(no root, no network, no live capture needed) and asserts the rule-based
detectors behave correctly:

  * port-scan threshold + boundary (6th distinct port fires, 5 do not)
  * flood threshold + boundary (1501st packet fires, 1500 do not)
  * per-IP tracking independence
  * one alert per IP per window (dedup), re-alert after window reset
  * loopback traffic never raises alerts (but is still logged)
  * BPF filter whitelist rejects injection strings
  * update_settings rejects non-positive values
  * ML artifacts present and predict() callable (or clean SKIP)

Run from the project root:

    ./.venv/bin/python3 backend/security_audit.py

Exit code 0 = every check passed. Non-zero = something needs attention
before the demo.
"""

import sys
import time
from pathlib import Path
from queue import Queue, Empty

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scapy.all import IP, TCP  # noqa: E402

from backend.sniffer import PacketSniffer  # noqa: E402

# Production thresholds — the audit verifies the *deployed* config.
SCAN_THRESHOLD = 5      # alert when distinct ports > 5  (i.e. 6th port)
FLOOD_THRESHOLD = 1500  # alert when packet count > 1500 (i.e. 1501st)

results: list[tuple[str, str, str]] = []  # (name, PASS/FAIL/SKIP, detail)


def check(name: str, status: str, detail: str = "") -> None:
    assert status in ("PASS", "FAIL", "SKIP")
    results.append((name, status, detail))
    mark = {"PASS": "PASS", "FAIL": "FAIL", "SKIP": "SKIP"}[status]
    extra = f" — {detail}" if detail and status != "PASS" else ""
    print(f"[{mark}] {name}{extra}")


def make_sniffer(**kw):
    pq, aq = Queue(), Queue()
    args = dict(packet_queue=pq, alert_queue=aq, session_id="audit",
                time_window=10,
                max_ports_scanned=SCAN_THRESHOLD,
                max_packets_flood=FLOOD_THRESHOLD)
    args.update(kw)
    s = PacketSniffer(**args)
    s.running = True  # _packet_callback drops packets unless running
    return s, pq, aq


def syn(src: str, dport: int, dst: str = "192.168.1.10",
        sport: int = 40000) -> "IP":
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")


def drain(q: Queue) -> list:
    out = []
    while True:
        try:
            out.append(q.get_nowait())
        except Empty:
            return out


def feed(s: PacketSniffer, pkts) -> None:
    for p in pkts:
        s._packet_callback(p)


def scan_from(s: PacketSniffer, src: str, n_ports: int,
              start_port: int = 20) -> None:
    feed(s, [syn(src, start_port + i) for i in range(n_ports)])


def flood_from(s: PacketSniffer, src: str, n: int, dport: int = 80) -> None:
    feed(s, [syn(src, dport) for _ in range(n)])


# ── 1. Port-scan threshold ─────────────────────────────────────────── #
s, pq, aq = make_sniffer()
scan_from(s, "203.0.113.7", SCAN_THRESHOLD)          # 5 distinct ports
got = [a for a in drain(aq) if a[2] == "Port Scanning"]
check("scan: 5 distinct ports → no alert", "PASS" if not got else "FAIL",
      f"got {len(got)} alert(s)")

s._packet_callback(syn("203.0.113.7", 25))            # 6th distinct port
got = [a for a in drain(aq) if a[2] == "Port Scanning"]
check("scan: 6th distinct port → exactly 1 alert",
      "PASS" if len(got) == 1 else "FAIL", f"got {len(got)}")
if got:
    check("scan: message names the port count",
          "PASS" if "6 ports" in got[0][3] else "FAIL", got[0][3][:80])

# ── 2. Per-window dedup ────────────────────────────────────────────── #
scan_from(s, "203.0.113.7", 6, start_port=100)        # same IP, new ports
got = [a for a in drain(aq) if a[2] == "Port Scanning"]
check("scan: no second alert for same IP within window",
      "PASS" if not got else "FAIL", f"got {len(got)}")

# ── 3. Per-IP independence ─────────────────────────────────────────── #
scan_from(s, "203.0.113.8", SCAN_THRESHOLD + 1)       # different attacker
got = [a for a in drain(aq) if a[2] == "Port Scanning"]
check("scan: second IP still alerts independently",
      "PASS" if len(got) == 1 and got[0][1] == "203.0.113.8" else "FAIL",
      f"got {len(got)}")

# ── 4. Flood threshold ─────────────────────────────────────────────── #
s, pq, aq = make_sniffer()
flood_from(s, "198.51.100.9", FLOOD_THRESHOLD)        # exactly 1500
got = [a for a in drain(aq) if a[2] == "Flooding"]
check("flood: 1500 packets → no alert", "PASS" if not got else "FAIL",
      f"got {len(got)} alert(s)")

s._packet_callback(syn("198.51.100.9", 80))           # 1501st
got = [a for a in drain(aq) if a[2] == "Flooding"]
check("flood: 1501st packet → exactly 1 alert",
      "PASS" if len(got) == 1 else "FAIL", f"got {len(got)}")
feed(s, [syn("198.51.100.9", 80) for _ in range(50)])
got = [a for a in drain(aq) if a[2] == "Flooding"]
check("flood: no second alert within window",
      "PASS" if not got else "FAIL", f"got {len(got)}")

# ── 5. Scan + flood are independent alert keys ─────────────────────── #
s, pq, aq = make_sniffer()
scan_from(s, "192.0.2.44", SCAN_THRESHOLD + 1)
flood_from(s, "192.0.2.44", FLOOD_THRESHOLD + 1)      # same IP floods too
types = sorted(a[2] for a in drain(aq))
check("scan+flood: same IP raises both alert types",
      "PASS" if types == ["Flooding", "Port Scanning"] else "FAIL",
      f"got {types}")

# ── 6. Loopback exclusion (regression: no self-flagging) ───────────── #
s, pq, aq = make_sniffer()
feed(s, [syn("127.0.0.1", 8000 + i, dst="127.0.0.1") for i in range(20)])
feed(s, [syn("127.0.0.1", 3000, dst="127.0.0.1") for _ in range(2000)])
got = drain(aq)
logged = drain(pq)
check("loopback: 2000 pkts / 20 ports → zero alerts",
      "PASS" if not got else "FAIL", f"got {len(got)} alert(s)")
check("loopback: packets still logged for forensics",
      "PASS" if len(logged) == 2020 else "FAIL", f"logged {len(logged)}")

# ── 7. Window reset re-arms alerts ─────────────────────────────────── #
s, pq, aq = make_sniffer()
scan_from(s, "203.0.113.99", SCAN_THRESHOLD + 1)
n1 = len([a for a in drain(aq) if a[2] == "Port Scanning"])
s._last_cleanup = time.time() - s.time_window - 1    # force window expiry
s._packet_callback(syn("198.51.100.1", 80))          # any packet triggers cleanup
scan_from(s, "203.0.113.99", SCAN_THRESHOLD + 1)
n2 = len([a for a in drain(aq) if a[2] == "Port Scanning"])
check("window reset: scanner re-alerts in new window",
      "PASS" if (n1, n2) == (1, 1) else "FAIL", f"alerts per window: {n1}, {n2}")

# ── 8. BPF whitelist blocks injection ──────────────────────────────── #
s, _, _ = make_sniffer(filter_exp="tcp and host 1.2.3.4; rm -rf /")
check("bpf: compound/injection filter rejected",
      "PASS" if s.filter is None else "FAIL", f"filter={s.filter!r}")
s, _, _ = make_sniffer(filter_exp="TCP")
check("bpf: plain 'tcp' accepted (normalised)",
      "PASS" if s.filter == "tcp" else "FAIL", f"filter={s.filter!r}")

# ── 9. Settings validation ─────────────────────────────────────────── #
s, _, _ = make_sniffer()
s.update_settings(time_window=-5, max_ports_scanned=0, max_packets_flood=-1)
check("settings: non-positive values rejected",
      "PASS" if (s.time_window, s.max_ports_scanned, s.max_packets_flood)
      == (10, SCAN_THRESHOLD, FLOOD_THRESHOLD) else "FAIL",
      f"got {(s.time_window, s.max_ports_scanned, s.max_packets_flood)}")

# ── 10. ML artifacts ───────────────────────────────────────────────── #
s, _, _ = make_sniffer()
loader = s.model_loader
if loader.model is None:
    check("ml: artifacts load", "SKIP",
          "model.joblib/scaler/spec missing — ML path inactive, rules only")
else:
    try:
        feats = {f: 0.0 for f in loader.selected_features}
        is_attack, prob = loader.predict(feats)
        ok = isinstance(prob, (int, float)) and 0.0 <= prob <= 1.0
        check("ml: predict() returns sane verdict", "PASS" if ok else "FAIL",
              f"is_attack={is_attack}, prob={prob}")
    except Exception as exc:  # noqa: BLE001
        check("ml: predict() returns sane verdict", "FAIL", str(exc)[:100])

# ── Summary ────────────────────────────────────────────────────────── #
n_pass = sum(1 for _, st, _ in results if st == "PASS")
n_fail = sum(1 for _, st, _ in results if st == "FAIL")
n_skip = sum(1 for _, st, _ in results if st == "SKIP")
print(f"\n{len(results)} checks: {n_pass} passed, {n_fail} failed, {n_skip} skipped")
sys.exit(1 if n_fail else 0)
