"""Detection-engine tests for backend/sniffer.py.

Ports the checks from backend/security_audit.py into pytest: crafted
Scapy packets are fed straight into PacketSniffer._packet_callback —
no root, no network, no live capture needed.

Alert tuples on the alert queue are (timestamp, src_ip, alert_type,
description, session_id).
"""

import time
from queue import Queue, Empty

import pytest
from scapy.all import IP, TCP

from backend.sniffer import PacketSniffer

SCAN_THRESHOLD = 5     # alert when distinct ports > 5  (i.e. the 6th port)
FLOOD_THRESHOLD = 1500  # alert when packet count > 1500 (i.e. 1501st)


def syn(src, dport, dst="192.168.1.10", sport=40000):
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")


def make_sniffer(**kw):
    pq, aq = Queue(), Queue()
    args = dict(packet_queue=pq, alert_queue=aq, session_id="pytest",
                time_window=10,
                max_ports_scanned=SCAN_THRESHOLD,
                max_packets_flood=FLOOD_THRESHOLD)
    args.update(kw)
    sniffer = PacketSniffer(**args)
    sniffer.running = True  # _packet_callback drops packets unless running
    return sniffer, pq, aq


def drain(q):
    out = []
    while True:
        try:
            out.append(q.get_nowait())
        except Empty:
            return out


def feed(sniffer, packets):
    for p in packets:
        sniffer._packet_callback(p)


def scan_from(sniffer, src, n_ports, start_port=20):
    feed(sniffer, [syn(src, start_port + i) for i in range(n_ports)])


def flood_from(sniffer, src, n, dport=80):
    feed(sniffer, [syn(src, dport) for _ in range(n)])


def alerts_of(aq, alert_type):
    return [a for a in drain(aq) if a[2] == alert_type]


# ── Port-scan threshold ────────────────────────────────────────────── #


def test_scan_five_ports_no_alert():
    s, pq, aq = make_sniffer()
    scan_from(s, "203.0.113.7", SCAN_THRESHOLD)
    assert alerts_of(aq, "Port Scanning") == []


def test_scan_sixth_port_fires_exactly_once():
    s, pq, aq = make_sniffer()
    scan_from(s, "203.0.113.7", SCAN_THRESHOLD)
    s._packet_callback(syn("203.0.113.7", 25))  # 6th distinct port
    got = alerts_of(aq, "Port Scanning")
    assert len(got) == 1
    assert "6 ports" in got[0][3]  # message names the port count


def test_scan_no_second_alert_same_ip_within_window():
    s, pq, aq = make_sniffer()
    scan_from(s, "203.0.113.7", SCAN_THRESHOLD + 1)
    assert len(alerts_of(aq, "Port Scanning")) == 1
    scan_from(s, "203.0.113.7", 6, start_port=100)  # same IP, fresh ports
    assert alerts_of(aq, "Port Scanning") == []  # deduped within window


def test_scan_second_ip_alerts_independently():
    s, pq, aq = make_sniffer()
    scan_from(s, "203.0.113.7", SCAN_THRESHOLD + 1)
    assert len(alerts_of(aq, "Port Scanning")) == 1  # first attacker alerts
    scan_from(s, "203.0.113.8", SCAN_THRESHOLD + 1)
    got = alerts_of(aq, "Port Scanning")
    assert len(got) == 1
    assert got[0][1] == "203.0.113.8"


def test_window_reset_rearms_scan_alert():
    s, pq, aq = make_sniffer()
    scan_from(s, "203.0.113.99", SCAN_THRESHOLD + 1)
    assert len(alerts_of(aq, "Port Scanning")) == 1
    s._last_cleanup = time.time() - s.time_window - 1  # force window expiry
    s._packet_callback(syn("198.51.100.1", 80))  # any packet triggers cleanup
    scan_from(s, "203.0.113.99", SCAN_THRESHOLD + 1)
    assert len(alerts_of(aq, "Port Scanning")) == 1


# ── Flood threshold ────────────────────────────────────────────────── #


def test_flood_1500_packets_no_alert():
    s, pq, aq = make_sniffer()
    flood_from(s, "198.51.100.9", FLOOD_THRESHOLD)
    assert alerts_of(aq, "Flooding") == []


def test_flood_1501st_packet_fires_exactly_once():
    s, pq, aq = make_sniffer()
    flood_from(s, "198.51.100.9", FLOOD_THRESHOLD)
    s._packet_callback(syn("198.51.100.9", 80))  # 1501st
    assert len(alerts_of(aq, "Flooding")) == 1
    feed(s, [syn("198.51.100.9", 80) for _ in range(50)])
    assert alerts_of(aq, "Flooding") == []  # deduped within window


def test_scan_and_flood_alert_independently():
    s, pq, aq = make_sniffer()
    scan_from(s, "192.0.2.44", SCAN_THRESHOLD + 1)
    flood_from(s, "192.0.2.44", FLOOD_THRESHOLD + 1)
    types = sorted(a[2] for a in drain(aq))
    assert types == ["Flooding", "Port Scanning"]


# ── Loopback exclusion ─────────────────────────────────────────────── #


def test_loopback_never_alerts_but_still_logged():
    s, pq, aq = make_sniffer()
    feed(s, [syn("127.0.0.1", 8000 + i, dst="127.0.0.1") for i in range(20)])
    feed(s, [syn("127.0.0.1", 3000, dst="127.0.0.1") for _ in range(2000)])
    assert drain(aq) == []  # zero alerts for self-traffic
    assert len(drain(pq)) == 2020  # ...but packets are still logged


# ── BPF filter whitelist ───────────────────────────────────────────── #


def test_bpf_rejects_injection_string():
    s, _, _ = make_sniffer(filter_exp="tcp and host 1.2.3.4; rm -rf /")
    assert s.filter is None


def test_bpf_accepts_plain_tcp_normalised():
    s, _, _ = make_sniffer(filter_exp="TCP")
    assert s.filter == "tcp"


def test_bpf_rejects_unknown_filter():
    s, _, _ = make_sniffer(filter_exp="port 80 and host 1.1.1.1")
    assert s.filter is None


# ── Settings validation ───────────────────────────────────────────── #


def test_update_settings_rejects_non_positive():
    s, _, _ = make_sniffer()
    s.update_settings(time_window=-5, max_ports_scanned=0, max_packets_flood=-1)
    assert (s.time_window, s.max_ports_scanned, s.max_packets_flood) == \
        (10, SCAN_THRESHOLD, FLOOD_THRESHOLD)


def test_update_settings_accepts_positive():
    s, _, _ = make_sniffer()
    s.update_settings(time_window=30, max_ports_scanned=10, max_packets_flood=500)
    assert (s.time_window, s.max_ports_scanned, s.max_packets_flood) == (30, 10, 500)


# ── ML artifacts ───────────────────────────────────────────────────── #


def test_ml_artifacts_predict_sane_verdict():
    s, _, _ = make_sniffer()
    loader = s.model_loader
    if loader.model is None:
        pytest.skip("model.joblib/scaler/spec missing — ML path inactive")
    feats = {f: 0.0 for f in loader.selected_features}
    is_attack, prob = loader.predict(feats)
    assert isinstance(prob, (int, float)) and 0.0 <= prob <= 1.0
