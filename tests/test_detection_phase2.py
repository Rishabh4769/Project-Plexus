"""Phase-2 detection tests: SYN flood, DNS tunneling, ARP spoofing,
incident correlation (backend/incidents.py), and blocklist enrichment
(backend/threatintel.py).

Same harness as test_detection.py: crafted Scapy packets fed straight
into PacketSniffer._packet_callback — no root, no network.

Alert tuples on the alert queue are (timestamp, src_ip, alert_type,
description, session_id).
"""

import time
from queue import Queue, Empty

import pytest
from scapy.all import IP, TCP, UDP, DNS, DNSQR, ARP, Ether

from backend.sniffer import PacketSniffer, _dns_entropy
from backend import incidents
from backend import threatintel

SYN_FLOOD_THRESHOLD = 500  # alert when SYN count >= 500 (i.e. the 500th SYN)


def syn(src, dport=80, dst="192.168.1.10", sport=40000, flags="S"):
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)


def dns_query(src, qname, dst="8.8.8.8"):
    return (
        IP(src=src, dst=dst)
        / UDP(sport=5353, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=qname))
    )


def arp_reply(ip, mac):
    return Ether() / ARP(op=2, psrc=ip, hwsrc=mac)


def make_sniffer(**kw):
    pq, aq = Queue(), Queue()
    args = dict(packet_queue=pq, alert_queue=aq, session_id="pytest",
                time_window=10,
                max_ports_scanned=5,
                max_packets_flood=1500,
                max_syn_flood=SYN_FLOOD_THRESHOLD)
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


def alerts_of(aq, alert_type):
    return [a for a in drain(aq) if a[2] == alert_type]


# ── SYN flood ──────────────────────────────────────────────────────── #


def test_syn_499_no_alert():
    s, pq, aq = make_sniffer()
    feed(s, [syn("203.0.113.50") for _ in range(SYN_FLOOD_THRESHOLD - 1)])
    assert drain(aq) == []  # nothing at all: no scan, no flood, no SYN alert


def test_syn_500th_fires_exactly_once():
    s, pq, aq = make_sniffer()
    feed(s, [syn("203.0.113.50") for _ in range(SYN_FLOOD_THRESHOLD - 1)])
    s._packet_callback(syn("203.0.113.50"))  # 500th SYN
    got = alerts_of(aq, "SYN Flood")
    assert len(got) == 1
    assert "500 SYN" in got[0][3]  # message names the SYN count


def test_syn_no_second_alert_within_window():
    s, pq, aq = make_sniffer()
    feed(s, [syn("203.0.113.50") for _ in range(SYN_FLOOD_THRESHOLD)])
    assert len(alerts_of(aq, "SYN Flood")) == 1
    feed(s, [syn("203.0.113.50") for _ in range(50)])
    assert alerts_of(aq, "SYN Flood") == []  # deduped within window


def test_syn_ack_packets_not_counted():
    # SYN+ACK (and plain ACK) must not feed the SYN-flood counter.
    s, pq, aq = make_sniffer()
    feed(s, [syn("203.0.113.51", flags="SA") for _ in range(SYN_FLOOD_THRESHOLD)])
    assert alerts_of(aq, "SYN Flood") == []


# ── DNS tunneling ──────────────────────────────────────────────────── #


def test_dns_normal_query_no_alert():
    s, pq, aq = make_sniffer()
    feed(s, [dns_query("203.0.113.60", "www.example.com")])
    assert drain(aq) == []


def test_dns_long_qname_fires():
    s, pq, aq = make_sniffer()
    long_name = "a" * 51 + ".example.com"  # qname 63 chars > 50
    s._packet_callback(dns_query("203.0.113.60", long_name))
    got = alerts_of(aq, "DNS Tunneling")
    assert len(got) == 1
    assert "DNS tunneling" in got[0][3]


def test_dns_many_labels_fires():
    s, pq, aq = make_sniffer()
    many = "a.b.c.d.e.f.example.com"  # 8 labels > 5
    s._packet_callback(dns_query("203.0.113.61", many))
    assert len(alerts_of(aq, "DNS Tunneling")) == 1


def test_dns_no_second_alert_within_window():
    s, pq, aq = make_sniffer()
    long_name = "a" * 51 + ".example.com"
    feed(s, [dns_query("203.0.113.60", long_name) for _ in range(3)])
    assert len(alerts_of(aq, "DNS Tunneling")) == 1  # deduped within window


def test_dns_entropy_helper():
    assert _dns_entropy("") == 0.0
    assert _dns_entropy("aaaaaaaa") == pytest.approx(0.0)
    # 16 distinct symbols -> exactly 4 bits
    assert _dns_entropy("abcdefghijklmnop") == pytest.approx(4.0)
    # 24 distinct symbols -> log2(24) ~= 4.58 bits, over the 4.5 threshold
    assert _dns_entropy("abcdefghijklmnopqrstuvwx") > 4.5


# ── ARP spoofing ───────────────────────────────────────────────────── #


def test_arp_first_sighting_quiet():
    s, pq, aq = make_sniffer()
    s._packet_callback(arp_reply("192.168.1.5", "aa:bb:cc:dd:ee:01"))
    assert drain(aq) == []  # learning a new mapping is not an attack


def test_arp_consistent_mapping_quiet():
    s, pq, aq = make_sniffer()
    feed(s, [arp_reply("192.168.1.5", "aa:bb:cc:dd:ee:01") for _ in range(3)])
    assert drain(aq) == []


def test_arp_mac_change_fires_once():
    s, pq, aq = make_sniffer()
    s._packet_callback(arp_reply("192.168.1.5", "aa:bb:cc:dd:ee:01"))
    s._packet_callback(arp_reply("192.168.1.5", "aa:bb:cc:dd:ee:02"))  # MITM?
    got = alerts_of(aq, "ARP Spoofing")
    assert len(got) == 1
    assert "possible MITM" in got[0][3]
    assert got[0][1] == "192.168.1.5"  # alert attributed to the claimed IP


def test_arp_gratuitous_new_ip_quiet():
    s, pq, aq = make_sniffer()
    s._packet_callback(arp_reply("192.168.1.9", "aa:bb:cc:dd:ee:09"))
    assert drain(aq) == []  # unseen IP: learned, not alerted


def test_arp_zero_ip_ignored():
    s, pq, aq = make_sniffer()
    s._packet_callback(arp_reply("0.0.0.0", "aa:bb:cc:dd:ee:ff"))
    assert drain(aq) == []
    assert "0.0.0.0" not in s._arp_table  # never learned


def test_arp_request_ignored():
    s, pq, aq = make_sniffer()
    who_has = Ether() / ARP(op=1, psrc="192.168.1.5", hwsrc="aa:bb:cc:dd:ee:01")
    s._packet_callback(who_has)  # who-has makes no claim
    assert drain(aq) == []


# ── Settings validation ────────────────────────────────────────────── #


def test_update_settings_rejects_non_positive_syn():
    s, _, _ = make_sniffer()
    s.update_settings(max_syn_flood=0)
    assert s.max_syn_flood == SYN_FLOOD_THRESHOLD
    s.update_settings(max_syn_flood=-10)
    assert s.max_syn_flood == SYN_FLOOD_THRESHOLD


def test_update_settings_accepts_positive_syn():
    s, _, _ = make_sniffer()
    s.update_settings(max_syn_flood=100)
    assert s.max_syn_flood == 100


# ── Incident correlation ───────────────────────────────────────────── #


def _a(ts, ip, atype):
    return (ts, ip, atype, f"{atype} from {ip}", "pytest")


def test_incident_single_scan_is_medium():
    incs = incidents.correlate([_a("2026-01-01 00:00:00", "10.0.0.1", "Port Scanning")])
    assert len(incs) == 1
    assert incs[0]["severity"] == "medium"
    assert incs[0]["alert_types"] == ["Port Scanning"]
    assert incs[0]["count"] == 1


def test_incident_scan_plus_flood_is_high():
    incs = incidents.correlate([
        _a("2026-01-01 00:00:00", "10.0.0.1", "Port Scanning"),
        _a("2026-01-01 00:00:30", "10.0.0.1", "Flooding"),
    ])
    assert incs[0]["severity"] == "high"
    assert incs[0]["alert_types"] == ["Flooding", "Port Scanning"]


def test_incident_three_types_is_critical():
    incs = incidents.correlate([
        _a("2026-01-01 00:00:00", "10.0.0.1", "Port Scanning"),
        _a("2026-01-01 00:00:30", "10.0.0.1", "Flooding"),
        _a("2026-01-01 00:01:00", "10.0.0.1", "SYN Flood"),
    ])
    assert incs[0]["severity"] == "critical"
    assert incs[0]["count"] == 3


def test_incident_arp_spoofing_alone_is_critical():
    incs = incidents.correlate([_a("2026-01-01 00:00:00", "10.0.0.1", "ARP Spoofing")])
    assert incs[0]["severity"] == "critical"


def test_incident_dns_tunneling_alone_is_high():
    incs = incidents.correlate([_a("2026-01-01 00:00:00", "10.0.0.1", "DNS Tunneling")])
    assert incs[0]["severity"] == "high"


def test_incident_unknown_single_type_is_low():
    incs = incidents.correlate([_a("2026-01-01 00:00:00", "10.0.0.1", "ML NIDS Anomaly")])
    assert incs[0]["severity"] == "low"


def test_incident_window_splits_stale_attackers():
    incs = incidents.correlate([
        _a("2026-01-01 00:00:00", "10.0.0.1", "Port Scanning"),
        _a("2026-01-01 00:10:00", "10.0.0.1", "Port Scanning"),  # 600s > window
    ], window=300)
    assert len(incs) == 2
    assert incs[0]["first_seen"] == "2026-01-01 00:00:00"
    assert incs[1]["first_seen"] == "2026-01-01 00:10:00"


def test_incident_groups_by_ip():
    incs = incidents.correlate([
        _a("2026-01-01 00:00:00", "10.0.0.1", "Port Scanning"),
        _a("2026-01-01 00:00:10", "10.0.0.2", "Flooding"),
    ])
    assert {i["src_ip"] for i in incs} == {"10.0.0.1", "10.0.0.2"}


# ── Threat-intel enrichment ────────────────────────────────────────── #


def test_blocklisted_ip_flagged():
    assert threatintel.is_blocklisted("203.0.113.200") is True


def test_unlisted_ip_not_flagged():
    assert threatintel.is_blocklisted("8.8.8.8") is False


def test_enrich_alert_tags_blocklisted():
    alert = ("2026-01-01 00:00:00", "203.0.113.200",
             "Port Scanning", "Port scanning detected", "pytest")
    tagged, flagged = threatintel.enrich_alert(alert)
    assert flagged is True
    assert tagged[3].endswith(" [blocklisted]")


def test_enrich_alert_leaves_clean_untouched():
    alert = ("2026-01-01 00:00:00", "8.8.8.8",
             "Port Scanning", "Port scanning detected", "pytest")
    same, flagged = threatintel.enrich_alert(alert)
    assert flagged is False
    assert same == alert


def test_sniffer_tags_blocklisted_attacker():
    s, pq, aq = make_sniffer()
    feed(s, [syn("203.0.113.200", dport=20 + i) for i in range(6)])
    got = alerts_of(aq, "Port Scanning")
    assert len(got) == 1
    assert got[0][3].endswith(" [blocklisted]")


def test_sniffer_leaves_clean_attacker_untagged():
    s, pq, aq = make_sniffer()
    feed(s, [syn("203.0.113.7", dport=20 + i) for i in range(6)])
    got = alerts_of(aq, "Port Scanning")
    assert len(got) == 1
    assert "[blocklisted]" not in got[0][3]
