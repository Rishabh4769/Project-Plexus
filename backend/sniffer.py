"""
sniffer.py — Packet capture engine, fully decoupled from the UI.
Captures extended fields: src_port, dst_ip, ttl, checksum, payload preview.
"""

import time
import math
from threading import Thread
from queue import Queue
from collections import defaultdict

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, ARP  # type: ignore

import sys
from pathlib import Path
# Include project root in path to import ML features
sys.path.append(str(Path(__file__).resolve().parent.parent))

from backend.threatintel import enrich_alert
from ml.features.flow_aggregator import FlowAggregator
from ml.inference.model_loader import NIDSModelLoader

# Laya decision-model second opinion (optional). laya_scorer degrades
# gracefully when the `laya` package or its weights are missing, so this
# import is always safe — verdicts are purely additive to alerts.
try:
    from ml.inference.laya_scorer import second_opinion as laya_second_opinion
except Exception:
    laya_second_opinion = None


# Whitelist of safe BPF filter expressions accepted from the API
VALID_BPF_FILTERS = {"tcp", "udp", "icmp", "ip"}

# DNS-tunneling heuristics — a query is suspicious when ANY of these hold
DNS_QNAME_LEN_THRESHOLD = 50    # qname longer than this many characters
DNS_LABEL_COUNT_THRESHOLD = 5   # more dot-separated labels than this
DNS_ENTROPY_THRESHOLD = 4.5     # Shannon entropy (bits) of the leftmost label


def _dns_entropy(label: str) -> float:
    """Shannon entropy of a DNS label, in bits. Random-looking labels
    (data exfiltration, DGAs) score high; dictionary words score low."""
    if not label:
        return 0.0
    counts = defaultdict(int)
    for ch in label:
        counts[ch] += 1
    length = len(label)
    return -sum(
        (c / length) * math.log2(c / length) for c in counts.values()
    )


class PacketSniffer:
    def __init__(
        self,
        packet_queue: Queue,
        alert_queue: Queue,
        session_id: str,
        filter_exp: str | None = None,
        iface: str | None = None,
        time_window: int = 10,
        max_ports_scanned: int = 5,
        max_packets_flood: int = 1500,
        max_syn_flood: int = 500,
    ) -> None:
        self.packet_queue      = packet_queue
        self.alert_queue       = alert_queue
        self.session_id        = session_id
        self.time_window       = time_window
        self.max_ports_scanned = max_ports_scanned
        self.max_packets_flood = max_packets_flood
        self.max_syn_flood     = max_syn_flood

        # iface is pre-validated by the API layer (is_valid_interface check)
        # so we trust it here but still default to None (all interfaces)
        self.iface: str | None = iface or None

        # Sanitise BPF filter — whitelist only
        if filter_exp and filter_exp.strip().lower() in VALID_BPF_FILTERS:
            self.filter: str | None = filter_exp.strip().lower()
        else:
            self.filter = None

        self._connections:    defaultdict[str, set] = defaultdict(set)
        self._packet_counts:  defaultdict[str, int]  = defaultdict(int)
        self._syn_counts:     defaultdict[str, int]  = defaultdict(int)
        self._arp_table:      dict[str, str]         = {}  # IP -> MAC, persistent
        self._alerted_ips:    set[str]               = set()
        self._last_cleanup:   float                  = time.time()
        self.running:         bool                   = False
        self._thread:         Thread | None          = None

        # ML NIDS components
        self.flow_aggregator = FlowAggregator(flow_timeout=15.0)
        self.model_loader = NIDSModelLoader()
        self._alerted_ml_flows: set[str]             = set()


    # ── Public control ─────────────────────────────────────────────── #

    def start(self) -> None:
        self.running = True
        self._thread = Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.running = False

    def update_settings(
        self,
        filter_exp:        str | None = None,
        time_window:       int | None = None,
        max_ports_scanned: int | None = None,
        max_packets_flood: int | None = None,
        max_syn_flood:     int | None = None,
    ) -> None:
        if filter_exp is not None:
            cleaned = filter_exp.strip().lower()
            self.filter = cleaned if cleaned in VALID_BPF_FILTERS else None
        if time_window is not None and time_window > 0:
            self.time_window = time_window
        if max_ports_scanned is not None and max_ports_scanned > 0:
            self.max_ports_scanned = max_ports_scanned
        if max_packets_flood is not None and max_packets_flood > 0:
            self.max_packets_flood = max_packets_flood
        if max_syn_flood is not None and max_syn_flood > 0:
            self.max_syn_flood = max_syn_flood

    def _emit_alert(self, ts: str, src_ip: str, alert_type: str, msg: str) -> None:
        """Push an alert tuple, tagging blocklisted source IPs."""
        alert, _flagged = enrich_alert(
            (ts, src_ip, alert_type, msg, self.session_id)
        )
        self.alert_queue.put(alert)

    # ── Internal loop ──────────────────────────────────────────────── #

    def _sniff_loop(self) -> None:
        try:
            kwargs: dict = {
                "prn":         self._packet_callback,
                "store":       0,
                "stop_filter": lambda _pkt: not self.running,
            }
            if self.filter:
                kwargs["filter"] = self.filter
            if self.iface:
                kwargs["iface"] = self.iface
            sniff(**kwargs)
        except Exception as exc:
            print(f"[PLEXUS/sniffer] Error: {exc}")

    def _packet_callback(self, pkt) -> None:
        if not self.running:
            return

        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        # ── ARP spoofing detection (layer-2; ARP packets carry no IP) ─── #
        if ARP in pkt:
            self._check_arp(pkt, ts)

        if IP not in pkt:
            return

        src_ip   = pkt[IP].src
        dst_ip   = pkt[IP].dst
        ttl      = pkt[IP].ttl
        length   = len(pkt)
        protocol = "IP"
        src_port = 0
        dst_port = 0
        flags    = ""
        checksum = 0

        if TCP in pkt:
            protocol = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            flags    = str(pkt[TCP].flags)
            checksum = int(pkt[TCP].chksum) if pkt[TCP].chksum else 0
        elif UDP in pkt:
            protocol = "UDP"
            src_port = int(pkt[UDP].sport)
            try:
                dst_port = int(pkt[UDP].dport)
            except Exception:
                dst_port = 0
            checksum = int(pkt[UDP].chksum) if pkt[UDP].chksum else 0
        elif ICMP in pkt:
            protocol = "ICMP"
            checksum = int(pkt[ICMP].chksum) if pkt[ICMP].chksum else 0

        # Grab up to 32 bytes of payload as a hex string for the detail pane
        try:
            raw_payload = bytes(pkt[IP].payload)[:32]
            payload_hex = raw_payload.hex()
        except Exception:
            payload_hex = ""

        self.packet_queue.put((
            ts, src_ip, dst_ip, src_port, dst_port,
            length, protocol, flags, ttl, checksum,
            payload_hex, self.session_id,
        ))

        # ── ML-based NIDS Detection ─────────────────────────────────── #
        try:
            res = self.flow_aggregator.process_packet(pkt, time.time())
            if res:
                flow_key, features = res
                if flow_key not in self._alerted_ml_flows:
                    is_attack, prob = self.model_loader.predict(features)
                    if is_attack:
                        alert_msg = (
                            f"ML NIDS detected Attack on flow {flow_key} "
                            f"(Confidence: {prob * 100:.2f}%)"
                        )
                        # Laya second opinion (beta): independent calibrated
                        # verdict from the decision model. Purely additive —
                        # any failure leaves the alert exactly as before.
                        if laya_second_opinion is not None:
                            try:
                                verdict = laya_second_opinion(flow_key, protocol, features)
                                if verdict:
                                    alert_msg += f" | {verdict}"
                            except Exception as laya_err:
                                print(f"[PLEXUS/sniffer/Laya] second opinion failed: {laya_err}")
                        self._emit_alert(ts, src_ip, "ML NIDS Anomaly", alert_msg)
                        self._alerted_ml_flows.add(flow_key)
        except Exception as ml_err:
            print(f"[PLEXUS/sniffer/ML] Inference Error: {ml_err}")

        # ── Rule-based Anomaly detection ────────────────────────────── #
        # Loopback chatter (browser ↔ Vite, frontend ↔ backend API/WS) is
        # not hostile — never count it toward scan/flood heuristics, or
        # PLEXUS flags its own dashboard as a port scanner. Packets are
        # still logged below; only the detection is skipped.
        is_loopback = src_ip.startswith("127.") or src_ip == "::1"

        if not is_loopback:
            self._connections[src_ip].add(dst_port)
            self._packet_counts[src_ip] += 1

            # ── SYN-flood accounting: bare SYNs (SYN set, ACK not set) ── #
            if TCP in pkt:
                tcp_flags = int(pkt[TCP].flags)
                if tcp_flags & 0x02 and not tcp_flags & 0x10:
                    self._syn_counts[src_ip] += 1

            # ── DNS-tunneling heuristic on outbound queries ───────────── #
            if UDP in pkt and dst_port == 53 and DNS in pkt and DNSQR in pkt:
                self._check_dns(pkt, ts, src_ip)


        now = time.time()
        if now - self._last_cleanup > self.time_window:
            self._connections.clear()
            self._packet_counts.clear()
            self._syn_counts.clear()
            self._alerted_ips.clear()
            self._last_cleanup = now

        port_key  = src_ip
        flood_key = f"{src_ip}__flood"
        syn_key   = f"{src_ip}__synflood"

        if (
            len(self._connections[src_ip]) > self.max_ports_scanned
            and port_key not in self._alerted_ips
        ):
            msg = (
                f"Port scanning detected from {src_ip} "
                f"({len(self._connections[src_ip])} ports in {self.time_window}s)"
            )
            self._emit_alert(ts, src_ip, "Port Scanning", msg)
            self._alerted_ips.add(port_key)

        if (
            self._packet_counts[src_ip] > self.max_packets_flood
            and flood_key not in self._alerted_ips
        ):
            msg = (
                f"Traffic flooding from {src_ip} "
                f"({self._packet_counts[src_ip]} packets in {self.time_window}s)"
            )
            self._emit_alert(ts, src_ip, "Flooding", msg)
            self._alerted_ips.add(flood_key)

        if (
            self._syn_counts[src_ip] >= self.max_syn_flood
            and syn_key not in self._alerted_ips
        ):
            msg = (
                f"SYN flood detected from {src_ip} "
                f"({self._syn_counts[src_ip]} SYNs in {self.time_window}s)"
            )
            self._emit_alert(ts, src_ip, "SYN Flood", msg)
            self._alerted_ips.add(syn_key)

    # ── Phase-2 detections ─────────────────────────────────────────── #

    def _check_arp(self, pkt, ts: str) -> None:
        """ARP-spoofing detection: alert when a known IP is suddenly
        claimed by a different MAC (possible MITM). First sightings are
        learned quietly; 0.0.0.0 claims are ignored."""
        try:
            arp = pkt[ARP]
            if int(arp.op) != 2:  # only replies ("is-at") make claims
                return
            claimed_ip  = str(arp.psrc)
            claimed_mac = str(arp.hwsrc).lower()
        except Exception:
            return
        if not claimed_ip or claimed_ip == "0.0.0.0":
            return
        known_mac = self._arp_table.get(claimed_ip)
        if known_mac is None:
            self._arp_table[claimed_ip] = claimed_mac  # learn first sighting
            return
        if known_mac != claimed_mac:
            key = f"{claimed_ip}__arpspoof"
            if key not in self._alerted_ips:
                msg = (
                    f"ARP spoofing detected: {claimed_ip} claimed by "
                    f"{claimed_mac} (was {known_mac}) — possible MITM"
                )
                self._emit_alert(ts, claimed_ip, "ARP Spoofing", msg)
                self._alerted_ips.add(key)
            self._arp_table[claimed_ip] = claimed_mac  # track latest claim

    def _check_dns(self, pkt, ts: str, src_ip: str) -> None:
        """DNS-tunneling heuristic: alert on queries whose qname is too
        long, has too many labels, or whose leftmost label has high
        Shannon entropy (data exfiltration / DGA lookalike)."""
        try:
            qname = pkt[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="ignore")
            qname = qname.rstrip(".")
        except Exception:
            return
        labels = qname.split(".")
        suspicious = (
            len(qname) > DNS_QNAME_LEN_THRESHOLD
            or len(labels) > DNS_LABEL_COUNT_THRESHOLD
            or (labels and _dns_entropy(labels[0]) > DNS_ENTROPY_THRESHOLD)
        )
        if suspicious:
            key = f"{src_ip}__dnstunnel"
            if key not in self._alerted_ips:
                msg = (
                    f"Possible DNS tunneling from {src_ip} "
                    f"(suspicious query: {qname[:64]})"
                )
                self._emit_alert(ts, src_ip, "DNS Tunneling", msg)
                self._alerted_ips.add(key)
