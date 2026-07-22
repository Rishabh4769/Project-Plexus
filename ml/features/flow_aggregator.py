"""
Flow Aggregation Module
========================
Copyright (c) 2026 Rishabh Joshi

Aggregates packet streams (from live sniffer or PCAP files) into network flows.
Calculates the 20 features selected for the XGBoost NIDS classifier.
"""

import time
import numpy as np
from scapy.all import IP, TCP, UDP, ICMP  # type: ignore

class Flow:
    """
    Represents a bidirectional network flow and accumulates statistical properties.
    """
    def __init__(self, start_time: float):
        """
        Initializes a Flow object.

        Args:
            start_time (float): The epoch timestamp of the first packet in the flow.
        """
        self.start_time = start_time
        self.last_active = start_time
        self.fwd_pkt_lens = []
        self.bwd_pkt_lens = []
        self.all_pkt_lens = []
        self.fwd_timestamps = []
        self.bwd_timestamps = []
        self.all_timestamps = []
        self.fwd_hdr_len = 0
        self.bwd_hdr_len = 0
        self.fwd_psh_flags = 0
        self.syn_flag_count = 0
        self.min_seg_size_forward = 0

    def add_packet(self, pkt, direction: str, ts: float) -> None:
        """
        Accumulates metrics of a single packet into this flow.

        Args:
            pkt: The Scapy packet instance.
            direction (str): 'fwd' for forward traffic, 'bwd' for backward traffic.
            ts (float): Packet arrival timestamp.
        """
        self.last_active = ts
        self.all_timestamps.append(ts)
        
        pkt_len = len(pkt)
        self.all_pkt_lens.append(pkt_len)
        
        hdr_len = 0
        if IP in pkt:
            hdr_len += (pkt[IP].ihl * 4) if pkt[IP].ihl else 20
        
        is_tcp = TCP in pkt
        is_udp = UDP in pkt
        
        if is_tcp:
            tcp_hdr_len = (pkt[TCP].dataofs * 4) if pkt[TCP].dataofs else 20
            hdr_len += tcp_hdr_len
            
            if self.min_seg_size_forward == 0 or tcp_hdr_len < self.min_seg_size_forward:
                self.min_seg_size_forward = tcp_hdr_len
                
            flags = pkt[TCP].flags
            if "S" in flags:
                self.syn_flag_count += 1
            if "P" in flags and direction == "fwd":
                self.fwd_psh_flags += 1
                
        elif is_udp:
            hdr_len += 8
            if self.min_seg_size_forward == 0 or 8 < self.min_seg_size_forward:
                self.min_seg_size_forward = 8

        if direction == "fwd":
            self.fwd_pkt_lens.append(pkt_len)
            self.fwd_timestamps.append(ts)
            self.fwd_hdr_len += hdr_len
        else:
            self.bwd_pkt_lens.append(pkt_len)
            self.bwd_timestamps.append(ts)
            self.bwd_hdr_len += hdr_len

    def get_features(self) -> dict:
        """
        Computes and returns the 20 features matching the feature spec.

        Returns:
            dict: The 20 flow-level statistical metrics.
        """
        duration = max(self.last_active - self.start_time, 1e-6)
        
        fwd_count = len(self.fwd_pkt_lens)
        bwd_count = len(self.bwd_pkt_lens)
        total_count = len(self.all_pkt_lens)
        
        fwd_sum = sum(self.fwd_pkt_lens)
        bwd_sum = sum(self.bwd_pkt_lens)
        total_sum = sum(self.all_pkt_lens)
        
        pkt_len_mean = np.mean(self.all_pkt_lens) if total_count > 0 else 0.0
        fwd_pkt_len_mean = np.mean(self.fwd_pkt_lens) if fwd_count > 0 else 0.0
        avg_pkt_size = (total_sum / total_count) if total_count > 0 else 0.0
        avg_fwd_seg_size = fwd_pkt_len_mean
        max_pkt_len = max(self.all_pkt_lens) if total_count > 0 else 0.0
        fwd_pkt_len_max = max(self.fwd_pkt_lens) if fwd_count > 0 else 0.0
        bwd_pkt_len_mean = np.mean(self.bwd_pkt_lens) if bwd_count > 0 else 0.0
        avg_bwd_seg_size = bwd_pkt_len_mean
        min_pkt_len = min(self.all_pkt_lens) if total_count > 0 else 0.0
        fwd_pkt_len_std = np.std(self.fwd_pkt_lens) if fwd_count > 1 else 0.0
        pkt_len_var = np.var(self.all_pkt_lens) if total_count > 1 else 0.0
        bwd_pkts_per_s = bwd_count / duration
        pkt_len_std = np.std(self.all_pkt_lens) if total_count > 1 else 0.0
        total_len_fwd = float(fwd_sum)
        bwd_pkt_len_max = max(self.bwd_pkt_lens) if bwd_count > 0 else 0.0
        init_win_bytes_fwd = 0.0
        bwd_hdr_len = float(self.bwd_hdr_len)
        flow_bytes_per_s = total_sum / duration
        
        fwd_iat_min = 0.0
        if fwd_count > 1:
            fwd_iats = np.diff(self.fwd_timestamps)
            fwd_iat_min = float(np.min(fwd_iats)) * 1e6

        return {
            "Packet Length Mean": float(pkt_len_mean),
            "Fwd Packet Length Mean": float(fwd_pkt_len_mean),
            "Average Packet Size": float(avg_pkt_size),
            "Avg Fwd Segment Size": float(avg_fwd_seg_size),
            "Max Packet Length": float(max_pkt_len),
            "Fwd Packet Length Max": float(fwd_pkt_len_max),
            "Avg Bwd Segment Size": float(avg_bwd_seg_size),
            "min_seg_size_forward": float(self.min_seg_size_forward),
            "Bwd Packet Length Mean": float(bwd_pkt_len_mean),
            "Min Packet Length": float(min_pkt_len),
            "Fwd Packet Length Std": float(fwd_pkt_len_std),
            "Packet Length Variance": float(pkt_len_var),
            "Bwd Packets/s": float(bwd_pkts_per_s),
            "Packet Length Std": float(pkt_len_std),
            "Total Length of Fwd Packets": float(total_len_fwd),
            "Bwd Packet Length Max": float(bwd_pkt_len_max),
            "Init_Win_bytes_forward": float(init_win_bytes_fwd),
            "Bwd Header Length": float(bwd_hdr_len),
            "Flow Bytes/s": float(flow_bytes_per_s),
            "Fwd IAT Min": float(fwd_iat_min)
        }

class FlowAggregator:
    """
    Manages active network flows and maps Scapy packets into bidirectional Flow objects.
    """
    def __init__(self, flow_timeout: float = 15.0):
        """
        Initializes the FlowAggregator.

        Args:
            flow_timeout (float): Inactivity duration (seconds) before a flow is pruned.
        """
        self.flows = {}
        self.flow_timeout = flow_timeout

    def process_packet(self, pkt, ts: float = None) -> tuple[str, dict] | None:
        """
        Processes a single Scapy packet and associates it with a flow.

        Args:
            pkt: The Scapy packet instance.
            ts (float): Packet timestamp.

        Returns:
            tuple[str, dict] | None: A tuple of (flow_key, features) if the flow updates
            or terminates, otherwise None.
        """
        if IP not in pkt:
            return None
        if ts is None:
            ts = time.time()

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        
        sport = 0
        dport = 0
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        fwd_key = (src_ip, dst_ip, sport, dport, proto)
        bwd_key = (dst_ip, src_ip, dport, sport, proto)

        if fwd_key in self.flows:
            flow_key = fwd_key
            direction = "fwd"
        elif bwd_key in self.flows:
            flow_key = bwd_key
            direction = "bwd"
        else:
            flow_key = fwd_key
            self.flows[flow_key] = Flow(ts)
            direction = "fwd"

        if TCP in pkt and direction == "fwd" and self.flows[flow_key].min_seg_size_forward == 0:
            self.flows[flow_key].min_seg_size_forward = 20
            
        self.flows[flow_key].add_packet(pkt, direction, ts)
        self.clean_expired_flows(ts)

        is_termination = TCP in pkt and any(f in str(pkt[TCP].flags) for f in ["F", "R"])
        flow = self.flows[flow_key]
        
        if len(flow.all_pkt_lens) % 15 == 0 or is_termination:
            key_str = f"{src_ip}:{sport} -> {dst_ip}:{dport} ({proto})"
            return key_str, flow.get_features()

        return None

    def clean_expired_flows(self, current_time: float) -> None:
        """
        Removes expired flows from the session tracking state.

        Args:
            current_time (float): Current system epoch time.
        """
        expired = []
        for key, flow in self.flows.items():
            if current_time - flow.last_active > self.flow_timeout:
                expired.append(key)
        for key in expired:
            del self.flows[key]
