"""
Live Capture Engine
===================
Sniffs real-time traffic using Scapy on a configurable interface.
Buffers packets into sliding windows, converts to features, and
feeds them through the active model's hierarchical prediction pipeline.
"""
import threading
import queue
import time
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from config.settings import WINDOW_SIZE, WINDOW_TIMEOUT, DEFAULT_IFACE
from sniffer.packet_parser import parse_scapy_packet, packets_to_feature_vector


class LiveSniffer:
    """Thread-safe live traffic sniffer with sliding window buffering."""

    def __init__(self, engine, iface: str = None, threshold: float = 0.95,
                 bpf_filter: str = None, classification_threshold: float = 0.50):
        """
        Parameters
        ----------
        engine : a loaded model engine (XGBoost/RF/NN) with hierarchical_predict
        iface : network interface name
        threshold : confidence threshold for Stage 1 (binary: attack vs normal)
        bpf_filter : optional BPF filter string for Scapy sniff
        classification_threshold : minimum confidence for Stage 2 (attack type)
        """
        self.engine = engine
        self.iface = iface or DEFAULT_IFACE
        self.threshold = threshold
        self.classification_threshold = classification_threshold
        self.bpf_filter = bpf_filter

        self.packet_buffer = []
        self.result_queue = queue.Queue(maxsize=10000)
        self.running = False
        self._thread = None
        self._last_flush_time = time.time()
        self.stats = {"total_packets": 0, "total_windows": 0,
                      "attacks_detected": 0, "normal_count": 0}

    def _extract_flow_metadata(self, parsed_packets):
        """Extract dominant src/dst IP and port from a window of packets."""
        from collections import Counter
        src_ips, dst_ips, src_ports, dst_ports = [], [], [], []
        for pkt in parsed_packets:
            sp = pkt.get("TCP Source Port", 0) or pkt.get("UDP Source Port", 0)
            dp = pkt.get("TCP Destination Port", 0) or pkt.get("UDP Destination Port", 0)
            if sp: src_ports.append(int(sp))
            if dp: dst_ports.append(int(dp))
            if pkt.get("_src_ip"): src_ips.append(pkt["_src_ip"])
            if pkt.get("_dst_ip"): dst_ips.append(pkt["_dst_ip"])
        src_ip = Counter(src_ips).most_common(1)[0][0] if src_ips else ""
        dst_ip = Counter(dst_ips).most_common(1)[0][0] if dst_ips else ""
        dst_port = Counter(dst_ports).most_common(1)[0][0] if dst_ports else 0
        src_port = Counter(src_ports).most_common(1)[0][0] if src_ports else 0
        return src_ip, dst_ip, src_port, dst_port

    def _heuristic_override(self, parsed_packets, model_label, model_conf):
        """
        Apply rules ONLY for attack types the AI model was NOT trained on:
        ICMP Flood, DDoS UDP, DDoS RAW, DDoS (general).

        The 5 trained attack classes (PortScan, SSHBrute, FTPBrute, SYNFlood,
        ARPSpoof) are detected purely by the XGBoost AI model.

        Returns (label, confidence) tuple.
        """
        import numpy as np
        n = len(parsed_packets)
        if n == 0:
            return model_label, model_conf

        # Count protocol types
        icmp_cnt = sum(1 for p in parsed_packets if p.get("ICMP Type", 0) > 0)
        udp_cnt = sum(1 for p in parsed_packets if p.get("protocol_encoded", 0) == 2)

        # Ratios
        icmp_ratio = icmp_cnt / n if n > 0 else 0
        udp_ratio = udp_cnt / n if n > 0 else 0

        # Port analysis (for DDoS rules only)
        tcp_dports = [int(p.get("TCP Destination Port", 0)) for p in parsed_packets if p.get("TCP Destination Port", 0) > 0]
        udp_dports = [int(p.get("UDP Destination Port", 0)) for p in parsed_packets if p.get("UDP Destination Port", 0) > 0]

        # Proto entropy
        protos = [p.get("protocol_encoded", 0) for p in parsed_packets]
        unique_protos = len(set(protos))
        proto_entropy = np.log2(unique_protos) if unique_protos > 1 else 0

        # ── Rules for UNTRAINED attack types only ──

        # ICMP Flood (not in training data)
        if icmp_cnt >= 8 and icmp_ratio >= 0.60:
            return "ICMP Flood", 0.92

        # DDoS UDP (not in training data)
        if udp_ratio >= 0.5 and n >= 12 and len(set(udp_dports)) >= 3:
            return "DDoS UDP", 0.90

        # DDoS RAW (not in training data)
        if n >= 15 and proto_entropy >= 1.0:
            return "DDoS RAW", 0.88

        # DDoS general (not in training data)
        if n >= 18 and len(set(tcp_dports + udp_dports)) >= 4:
            return "DDoS", 0.87

        # All other attacks → pure AI model prediction
        return model_label, model_conf

    def _process_window(self, parsed_packets):
        """Process a window of packets through the model."""
        try:
            # Skip slow-filling windows (background traffic, not attacks)
            # Real attacks send 100s-1000s of packets/sec; background ARP is ~1 pkt/min
            if len(parsed_packets) >= 2:
                t_first = parsed_packets[0].get('_arrival_time', 0)
                t_last = parsed_packets[-1].get('_arrival_time', 0)
                if t_first > 0 and t_last > 0 and (t_last - t_first) > 10:
                    self.stats["total_windows"] += 1
                    self.stats["normal_count"] += 1
                    return  # too slow to be an attack

            X = packets_to_feature_vector(parsed_packets)
            labels, confidences = self.engine.hierarchical_predict(
                X, self.threshold, self.classification_threshold
            )

            model_label = labels[0]
            model_conf = confidences[0]

            # Apply heuristic overrides for DoS/DDoS types not in training data
            label, conf = self._heuristic_override(parsed_packets, model_label, model_conf)

            src_ip, dst_ip, src_port, dst_port = self._extract_flow_metadata(parsed_packets)

            result = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "label": label,
                "confidence": conf,
                "n_packets": len(parsed_packets),
                "window_id": self.stats["total_windows"],
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
            }

            self.stats["total_windows"] += 1
            if label != "Normal":
                self.stats["attacks_detected"] += 1
                result["alert"] = True
            else:
                self.stats["normal_count"] += 1
                result["alert"] = False

            self.result_queue.put(result, block=False)
        except queue.Full:
            pass
        except Exception as e:
            print(f"[Sniffer] Window processing error: {e}")

    def _packet_callback(self, pkt):
        """Called for each captured packet."""
        if not self.running:
            return

        try:
            parsed = parse_scapy_packet(pkt)
            parsed['_arrival_time'] = time.time()
            self.packet_buffer.append(parsed)
            self.stats["total_packets"] += 1

            # Check if window is full
            if len(self.packet_buffer) >= WINDOW_SIZE:
                window = self.packet_buffer[:WINDOW_SIZE]
                self.packet_buffer = self.packet_buffer[WINDOW_SIZE:]
                self._last_flush_time = time.time()
                self._process_window(window)

            # Timeout flush for partial windows
            elif (time.time() - self._last_flush_time) > WINDOW_TIMEOUT and len(self.packet_buffer) > 0:
                window = self.packet_buffer[:]
                self.packet_buffer = []
                self._last_flush_time = time.time()
                self._process_window(window)

        except Exception as e:
            print(f"[Sniffer] Packet error: {e}")

    def _sniff_thread(self):
        """Run the sniffer in a background thread."""
        try:
            from scapy.all import sniff
            print(f"[Sniffer] Started on interface: {self.iface}")
            sniff(
                iface=self.iface,
                prn=self._packet_callback,
                store=False,
                filter=self.bpf_filter,
                stop_filter=lambda _: not self.running,
            )
        except Exception as e:
            print(f"[Sniffer] Error: {e}")
            self.running = False

    def start(self):
        """Start sniffing in a background thread."""
        if self.running:
            return
        self.running = True
        self.packet_buffer = []
        self._last_flush_time = time.time()
        self._thread = threading.Thread(target=self._sniff_thread, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop sniffing."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        # Flush remaining packets
        if self.packet_buffer:
            self._process_window(self.packet_buffer)
            self.packet_buffer = []
        print(f"[Sniffer] Stopped. Stats: {self.stats}")

    def get_results(self, max_items: int = 100) -> list:
        """Get queued prediction results."""
        results = []
        while not self.result_queue.empty() and len(results) < max_items:
            try:
                results.append(self.result_queue.get_nowait())
            except queue.Empty:
                break
        return results

    def get_stats(self) -> dict:
        """Get current statistics."""
        return self.stats.copy()
