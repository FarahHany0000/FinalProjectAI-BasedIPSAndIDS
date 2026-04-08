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
import socket

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from config.settings import WINDOW_SIZE, WINDOW_TIMEOUT, DEFAULT_IFACE
from sniffer.packet_parser import parse_scapy_packet, packets_to_feature_vector


def _get_local_ips():
    """Get all local IP addresses — traffic FROM these IPs is outbound, not attacks."""
    local_ips = {"127.0.0.1", "0.0.0.0"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            local_ips.add(info[4][0])
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return local_ips


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
        self._arp_buffer = []  # Separate buffer for ARP packets
        self._arp_flush_time = time.time()
        self._local_ips = _get_local_ips()
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

    def _is_normal_arp(self, parsed_packets):
        """
        Detect normal ARP traffic (gateway resolution) vs ARP spoofing.
        Normal ARP: few request/reply pairs, consistent MAC-IP bindings.
        ARP Spoof: many unsolicited replies, MAC-IP inconsistencies.
        Returns True if traffic looks normal (should skip detection).
        """
        if not parsed_packets:
            return True

        replies = [p for p in parsed_packets if p.get("_arp_op") == 2]
        requests = [p for p in parsed_packets if p.get("_arp_op") == 1]

        # Normal ARP: mostly requests, or balanced request/reply pairs
        # Spoofing: overwhelmingly replies (unsolicited)
        reply_ratio = len(replies) / len(parsed_packets) if parsed_packets else 0

        # If mostly requests → normal gateway resolution
        if reply_ratio < 0.5:
            return True

        # Check MAC-IP consistency: spoofing uses one MAC for multiple IPs
        # or different MACs for the same IP
        mac_ip_pairs = {}
        for p in replies:
            mac = p.get("_arp_hwsrc", "")
            ip = p.get("_src_ip", "")
            if ip and mac:
                if ip not in mac_ip_pairs:
                    mac_ip_pairs[ip] = set()
                mac_ip_pairs[ip].add(mac)

        # Multiple MACs claiming same IP = spoofing indicator
        for ip, macs in mac_ip_pairs.items():
            if len(macs) > 1:
                return False  # Definite spoof indicator

        # Few replies from known gateway → normal
        # Many rapid unsolicited replies → suspicious
        if len(replies) <= 3 and len(parsed_packets) <= 5:
            return True

        return False

    def _process_window(self, parsed_packets):
        """Process a window of packets through the model."""
        try:
            # Check if this is an ARP-only window — apply smart filtering
            is_arp_window = all(p.get("protocol_encoded") == 4.0 for p in parsed_packets)
            if is_arp_window and self._is_normal_arp(parsed_packets):
                self.stats["total_windows"] += 1
                self.stats["normal_count"] += 1
                return  # normal ARP traffic, skip

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

            # Skip outbound traffic from THIS machine — not an attack on us
            if src_ip in self._local_ips and label != "Normal":
                self.stats["total_windows"] += 1
                self.stats["normal_count"] += 1
                return

            # Skip SSH/FTP SERVER RESPONSES — src_port=22 means it's a server
            # replying, not an attacker initiating brute force (dst_port=22 is attack)
            if label in ("SSHBrute", "FTPBrute"):
                svc_port = 22 if label == "SSHBrute" else 21
                if src_port == svc_port and dst_port != svc_port:
                    self.stats["total_windows"] += 1
                    self.stats["normal_count"] += 1
                    return

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
                print(f"[Sniffer] 🔴 DETECTED: {label} | conf={conf:.3f} "
                      f"| {src_ip}→{dst_ip} | {len(parsed_packets)} pkts")
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
            from scapy.all import ARP as ARP_Layer

            parsed = parse_scapy_packet(pkt)
            parsed['_arrival_time'] = time.time()
            self.stats["total_packets"] += 1

            # Separate ARP and TCP/IP into different buffers to prevent
            # ARP resolution traffic from contaminating attack windows
            is_arp = pkt.haslayer(ARP_Layer)
            now = time.time()

            if is_arp:
                self._arp_buffer.append(parsed)
                arp_len = len(self._arp_buffer)
                arp_elapsed = now - self._arp_flush_time

                if arp_len >= WINDOW_SIZE:
                    window = self._arp_buffer[:WINDOW_SIZE]
                    self._arp_buffer = self._arp_buffer[WINDOW_SIZE:]
                    self._arp_flush_time = now
                    print(f"[Sniffer] ARP window full ({len(window)} pkts), processing...")
                    self._process_window(window)
                # Timeout flush for partial ARP windows (arpspoof ~1 pkt/sec)
                # Raised minimum to 5 to avoid false positives from normal ARP resolution
                elif arp_elapsed > WINDOW_TIMEOUT and arp_len >= 5:
                    window = self._arp_buffer[:]
                    self._arp_buffer = []
                    self._arp_flush_time = now
                    print(f"[Sniffer] ARP timeout flush ({len(window)} pkts, {arp_elapsed:.1f}s elapsed)")
                    self._process_window(window)
            else:
                self.packet_buffer.append(parsed)
                if len(self.packet_buffer) >= WINDOW_SIZE:
                    window = self.packet_buffer[:WINDOW_SIZE]
                    self.packet_buffer = self.packet_buffer[WINDOW_SIZE:]
                    self._last_flush_time = now
                    self._process_window(window)

                # Timeout flush for partial TCP/IP windows
                elif (now - self._last_flush_time) > WINDOW_TIMEOUT and len(self.packet_buffer) > 0:
                    window = self.packet_buffer[:]
                    self.packet_buffer = []
                    self._last_flush_time = now
                    self._process_window(window)

        except Exception as e:
            print(f"[Sniffer] Packet error: {e}")

    def _sniff_thread(self):
        """Run the sniffer in a background thread."""
        try:
            from scapy.all import sniff
            print(f"[Sniffer] Started on interface: {self.iface}")
            print(f"[Sniffer] Local IPs (whitelisted as src): {self._local_ips}")
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
        self._arp_buffer = []
        self._arp_flush_time = time.time()
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
