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
                 bpf_filter: str = None):
        """
        Parameters
        ----------
        engine : a loaded model engine (XGBoost/RF/NN) with hierarchical_predict
        iface : network interface name
        threshold : confidence threshold for attack detection
        bpf_filter : optional BPF filter string for Scapy sniff
        """
        self.engine = engine
        self.iface = iface or DEFAULT_IFACE
        self.threshold = threshold
        self.bpf_filter = bpf_filter

        self.packet_buffer = []
        self.result_queue = queue.Queue(maxsize=10000)
        self.running = False
        self._thread = None
        self._last_flush_time = time.time()
        self.stats = {"total_packets": 0, "total_windows": 0,
                      "attacks_detected": 0, "normal_count": 0}

    def _process_window(self, parsed_packets):
        """Process a window of packets through the model."""
        try:
            X = packets_to_feature_vector(parsed_packets)
            labels, confidences = self.engine.hierarchical_predict(X, self.threshold)

            label = labels[0]
            conf = confidences[0]

            result = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "label": label,
                "confidence": conf,
                "n_packets": len(parsed_packets),
                "window_id": self.stats["total_windows"],
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
