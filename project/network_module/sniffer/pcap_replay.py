"""
PCAP Replay Engine
==================
Reads .pcap files and processes them through the same pipeline as live capture.
"""
import time
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from config.settings import WINDOW_SIZE
from sniffer.packet_parser import parse_scapy_packet, packets_to_feature_vector


class PcapPlayer:
    """Read and process .pcap files through the model pipeline."""

    def __init__(self, engine, threshold: float = 0.95):
        self.engine = engine
        self.threshold = threshold

    def process_pcap(self, pcap_path: str, max_packets: int = None,
                     realtime_pace: bool = False) -> list:
        """
        Process a .pcap file and return prediction results.

        Parameters
        ----------
        pcap_path : path to .pcap file
        max_packets : limit number of packets processed
        realtime_pace : if True, pace packet processing at capture speed

        Returns
        -------
        list of result dicts with label, confidence, etc.
        """
        from scapy.all import PcapReader, rdpcap

        print(f"[PCAP] Loading {pcap_path} ...")

        results = []
        packet_buffer = []
        total_packets = 0
        window_id = 0

        try:
            # Use PcapReader for large files (streaming)
            reader = PcapReader(str(pcap_path))
            prev_time = None

            for pkt in reader:
                if max_packets and total_packets >= max_packets:
                    break

                # Real-time pacing
                if realtime_pace and prev_time is not None:
                    try:
                        delay = float(pkt.time) - prev_time
                        if 0 < delay < 1.0:
                            time.sleep(delay)
                    except Exception:
                        pass
                prev_time = float(pkt.time) if hasattr(pkt, 'time') else None

                # Parse packet
                parsed = parse_scapy_packet(pkt)
                packet_buffer.append(parsed)
                total_packets += 1

                # Process window when full
                if len(packet_buffer) >= WINDOW_SIZE:
                    window = packet_buffer[:WINDOW_SIZE]
                    packet_buffer = packet_buffer[WINDOW_SIZE:]

                    X = packets_to_feature_vector(window)
                    labels, confidences = self.engine.hierarchical_predict(X, self.threshold)

                    result = {
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "window_id": window_id,
                        "label": labels[0],
                        "confidence": confidences[0],
                        "n_packets": len(window),
                        "alert": labels[0] != "Normal",
                    }
                    results.append(result)
                    window_id += 1

            reader.close()

            # Process remaining packets
            if packet_buffer:
                X = packets_to_feature_vector(packet_buffer)
                labels, confidences = self.engine.hierarchical_predict(X, self.threshold)
                result = {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "window_id": window_id,
                    "label": labels[0],
                    "confidence": confidences[0],
                    "n_packets": len(packet_buffer),
                    "alert": labels[0] != "Normal",
                }
                results.append(result)

        except Exception as e:
            print(f"[PCAP] Error processing: {e}")

        # Summary
        attacks = sum(1 for r in results if r["alert"])
        print(f"[PCAP] Processed {total_packets} packets -> {len(results)} windows")
        print(f"[PCAP] Attacks detected: {attacks} / {len(results)} windows")

        return results
