"""
Network Sensor Agent
====================
Captures live network traffic and detects network-layer attacks using
the integrated network IDS module with XGBoost/RandomForest/NN models.

Uses sliding-window feature extraction (10 packets) with 48 behavioral features
to detect: PortScan, SSHBrute, FTPBrute, ARPSpoof, SYNFlood attacks.
"""
import time
import sys
import pathlib
import logging

# Add project paths
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from network_module.sniffer.live_capture import LiveSniffer
from network_module.sniffer.pcap_replay import PcapPlayer
from network_module.config.settings import DEFAULT_IFACE, CONFIDENCE_THRESHOLD

logger = logging.getLogger(__name__)

BACKEND_URL = "http://127.0.0.1:5000/alert"
HOSTNAME = "NetworkSensor-1"
CHECK_INTERVAL = 2  # Check for results every N seconds


class NetworkSensorAgent:
    """
    Network IDS Agent — captures packets and feeds predictions to backend.
    """

    def __init__(self, model_engine, iface: str = None, hostname: str = HOSTNAME):
        """
        Parameters
        ----------
        model_engine : loaded model with hierarchical_predict() method
        iface : network interface to sniff on (default: settings.DEFAULT_IFACE)
        hostname : identifier for this sensor
        """
        self.model_engine = model_engine
        self.sniffer = LiveSniffer(
            engine=model_engine,
            iface=iface or DEFAULT_IFACE,
            threshold=CONFIDENCE_THRESHOLD
        )
        self.hostname = hostname
        self.running = False

    def start(self):
        """Start packet capture."""
        if not self.running:
            self.running = True
            self.sniffer.start()
            print(f"[{self.hostname}] Network sensor started")

    def stop(self):
        """Stop packet capture."""
        if self.running:
            self.running = False
            self.sniffer.stop()
            print(f"[{self.hostname}] Network sensor stopped")

    def get_alerts(self):
        """Get detected attacks from the sniffer queue."""
        return self.sniffer.get_results()

    def get_stats(self):
        """Get packet/window statistics."""
        return self.sniffer.get_stats()

    def process_results_and_send(self):
        """Process buffered results and send alerts to backend."""
        alerts = self.get_alerts()
        for alert in alerts:
            if alert.get("alert"):
                self._send_alert(alert)

    def _send_alert(self, alert: dict):
        """Send attack alert to backend API."""
        try:
            import requests
            payload = {
                "source": self.hostname,
                "timestamp": alert.get("timestamp"),
                "attack_type": alert.get("label"),
                "confidence": float(alert.get("confidence", 0)),
                "n_packets": int(alert.get("n_packets", 0)),
            }
            resp = requests.post(BACKEND_URL, json=payload, timeout=5)
            if resp.status_code != 200:
                logger.warning(f"Backend alert failed: {resp.status_code}")
        except Exception as e:
            logger.error(f"Error sending alert: {e}")

    def run_loop(self, duration: int = None):
        """
        Main loop: continuously check for attacks.

        Parameters
        ----------
        duration : run for N seconds (None = infinite)
        """
        self.start()
        start_time = time.time()

        try:
            while True:
                # Check for new detections
                self.process_results_and_send()

                # Optional timeout
                if duration and (time.time() - start_time) > duration:
                    break

                time.sleep(CHECK_INTERVAL)
        except KeyboardInterrupt:
            print(f"\n[{self.hostname}] Interrupted")
        finally:
            self.stop()
            stats = self.get_stats()
            print(f"[{self.hostname}] Final Stats: {stats}")


def test_with_pcap(pcap_file: str, model_engine):
    """Test attack detection on a saved PCAP file."""
    player = PcapPlayer(engine=model_engine, threshold=CONFIDENCE_THRESHOLD)
    results = player.process_pcap(pcap_file, realtime_pace=False)

    # Summarize results
    print(f"\n[PCAP Analysis] {pcap_file}")
    print(f"  Total windows: {len(results)}")
    print(f"  Attacks detected: {sum(1 for r in results if r['alert'])}")

    # Show top detections
    attacks = [r for r in results if r["alert"]]
    if attacks:
        print(f"\n  Top attacks:")
        for r in sorted(attacks, key=lambda x: x["confidence"], reverse=True)[:10]:
            print(f"    {r['label']:15} conf={r['confidence']:.3f}  win#{r['window_id']}")

    return results


if __name__ == "__main__":
    print("Network Sensor Agent Module")
    print("  Use: from network_sensor import NetworkSensorAgent, test_with_pcap")
    print("  Example:")
    print("    from network_module.backend.ai_models.network_xgb import load_engine")
    print("    engine = load_engine()")
    print("    agent = NetworkSensorAgent(engine)")
    print("    agent.run_loop()")
