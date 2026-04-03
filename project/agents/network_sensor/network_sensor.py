"""
Network Sensor Agent
====================
Captures live network traffic and detects network-layer attacks using
the integrated network IDS module with XGBoost models.

Uses sliding-window feature extraction (10 packets) with 48 behavioral features
to detect: PortScan, SSHBrute, FTPBrute, ARPSpoof, SYNFlood attacks.
"""
import time
import sys
import pathlib
import logging
import requests

# Add project paths
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from network_module.sniffer.live_capture import LiveSniffer
from network_module.sniffer.pcap_replay import PcapPlayer
from network_module.config.settings import DEFAULT_IFACE, CONFIDENCE_THRESHOLD

logger = logging.getLogger(__name__)

BACKEND_URL = "http://127.0.0.1:5000/api/agent/network-alert"
AGENT_KEY = "changeme"  # Must match backend config
HOSTNAME = "NetworkSensor-1"
CHECK_INTERVAL = 1  # Check for results every N seconds


class NetworkSensorAgent:
    """
    Network IDS Agent — captures packets and sends detections to backend.
    """

    def __init__(self, model_engine, iface: str = None, hostname: str = HOSTNAME,
                 backend_url: str = BACKEND_URL, agent_key: str = AGENT_KEY):
        """
        Parameters
        ----------
        model_engine : loaded model with hierarchical_predict() method
        iface : network interface to sniff on (default: settings.DEFAULT_IFACE)
        hostname : identifier for this sensor
        backend_url : backend API endpoint for alerts
        agent_key : authentication key for backend
        """
        self.model_engine = model_engine
        self.sniffer = LiveSniffer(
            engine=model_engine,
            iface=iface or DEFAULT_IFACE,
            threshold=CONFIDENCE_THRESHOLD
        )
        self.hostname = hostname
        self.backend_url = backend_url
        self.agent_key = agent_key
        self.running = False
        self.stats = {"sent_alerts": 0, "failed_sends": 0}

    def start(self):
        """Start packet capture."""
        if not self.running:
            self.running = True
            self.sniffer.start()
            print(f"[{self.hostname}] Network sensor started on interface: {self.sniffer.iface}")
            print(f"[{self.hostname}] → Sending alerts to: {self.backend_url}")

    def stop(self):
        """Stop packet capture."""
        if self.running:
            self.running = False
            self.sniffer.stop()
            print(f"[{self.hostname}] Network sensor stopped")
            print(f"[{self.hostname}] Stats: {self.stats}")

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
        """
        Send attack alert to backend API.

        Parameters
        ----------
        alert : dict from sniffer.get_results()
            {
                "timestamp": str,
                "label": str (attack type),
                "confidence": float,
                "n_packets": int,
                "window_id": int,
                "alert": bool
            }
        """
        try:
            payload = {
                "source": self.hostname,
                "timestamp": alert.get("timestamp"),
                "attack_type": alert.get("label"),
                "confidence": float(alert.get("confidence", 0)),
                "n_packets": int(alert.get("n_packets", 0)),
                "window_id": int(alert.get("window_id", 0)),
            }

            headers = {
                "X-Agent-Key": self.agent_key,
                "Content-Type": "application/json",
            }

            resp = requests.post(
                self.backend_url,
                json=payload,
                headers=headers,
                timeout=5
            )

            if resp.status_code in [200, 201]:
                self.stats["sent_alerts"] += 1
                response_data = resp.json()
                alert_id = response_data.get("alert_id", "?")
                print(f"[{self.hostname}] Alert #{alert_id} sent: {payload['attack_type']} "
                      f"(conf={payload['confidence']:.2%})")
            else:
                self.stats["failed_sends"] += 1
                logger.warning(f"Backend alert failed: {resp.status_code} - {resp.text}")

        except requests.exceptions.ConnectionError:
            self.stats["failed_sends"] += 1
            logger.error(f"Cannot connect to backend: {self.backend_url}")
        except Exception as e:
            self.stats["failed_sends"] += 1
            logger.error(f"Error sending alert: {e}")

    def run_loop(self, duration: int = None):
        """
        Main loop: continuously check for attacks and send to backend.

        Parameters
        ----------
        duration : run for N seconds (None = infinite)
        """
        self.start()
        start_time = time.time()

        try:
            while self.running:
                # Check for new detections and send them
                self.process_results_and_send()

                # Optional timeout
                if duration and (time.time() - start_time) > duration:
                    break

                time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            print(f"\n[{self.hostname}] Interrupted by user")
        finally:
            self.stop()


def test_with_pcap(pcap_file: str, model_engine):
    """
    Test attack detection on a saved PCAP file.

    Parameters
    ----------
    pcap_file : path to .pcap file
    model_engine : loaded model
    """
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
    print("  Use: from agents.network_sensor.network_sensor import NetworkSensorAgent")
    print("  Example:")
    print("    from backend.utils.model_loader import load_network_model")
    print("    engine = load_network_model()")
    print("    agent = NetworkSensorAgent(engine)")
    print("    agent.run_loop()  # Runs until Ctrl+C")

