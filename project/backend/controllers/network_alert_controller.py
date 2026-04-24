"""Network Alert Controller -- Handles network IDS detections"""
from extensions import db, socketio
from models.alert import Alert
from datetime import datetime
import time
import threading
import socket

_block_lock = threading.Lock()


def _get_local_ips():
    """Get all local IP addresses for this machine (never block these)."""
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


def _is_protected_ip(ip: str) -> bool:
    """Never block local machine IPs or common gateway addresses."""
    if not ip:
        return True
    if ip in _get_local_ips():
        return True
    # Common gateway patterns (.1 and .254 in last octet)
    parts = ip.split(".")
    if len(parts) == 4 and parts[3] in ("1", "254", "0", "255"):
        return True
    return False


class NetworkAlertController:
    """Processes network attack detections from the network sniffer."""

    SEVERITY_MAP = {
        "PortScan": "Medium",
        "SSHBrute": "High",
        "FTPBrute": "High",
        "ARPSpoof": "Critical",
        "SYNFlood": "Critical",
        "ICMP Flood": "High",
        "DDoS": "Critical",
        "DDoS UDP": "Critical",
        "DDoS RAW": "Critical",
        "DDoS ICMP": "Critical",
    }

    ACTION_MAP = {
        "PortScan": "Monitor Network",
        "SSHBrute": "Block SSH Attempts",
        "FTPBrute": "Block FTP Attempts",
        "ARPSpoof": "Isolate Network",
        "SYNFlood": "Rate Limit / DDoS Mitigation",
        "ICMP Flood": "Block ICMP",
        "DDoS": "DDoS Mitigation",
        "DDoS UDP": "Block UDP Flood",
        "DDoS RAW": "Block RAW Flood",
        "DDoS ICMP": "Block ICMP Flood",
    }

    # Rate limiting: track alerts per IP { ip: [timestamp, timestamp, ...] }
    _ip_alert_history = {}
    RATE_LIMIT_WINDOW = 60    # seconds

    # Severity-based thresholds: Critical=3, High=10, Medium=15
    # Higher thresholds give the admin time to see detections on the dashboard
    RATE_LIMIT_BY_SEVERITY = {
        "Critical": 3,
        "High": 10,
        "Medium": 15,
    }
    RATE_LIMIT_MAX = 10       # default fallback

    @staticmethod
    def process_network_detection(payload: dict) -> dict:
        try:
            source = payload.get("source", "NetworkSensor-Unknown")
            attack_type = payload.get("attack_type", "Unknown")
            confidence = payload.get("confidence", 0.0)
            n_packets = payload.get("n_packets", 0)
            window_id = payload.get("window_id", 0)
            src_ip = payload.get("src_ip", "")
            dst_ip = payload.get("dst_ip", "")
            src_port = payload.get("src_port", 0)
            dst_port = payload.get("dst_port", 0)

            severity = NetworkAlertController.SEVERITY_MAP.get(attack_type, "Medium")
            action = NetworkAlertController.ACTION_MAP.get(attack_type, "Alert")

            # Verbose console logging
            blocked_tag = ""

            # Auto-block check — block ATTACKER (src) only, never block our own IPs
            is_blocked = False
            block_ip = src_ip
            if _is_protected_ip(src_ip) and dst_ip and not _is_protected_ip(dst_ip):
                block_ip = dst_ip  # src is us/gateway, block the other side
            if block_ip and not _is_protected_ip(block_ip):
                is_blocked = NetworkAlertController._auto_block_check(block_ip, attack_type)
                if is_blocked:
                    action = f"AUTO-BLOCKED ({action})"
                    blocked_tag = " ⛔ BLOCKED"

            alert = Alert(
                source_type="network",
                host_name=source,
                ip=src_ip or "0.0.0.0",
                threat_type=attack_type,
                severity=severity,
                action=action,
                confidence=confidence,
                details=f"Window #{window_id}: {n_packets} packets | {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
                time=datetime.now(),
                is_blocked=is_blocked,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=int(src_port) if src_port else 0,
                dst_port=int(dst_port) if dst_port else 0,
            )

            db.session.add(alert)
            db.session.commit()

            socketio.emit("new_alert", alert.to_dict())

            # Console output for every detection
            print(f"[ALERT] {severity:<8} | {attack_type:<15} | conf={confidence:.3f} "
                  f"| {src_ip}→{dst_ip} | {n_packets} pkts{blocked_tag}")

            return {
                "status": "success",
                "message": f"{attack_type} recorded" + (" [AUTO-BLOCKED]" if is_blocked else ""),
                "alert_id": alert.id,
            }

        except Exception as e:
            print(f"[NetworkAlertController] Error: {e}")
            return {"status": "error", "message": str(e)}

    @staticmethod
    def _auto_block_check(src_ip: str, attack_type: str) -> bool:
        """
        Immediate auto-block logic:
        - Block on first detected attack when prevention is enabled.
        - No rate-limit window or severity-based threshold checks.
        Thread-safe with lock to prevent duplicate blocks.
        """
        try:
            from routes.dashboard import _runtime_config, _apply_firewall_block

            if not _runtime_config.get("prevention_enabled", False):
                return False

            with _block_lock:
                if src_ip in _runtime_config.get("blocked_ips", []):
                    return True  # already blocked

                success = _apply_firewall_block(src_ip)
                if not success:
                    return False

                _runtime_config["blocked_ips"].append(src_ip)
                print(f"[AUTO-BLOCK] Blocked {src_ip} — {attack_type} (immediate)")
                socketio.emit("config_update", {
                    "blocked_ips": _runtime_config["blocked_ips"],
                })
                return True

            return False
        except Exception as e:
            print(f"[AUTO-BLOCK] Error: {e}")
            return False

    @staticmethod
    def get_network_alerts(limit: int = 50) -> list:
        alerts = (
            Alert.query
            .filter_by(source_type="network")
            .order_by(Alert.time.desc())
            .limit(limit)
            .all()
        )
        return [a.to_dict() for a in alerts]

    @staticmethod
    def get_network_stats() -> dict:
        from sqlalchemy import func

        total_alerts = Alert.query.filter_by(source_type="network").count()
        blocked_count = Alert.query.filter_by(source_type="network", is_blocked=True).count()

        attack_counts = (
            db.session.query(
                Alert.threat_type,
                func.count(Alert.id).label("count")
            )
            .filter(Alert.source_type == "network")
            .group_by(Alert.threat_type)
            .all()
        )

        return {
            "total_alerts": total_alerts,
            "blocked_attacks": blocked_count,
            "by_type": {threat: count for threat, count in attack_counts},
        }
