"""Network Alert Controller -- Handles network IDS detections"""
from extensions import db, socketio
from models.alert import Alert
from datetime import datetime
import time
import threading

_block_lock = threading.Lock()


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
    RATE_LIMIT_MAX = 5        # max alerts before auto-block

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

            # Auto-block check
            is_blocked = False
            if src_ip:
                is_blocked = NetworkAlertController._auto_block_check(src_ip, attack_type)
                if is_blocked:
                    action = f"AUTO-BLOCKED ({action})"

            alert = Alert(
                source_type="network",
                host_name=source,
                ip=src_ip or "0.0.0.0",
                threat_type=attack_type,
                severity=severity,
                action=action,
                confidence=confidence,
                details=f"Window #{window_id}: {n_packets} packets | {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
                time=datetime.utcnow(),
                is_blocked=is_blocked,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=int(src_port) if src_port else 0,
                dst_port=int(dst_port) if dst_port else 0,
            )

            db.session.add(alert)
            db.session.commit()

            socketio.emit("new_alert", alert.to_dict())

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
        Auto-block logic:
        1. If prevention is enabled and IP not already blocked → block after RATE_LIMIT_MAX alerts
        2. Rate limiting: tracks alerts per IP within a time window
        Thread-safe with lock to prevent duplicate blocks.
        """
        try:
            from routes.dashboard import _runtime_config, _apply_firewall_block

            if not _runtime_config.get("prevention_enabled", False):
                return False

            with _block_lock:
                if src_ip in _runtime_config.get("blocked_ips", []):
                    return True  # already blocked

                # Track alert rate for this IP
                now = time.time()
                history = NetworkAlertController._ip_alert_history
                if src_ip not in history:
                    history[src_ip] = []

                # Clean old entries outside the window
                window = NetworkAlertController.RATE_LIMIT_WINDOW
                history[src_ip] = [t for t in history[src_ip] if now - t < window]
                history[src_ip].append(now)

                # If IP exceeded rate limit → auto-block
                if len(history[src_ip]) >= NetworkAlertController.RATE_LIMIT_MAX:
                    _apply_firewall_block(src_ip)
                    _runtime_config["blocked_ips"].append(src_ip)
                    history[src_ip] = []  # reset counter
                    print(f"[AUTO-BLOCK] Blocked {src_ip} after {NetworkAlertController.RATE_LIMIT_MAX} "
                          f"alerts in {window}s ({attack_type})")
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
