"""Network Alert Controller — Handles network IDS detections"""
from flask import jsonify
from extensions import db, socketio
from models.alert import Alert
from datetime import datetime


class NetworkAlertController:
    """Processes network attack detections from the network sniffer."""

    @staticmethod
    def process_network_detection(payload: dict) -> dict:
        """
        Process a network attack detection from the sniffer.

        Parameters
        ----------
        payload : dict
            {
                "source": str (sensor hostname),
                "timestamp": str (ISO format),
                "attack_type": str (PortScan, SSHBrute, FTPBrute, ARPSpoof, SYNFlood),
                "confidence": float (0.0-1.0),
                "n_packets": int,
                "window_id": int (optional)
            }

        Returns
        -------
        dict : {"status": "success"/"error", "message": str}
        """
        try:
            source = payload.get("source", "NetworkSensor-Unknown")
            attack_type = payload.get("attack_type", "Unknown")
            confidence = payload.get("confidence", 0.0)
            n_packets = payload.get("n_packets", 0)
            window_id = payload.get("window_id", 0)

            # Map attack type to severity
            severity_map = {
                "PortScan": "Medium",
                "SSHBrute": "High",
                "FTPBrute": "High",
                "ARPSpoof": "Critical",
                "SYNFlood": "Critical",
            }
            severity = severity_map.get(attack_type, "Medium")

            # Action recommendations
            action_map = {
                "PortScan": "Monitor Network",
                "SSHBrute": "Block SSH Attempts",
                "FTPBrute": "Block FTP Attempts",
                "ARPSpoof": "Isolate Network",
                "SYNFlood": "Rate Limit / DDoS Mitigation",
            }
            action = action_map.get(attack_type, "Alert")

            # Create alert
            alert = Alert(
                source_type="network",
                host_name=source,
                ip="0.0.0.0",  # Network sensor doesn't have single IP
                threat_type=attack_type,
                severity=severity,
                action=action,
                confidence=confidence,
                details=f"Window #{window_id}: {n_packets} packets | Confidence: {confidence:.2%}",
                time=datetime.utcnow(),
            )

            db.session.add(alert)
            db.session.commit()

            # Emit real-time alert to frontend
            socketio.emit("new_alert", {
                "id": alert.id,
                "source_type": alert.source_type,
                "threat": attack_type,
                "severity": severity,
                "action": action,
                "confidence": confidence,
                "time": alert.time.isoformat(),
                "message": f"Network {attack_type} detected (confidence: {confidence:.1%})",
            })

            return {
                "status": "success",
                "message": f"{attack_type} recorded",
                "alert_id": alert.id,
            }

        except Exception as e:
            print(f"[NetworkAlertController] Error: {e}")
            return {"status": "error", "message": str(e)}

    @staticmethod
    def get_network_alerts(limit: int = 50) -> list:
        """Get recent network alerts."""
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
        """Get network alert statistics."""
        from sqlalchemy import func

        total_alerts = Alert.query.filter_by(source_type="network").count()

        # Count by attack type
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
            "by_type": {threat: count for threat, count in attack_counts},
        }
