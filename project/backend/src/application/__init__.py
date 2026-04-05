"""Application layer - Business logic services"""

import logging
from datetime import datetime
from ..domain import Alert, AlertType, AlertSeverity, AlertSourceType

logger = logging.getLogger(__name__)


class NetworkDetectionService:
    """Service for processing network detections from the sniffer"""

    def __init__(self, model_engine, db):
        self.model_engine = model_engine
        self.db = db

    def process_detection(self, payload):
        """
        Convert detection payload to domain Alert object

        payload = {
            "source": hostname,
            "timestamp": ISO string,
            "attack_type": str,
            "confidence": float,
            "n_packets": int,
            "window_id": int
        }
        """
        try:
            source = payload.get("source", "NetworkSensor")
            attack_type = payload.get("attack_type", "Unknown")
            confidence = payload.get("confidence", 0.0)

            # Map severity based on confidence
            if confidence >= 0.9:
                severity = AlertSeverity.CRITICAL
            elif confidence >= 0.8:
                severity = AlertSeverity.HIGH
            elif confidence >= 0.7:
                severity = AlertSeverity.MEDIUM
            else:
                severity = AlertSeverity.LOW

            # Create domain alert
            alert = Alert(
                threat_type=attack_type,
                severity=severity,
                confidence=confidence,
                source_type=AlertSourceType.NETWORK,
                host_name=source,
                ip="0.0.0.0",
                action="Block" if confidence >= 0.85 else "Alert",
                details=f"Packets: {payload.get('n_packets', 0)}, Window: {payload.get('window_id', 0)}",
                time=datetime.now()
            )

            return alert

        except Exception as e:
            logger.error(f"Error processing detection: {e}")
            return None

    def save_alert(self, alert):
        """Save alert to database"""
        try:
            self.db.session.add(alert)
            self.db.session.commit()
            return True
        except Exception as e:
            logger.error(f"Error saving alert: {e}")
            self.db.session.rollback()
            return False


class AlertService:
    """Service for alert retrieval and management"""

    def __init__(self, db):
        self.db = db

    def get_recent_alerts(self, limit=50, source_type=None):
        """Get recent alerts, optionally filtered by source"""
        from models.alert import Alert as AlertModel

        query = AlertModel.query.order_by(AlertModel.time.desc())

        if source_type:
            query = query.filter_by(source_type=source_type)

        return query.limit(limit).all()

    def get_network_alerts(self, limit=50):
        """Get recent network alerts"""
        return self.get_recent_alerts(limit, source_type="network")

    def get_critical_alerts(self):
        """Get all critical severity alerts"""
        from models.alert import Alert as AlertModel
        return AlertModel.query.filter_by(severity="Critical").all()

    def count_by_type(self):
        """Count alerts by attack type"""
        from models.alert import Alert as AlertModel
        from sqlalchemy import func

        return (
            self.db.session.query(
                AlertModel.threat_type,
                func.count(AlertModel.id).label("count")
            )
            .filter_by(source_type="network")
            .group_by(AlertModel.threat_type)
            .all()
        )
