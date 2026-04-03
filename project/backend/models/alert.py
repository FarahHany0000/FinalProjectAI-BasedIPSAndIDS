from extensions import db
from datetime import datetime


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    source_type = db.Column(db.String(20), default="host")  # "host" or "network"
    host_name = db.Column(db.String(100), nullable=False)
    ip = db.Column(db.String(100))
    threat_type = db.Column(db.String(100))
    severity = db.Column(db.String(20), default="Medium")
    action = db.Column(db.String(100), default="Alert")
    confidence = db.Column(db.Float, default=0.0)  # For network: model confidence
    details = db.Column(db.String(500))  # Additional info (ports, packet count, etc.)
    time = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "source_type": self.source_type,
            "host_name": self.host_name,
            "ip": self.ip,
            "threat": self.threat_type,
            "severity": self.severity,
            "action": self.action,
            "confidence": self.confidence,
            "details": self.details,
            "time": self.time.isoformat() if self.time else None,
        }
