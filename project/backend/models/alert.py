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
    confidence = db.Column(db.Float, default=0.0)
    details = db.Column(db.String(500))
    time = db.Column(db.DateTime, default=datetime.utcnow)
    is_blocked = db.Column(db.Boolean, default=False)
    src_ip = db.Column(db.String(50), default="")
    dst_ip = db.Column(db.String(50), default="")
    src_port = db.Column(db.Integer, default=0)
    dst_port = db.Column(db.Integer, default=0)

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
            "is_blocked": self.is_blocked,
            "src_ip": self.src_ip or "",
            "dst_ip": self.dst_ip or "",
            "src_port": self.src_port or 0,
            "dst_port": self.dst_port or 0,
        }
