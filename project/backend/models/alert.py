from extensions import db
from datetime import datetime


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    host_name = db.Column(db.String(100), nullable=False)
    ip = db.Column(db.String(100))
    threat_type = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    action = db.Column(db.String(100))
    time = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "host_name": self.host_name,
            "ip": self.ip,
            "threat": self.threat_type,
            "severity": self.severity,
            "action": self.action,
            "time": self.time.isoformat() if self.time else None,
        }
