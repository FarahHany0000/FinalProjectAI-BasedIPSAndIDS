from extensions import db
from datetime import datetime


class Host(db.Model):
    __tablename__ = "hosts"

    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(64), index=True)
    host_name = db.Column(db.String(100), nullable=False)
    ip = db.Column(db.String(100))
    os_info = db.Column(db.String(200))
    last_prediction = db.Column(db.String(50), default="Normal")
    last_probability = db.Column(db.Float, default=0.0)
    last_seen = db.Column(db.DateTime, default=datetime.now)
    status = db.Column(db.String(20), default="Online")
    action = db.Column(db.String(100))

    def to_dict(self):
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "host_name": self.host_name,
            "ip": self.ip,
            "os_info": self.os_info,
            "last_prediction": self.last_prediction or "Normal",
            "last_probability": self.last_probability or 0.0,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "status": self.status,
            "action": self.action,
        }
