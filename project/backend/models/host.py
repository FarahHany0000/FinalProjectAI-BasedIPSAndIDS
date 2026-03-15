from extensions import db
from datetime import datetime


class Host(db.Model):
    __tablename__ = "hosts"

    id = db.Column(db.Integer, primary_key=True)
    host_name = db.Column(db.String(100), nullable=False)
    ip = db.Column(db.String(100))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="Online")
    action = db.Column(db.String(100))

    def to_dict(self):
        return {
            "id": self.id,
            "host_name": self.host_name,
            "ip": self.ip,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "status": self.status,
            "action": self.action,
        }
