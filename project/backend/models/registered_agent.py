from extensions import db
from datetime import datetime


class RegisteredAgent(db.Model):
    """
    Each physical device running the agent gets a unique row here.
    agent_id is a UUID generated on the device at first run.
    The backend uses this to know exactly which devices exist.
    """
    __tablename__ = "registered_agents"

    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    host_name = db.Column(db.String(100), nullable=False)
    ip = db.Column(db.String(100))
    os_info = db.Column(db.String(200))
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_approved = db.Column(db.Boolean, default=True)
    status = db.Column(db.String(20), default="Online")

    def to_dict(self):
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "host_name": self.host_name,
            "ip": self.ip,
            "os_info": self.os_info,
            "registered_at": self.registered_at.isoformat() if self.registered_at else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "is_approved": self.is_approved,
            "status": self.status,
        }
