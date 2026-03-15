from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Host(db.Model):
    __tablename__ = "hosts"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    ip = db.Column(db.String(50))
    os = db.Column(db.String(50))
    cpu = db.Column(db.Float)
    memory = db.Column(db.Float)
    disk = db.Column(db.Float)
    network = db.Column(db.Float)
    status = db.Column(db.String(20), default="Online")  # Online, Warning, Offline
    threats = db.Column(db.Integer, default=0)
    last_detected = db.Column(db.DateTime, default=datetime.utcnow)

class HostLogs(db.Model):
    __tablename__ = "host_logs"
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("hosts.id"))
    time = db.Column(db.DateTime, default=datetime.utcnow)
    action = db.Column(db.String(100))
    threat_type = db.Column(db.String(50))
    status = db.Column(db.String(20))