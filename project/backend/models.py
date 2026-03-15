from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class Host(db.Model):
    __tablename__ = "hosts"
    id = db.Column(db.Integer, primary_key=True)
    host_name = db.Column(db.String(100))
    ip = db.Column(db.String(100))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="Online")
    action = db.Column(db.String(100))


class Alert(db.Model):
    __tablename__ = "alerts"
    id = db.Column(db.Integer, primary_key=True)
    host_name = db.Column(db.String(100))
    ip = db.Column(db.String(100))
    threat_type = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    action = db.Column(db.String(100))
    time = db.Column(db.DateTime, default=datetime.utcnow)


class HostLogs(db.Model):
    __tablename__ = "host_logs"
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("hosts.id"))
    time = db.Column(db.DateTime, default=datetime.utcnow)
    action = db.Column(db.String(100))
    threat_type = db.Column(db.String(50))
    status = db.Column(db.String(20))