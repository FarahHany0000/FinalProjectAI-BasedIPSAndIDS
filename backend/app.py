import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

app = Flask(__name__)

# تفعيل CORS للسماح للفرونت إند بالوصول بدون قيود
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ================= DATABASE CONFIG (SQLite) =================
# هنا الحل السحري: لا سيرفر، لا بورت، ولا باسوورد. ملف صغير هيحل كل المشاكل.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ids_project.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ================= MODELS =================
class Host(db.Model):
    __tablename__ = 'hosts'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    ip = db.Column(db.String(50), unique=True)
    cpu = db.Column(db.Float, default=0)
    memory = db.Column(db.Float, default=0)
    disk = db.Column(db.Float, default=0)
    network = db.Column(db.Float, default=0)
    status = db.Column(db.String(20), default="Offline")
    threats = db.Column(db.String(200), default="None")
    last_seen = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class HostLog(db.Model):
    __tablename__ = 'host_logs'
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer)
    status = db.Column(db.String(20))
    action = db.Column(db.String(100))
    attack_type = db.Column(db.String(100))
    time = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# ================= INITIALIZE =================
with app.app_context():
    try:
        db.create_all()
        print("✅✅✅ Success: SQLite Database Ready! Forget SQL Server Errors.")
    except Exception as e:
        print(f"❌ Error: {e}")

# ================= ROUTES =================
@app.route("/api/hosts", methods=["GET"])
def get_hosts():
    try:
        all_hosts = Host.query.all()
        now = datetime.datetime.utcnow()
        results = []
        for h in all_hosts:
            # الجهاز يعتبر Online لو بعت داتا في آخر 30 ثانية
            is_active = (now - h.last_seen).total_seconds() < 30
            results.append({
                "id": h.id,
                "host_name": h.name,
                "ip": h.ip,
                "cpu": h.cpu,
                "memory": h.memory,
                "disk": h.disk,
                "network": h.network,
                "status": "Online" if is_active else "Offline",
                "threats": h.threats
            })
        return jsonify(results)
    except Exception as e:
        return jsonify([])

@app.route("/api/agent/host-report", methods=["POST"])
def host_report():
    data = request.get_json()
    try:
        host = Host.query.filter_by(ip=data["ip"]).first()
        if not host:
            host = Host(name=data.get("host_name", "Unknown"), ip=data["ip"])
            db.session.add(host)
            db.session.flush()

        host.cpu = data.get("cpu", 0)
        host.memory = data.get("memory", 0)
        host.disk = data.get("disk", 0)
        host.network = data.get("network", 0)
        host.threats = data.get("attack_type", "None")
        host.last_seen = datetime.datetime.utcnow()
        host.status = "Online"

        new_log = HostLog(
            host_id=host.id,
            status=data.get("status", "Safe"),
            attack_type=data.get("attack_type", "None"),
            action=data.get("action", "Alerted")
        )
        db.session.add(new_log)
        db.session.commit()
        return jsonify({"status": "success"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(port=5000, debug=True)