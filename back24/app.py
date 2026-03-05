# app.py
from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from datetime import datetime
import sqlite3
import random

app = Flask(__name__) 

# السماح لأي request من React
CORS(
    app,
    resources={r"/*": {"origins": "http://localhost:5173"}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "OPTIONS"]
)

DB_FILE = "hosts.db"
DUMMY_TOKEN = "mysecrettoken"
ADMIN_USER = {"username": "admin", "is_admin": True}
current_mode = {"mode": "IDS"}

# ------------------- Database setup -------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS hosts_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_name TEXT,
            cpu_percent REAL,
            memory_percent REAL,
            disk_percent REAL,
            timestamp DATETIME,
            analysis TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ------------------- Auth Helper -------------------
def check_auth():
    """Check Authorization header for Bearer token."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        abort(401, description="Missing or invalid Authorization header")
    token = auth_header.split(" ")[1]
    if token != DUMMY_TOKEN:
        abort(401, description="Invalid token")
    return ADMIN_USER

# ------------------- API: Agent report (POST) -------------------
@app.route("/api/agent/host-report", methods=["POST"])
def host_report():
    agent_key = request.headers.get("X-Agent-Key")
    if agent_key != DUMMY_TOKEN:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    data = request.json
    host_name = data.get("host_name", "Unknown")

    # ممكن تخزني كل حاجة JSON كما هي
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS hosts_data_full (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_name TEXT,
            data TEXT,
            timestamp DATETIME
        )
    """)
    conn.commit()

    # خزّني البيانات كلها كـ JSON string
    import json
    c.execute("""
        INSERT INTO hosts_data_full (host_name, data, timestamp)
        VALUES (?, ?, ?)
    """, (host_name, json.dumps(data), datetime.now()))
    conn.commit()
    conn.close()

    return jsonify({"status": "received", "analysis": "Safe"})

# ------------------- API: Fetch Hosts (GET) -------------------
@app.route("/api/hosts", methods=["GET"])
def get_hosts():
    user = check_auth()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, host_name, cpu_percent, memory_percent, disk_percent, timestamp, analysis FROM hosts_data")
    rows = c.fetchall()
    conn.close()

    hosts = []
    for row in rows:
        id_, name, cpu, memory, disk, timestamp, analysis = row
        status = "Online" if "High" not in analysis else "Warning"
        hosts.append({
            "id": id_,
            "name": name,
            "cpu": cpu,
            "memory": memory,
            "disk": disk,
            "status": status,
            "ip": f"192.168.1.{id_ % 255}",
            "os": "Windows",
            "threats": 1 if "High" in analysis else 0
        })
    return jsonify({"hosts": hosts})

# ------------------- API: Dashboard Stats -------------------
@app.route("/api/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    user = check_auth()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM hosts_data")
    total_threats = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM hosts_data WHERE analysis LIKE 'High%'")
    blocked_attacks = c.fetchone()[0]
    conn.close()

    active_hosts = random.randint(1,5)
    ai_confidence = random.randint(80, 100)

    return jsonify({
        "total_threats": total_threats,
        "blocked_attacks": blocked_attacks,
        "active_hosts": active_hosts,
        "ai_confidence": ai_confidence
    })

# ------------------- API: Attack Trends -------------------
@app.route("/api/dashboard/trends", methods=["GET"])
def get_attack_trends():
    user = check_auth()
    trends = [
        {"time": f"{h:02d}:00", "detected": random.randint(0,30), "blocked": random.randint(0,10)}
        for h in range(0, 24, 4)
    ]
    return jsonify(trends)

# ------------------- API: Attack Distribution -------------------
@app.route("/api/dashboard/distribution", methods=["GET"])
def get_attack_distribution():
    user = check_auth()
    distribution = [
        {"attack_type": "DDoS", "percentage": random.randint(20,50), "count": random.randint(50,150)},
        {"attack_type": "Port Scan", "percentage": random.randint(20,40), "count": random.randint(30,100)},
        {"attack_type": "Malware", "percentage": random.randint(10,30), "count": random.randint(20,80)},
    ]
    return jsonify(distribution)

# ------------------- API: Recent Alerts -------------------
@app.route("/api/dashboard/recent-alerts", methods=["GET"])
def get_recent_alerts():
    user = check_auth()
    alerts = [
        {
            "id": f"ALT-{1000+i}",
            "timestamp": str(datetime.now()),
            "attack_type": random.choice(["Brute Force", "DDoS"]),
            "source_ip": f"192.168.1.{i+1}",
            "destination_ip": f"10.0.0.{(i%10)+1}",
            "port": random.randint(20,30),
            "status": random.choice(["Blocked","Detected"]),
            "confidence": random.randint(80,100),
            "protocol": random.choice(["SSH","HTTP"])
        } for i in range(50)
    ]
    return jsonify(alerts)

# ------------------- API: System Mode -------------------
@app.route("/api/system/mode", methods=["GET"])
def get_system_mode():
    user = check_auth()
    if not user.get("is_admin"):
        abort(403, description="Admin access required")
    return jsonify(current_mode)

@app.route("/api/system/mode", methods=["POST"])
def set_system_mode():
    user = check_auth()
    if not user.get("is_admin"):
        abort(403, description="Admin access required")

    data = request.get_json()
    mode = data.get("mode")
    if mode not in ["IDS","IPS"]:
        abort(400, description="Invalid mode")

    current_mode["mode"] = mode
    return jsonify({"success": True, "mode": mode})

# ------------------- API: Generic Alerts -------------------
@app.route("/api/alerts/", methods=["GET"])
def get_alerts():
    user = check_auth()
    alerts = []
    for i in range(10):
        status = random.choice(["Blocked", "Detected"])
        analysis = "High CPU usage" if status == "Blocked" else "Normal Activity"
        alerts.append({
            "id": f"ALT-{random.randint(1000,9999)}",
            "timestamp": str(datetime.now()),
            "attack_type": analysis,
            "source_ip": f"192.168.1.{random.randint(1,255)}",
            "destination_ip": f"10.0.0.{random.randint(1,255)}",
            "port": random.randint(20,30),
            "status": status,
            "confidence": random.randint(80,100),
            "protocol": random.choice(["SSH","HTTP"])
        })
    return jsonify(alerts)

# ------------------- Run Flask -------------------
if __name__ == "__main__":
    app.run(debug=True, port=5000)
