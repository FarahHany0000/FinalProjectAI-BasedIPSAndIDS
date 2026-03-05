from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import sqlite3
from datetime import datetime

app = Flask(__name__)

# السماح لأي origin مع كل الـ methods والـ headers
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

EXPECTED_AGENT_KEY = "super-secret-agent-key"
DB_FILE = "hosts.db"

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

# ------------------- Dashboard -------------------
@app.route("/")
def home():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM hosts_data ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()
    return render_template("dashboard.html", hosts=rows)

# ------------------- API: Agent reports -------------------
@app.route("/api/agent/host-report", methods=["POST"])
def host_report():
    agent_key = request.headers.get("X-Agent-Key")
    if agent_key != EXPECTED_AGENT_KEY:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    data = request.json
    host_name = data.get("host_name", "Unknown")
    cpu = data.get("cpu_percent", 0)
    memory = data.get("memory_percent", 0)
    disk = data.get("disk_percent", 0)

    analysis = "Safe"
    if cpu > 90:
        analysis = "High CPU usage"
    elif memory > 90:
        analysis = "High Memory usage"
    elif disk > 90:
        analysis = "High Disk usage"

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        INSERT INTO hosts_data (host_name, cpu_percent, memory_percent, disk_percent, timestamp, analysis)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (host_name, cpu, memory, disk, datetime.now(), analysis))
    conn.commit()
    conn.close()

    return jsonify({"status": "received", "analysis": analysis})

# ------------------- API: Get hosts for React -------------------
@app.route("/api/hosts", methods=["GET"])
def get_hosts():
    token = request.headers.get("Authorization", "")
    if not token or token != f"Bearer {EXPECTED_AGENT_KEY}":
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM hosts_data ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()

    hosts = []
    for row in rows:
        hosts.append({
            "id": row[0],
            "name": row[1],
            "cpu": row[2],
            "memory": row[3],
            "disk": row[4],
            "timestamp": row[5],
            "analysis": row[6],
            "status": "Warning" if "High" in row[6] else "Online"
        })

    return jsonify({"hosts": hosts})

# ------------------- Run server -------------------
if __name__ == "__main__":
    app.run(debug=True, port=5000)
