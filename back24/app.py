from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from Auth.routes import auth_bp  # استيراد الـ blueprint
from datetime import datetime

app = Flask(__name__)
CORS(app)  # للسماح لـ React frontend على port مختلف

# تسجيل الـ Blueprint مع URL prefix
app.register_blueprint(auth_bp, url_prefix="/api/auth")

# --- Dummy Authentication for Dashboard Endpoints ---
DUMMY_TOKEN = "mysecrettoken"
ADMIN_USER = {"username": "admin", "is_admin": True}
current_mode = {"mode": "IDS"}

def check_auth():
    """Check Authorization header for Bearer token."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        abort(401, description="Missing or invalid Authorization header")
    token = auth_header.split(" ")[1]
    if token != DUMMY_TOKEN:
        abort(401, description="Invalid token")
    return ADMIN_USER

# --- Dashboard Endpoints ---
@app.route("/api/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    user = check_auth()
    return jsonify({
        "total_threats": 150,
        "blocked_attacks": 45,
        "active_hosts": "3/5",
        "ai_confidence": 94
    })

@app.route("/api/dashboard/trends", methods=["GET"])
def get_attack_trends():
    user = check_auth()
    trends = [
        {"time": "00:00", "detected": 10, "blocked": 2},
        {"time": "04:00", "detected": 5, "blocked": 0},
        {"time": "08:00", "detected": 20, "blocked": 5},
        {"time": "12:00", "detected": 15, "blocked": 3},
        {"time": "16:00", "detected": 25, "blocked": 7},
        {"time": "20:00", "detected": 30, "blocked": 10},
    ]
    return jsonify(trends)

@app.route("/api/dashboard/distribution", methods=["GET"])
def get_attack_distribution():
    user = check_auth()
    distribution = [
        {"attack_type": "DDoS", "percentage": 45, "count": 120},
        {"attack_type": "Port Scan", "percentage": 30, "count": 80},
        {"attack_type": "Malware", "percentage": 25, "count": 65},
    ]
    return jsonify(distribution)

@app.route("/api/dashboard/recent-alerts", methods=["GET"])
def get_recent_alerts():
    user = check_auth()
    alerts = [
        {
            "id": f"ALT-{1000+i}",
            "timestamp": str(datetime.now()),
            "attack_type": "Brute Force" if i % 2 == 0 else "DDoS",
            "source_ip": f"192.168.1.{i+1}",
            "destination_ip": f"10.0.0.{(i%10)+1}",
            "port": 22 + (i % 5),
            "status": "Blocked" if i % 3 != 0 else "Detected",
            "confidence": 90 + (i % 10),
            "protocol": "SSH" if i % 2 == 0 else "HTTP"
        } for i in range(50)
    ]
    return jsonify(alerts)

# --- System Mode Endpoints ---
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
    if mode not in ["IDS", "IPS"]:
        abort(400, description="Invalid mode")

    current_mode["mode"] = mode
    return jsonify({"success": True, "mode": mode})

# --- Run Flask ---
if __name__ == "__main__":
    app.run(debug=True)
