import os
import sys
import datetime
import numpy as np
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

# ─────────────────────────────────────────────────────────
# Path setup — relative to this file, not hardcoded
# ─────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AI_MODELS_DIR = os.path.join(BASE_DIR, "ai_models")
sys.path.insert(0, AI_MODELS_DIR)

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────────────────
# Configuration (from environment or defaults)
# ─────────────────────────────────────────────────────────
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URI', f'sqlite:///{os.path.join(BASE_DIR, "instance", "ids.db")}'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'ids-secret-key')

AGENT_KEY = os.environ.get('AGENT_KEY', 'changeme')

db = SQLAlchemy(app)


# ─────────────────────────────────────────────────────────
# Database Models
# ─────────────────────────────────────────────────────────
class Host(db.Model):
    __tablename__ = "hosts"
    id = db.Column(db.Integer, primary_key=True)
    host_name = db.Column(db.String(100))
    ip = db.Column(db.String(100))
    last_seen = db.Column(db.DateTime)
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
    time = db.Column(db.DateTime)


# ─────────────────────────────────────────────────────────
# AI Model Loading — CNN pipeline with scaler + weights
# ─────────────────────────────────────────────────────────
model_pipeline = None

def load_ai_model():
    """Load the CNN pipeline (scaler from pkl, weights from h5)."""
    global model_pipeline
    try:
        import joblib
        import tensorflow as tf
        import __main__

        pkl_path = os.path.join(AI_MODELS_DIR, "cnn_complete_pipeline.pkl")
        h5_path = os.path.join(AI_MODELS_DIR, "cnn_weights.h5")

        if not os.path.exists(pkl_path):
            print(f"[WARN] Model file not found: {pkl_path}")
            return
        if not os.path.exists(h5_path):
            print(f"[WARN] Weights file not found: {h5_path}")
            return

        # The pkl was saved from a script where CNNPipeline was in __main__.
        # Inject the class so joblib can unpickle it.
        from use_models import CNNPipeline as _CNNPipeline
        __main__.CNNPipeline = _CNNPipeline

        pipeline = joblib.load(pkl_path)

        # Load actual CNN weights and attach to pipeline
        tf.get_logger().setLevel('ERROR')
        cnn_model = tf.keras.models.load_model(h5_path, compile=False)
        pipeline.model = cnn_model

        model_pipeline = pipeline

        print(f"[OK] CNN model loaded (scaler + weights)")
        print(f"     Pipeline type: {type(pipeline).__name__}")
        has_scaler = hasattr(pipeline, 'scaler') and pipeline.scaler is not None
        print(f"     Has scaler: {has_scaler}")

    except Exception as e:
        print(f"[ERROR] Failed to load AI model: {e}")
        import traceback
        traceback.print_exc()
        model_pipeline = None


# ─────────────────────────────────────────────────────────
# Feature names (must match host agent's 15 features exactly)
# ─────────────────────────────────────────────────────────
FEATURE_NAMES = [
    'total_logons', 'avg_logon_hour', 'std_logon_hour',
    'weekend_logons', 'after_hours_logons', 'unique_pcs_logon',
    'total_device_activities', 'unique_pcs_device',
    'avg_device_hour', 'after_hours_device',
    'total_file_activities', 'unique_files', 'unique_pcs_file',
    'avg_file_hour', 'after_hours_files'
]


# ─────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────

@app.route("/api/agent/health", methods=["GET"])
def health_check():
    """Heartbeat endpoint for agents to check if backend is alive."""
    return jsonify({
        "status": "ok",
        "model_loaded": model_pipeline is not None,
        "time": datetime.datetime.now().isoformat()
    })


@app.route("/api/hosts", methods=["GET"])
def get_hosts():
    """Return all registered hosts (for frontend dashboard)."""
    hosts = Host.query.all()
    output = []
    for h in hosts:
        output.append({
            "host_name": h.host_name,
            "ip": h.ip,
            "last_seen": h.last_seen.isoformat() if h.last_seen else None,
            "status": h.status,
            "action": h.action
        })
    return jsonify(output)


@app.route("/api/alerts/<hostname>", methods=["GET"])
def get_alerts(hostname):
    """Return alert logs for a specific host (for frontend)."""
    alerts = Alert.query.filter_by(host_name=hostname).order_by(Alert.time.desc()).all()
    output = []
    for a in alerts:
        output.append({
            "threat": a.threat_type,
            "severity": a.severity,
            "action": a.action,
            "time": a.time.isoformat() if a.time else None
        })
    return jsonify(output)


@app.route("/api/alerts", methods=["GET"])
def get_all_alerts():
    """Return all alerts across all hosts."""
    alerts = Alert.query.order_by(Alert.time.desc()).limit(100).all()
    output = []
    for a in alerts:
        output.append({
            "host_name": a.host_name,
            "ip": a.ip,
            "threat": a.threat_type,
            "severity": a.severity,
            "action": a.action,
            "time": a.time.isoformat() if a.time else None
        })
    return jsonify(output)


@app.route("/api/agent/host-report", methods=["POST", "OPTIONS"])
def agent_report():
    """
    Receive host features from agent, run CNN prediction, return result.
    This is the real-time detection endpoint — no dummy data.
    """
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    # ── Authentication ──
    agent_key = request.headers.get("X-Agent-Key", "")
    if agent_key != AGENT_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data"}), 400

        features = data.get("features")
        host_name = data.get("host_name", "unknown")
        ip = data.get("ip", "0.0.0.0")

        if not features or len(features) != 15:
            return jsonify({"error": f"Expected 15 features, got {len(features) if features else 0}"}), 400

        # ── AI Prediction (real-time, no dummy data) ──
        threat, severity, action = "Normal", "Low", "No Action"

        if model_pipeline is not None:
            try:
                result = model_pipeline.predict(features)

                if isinstance(result, dict):
                    # Pipeline returns dict with 'prediction', 'probability'
                    pred_label = result.get('prediction', 'Normal')
                    probability = result.get('probability', 0.0)
                    if pred_label == 'Attack' or pred_label == 1:
                        threat = "Attack"
                        severity = "High" if probability > 0.8 else "Medium"
                        action = "Host Flagged"
                else:
                    # Pipeline returns array/list
                    pred_val = result[0] if hasattr(result, '__getitem__') else result
                    if isinstance(pred_val, (list, np.ndarray)):
                        pred_val = pred_val[0]
                    if pred_val == 1 or (isinstance(pred_val, float) and pred_val >= 0.5):
                        threat = "Attack"
                        severity = "High"
                        action = "Host Flagged"

            except Exception as e:
                print(f"[PREDICTION ERROR] {e}")
                # Don't return error to agent — log it server-side, return Normal
        else:
            print("[WARN] No model loaded — cannot predict. Returning Normal.")

        # ── Update Database ──
        now = datetime.datetime.now()

        host = Host.query.filter_by(host_name=host_name).first()
        if not host:
            host = Host(host_name=host_name, ip=ip, last_seen=now, status="Online", action=action)
            db.session.add(host)
        else:
            host.last_seen = now
            host.ip = ip
            host.action = action
            host.status = "Online"

        if threat != "Normal":
            alert = Alert(
                host_name=host_name, ip=ip,
                threat_type=threat, severity=severity,
                action=action, time=now
            )
            db.session.add(alert)

        db.session.commit()

        return jsonify({
            "threats": threat,
            "severity": severity,
            "action": action
        })

    except Exception as e:
        print(f"[CRITICAL] agent_report error: {e}")
        return jsonify({"error": "Internal Error"}), 500


@app.route("/api/dashboard/stats", methods=["GET"])
def dashboard_stats():
    """Quick stats for the dashboard."""
    total_hosts = Host.query.count()
    online_hosts = Host.query.filter_by(status="Online").count()
    total_alerts = Alert.query.count()
    recent_alerts = Alert.query.filter(
        Alert.time >= datetime.datetime.now() - datetime.timedelta(hours=1)
    ).count()

    return jsonify({
        "total_hosts": total_hosts,
        "online_hosts": online_hosts,
        "total_alerts": total_alerts,
        "recent_alerts_1h": recent_alerts,
        "model_loaded": model_pipeline is not None
    })


# ─────────────────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Ensure instance directory exists for SQLite
    os.makedirs(os.path.join(BASE_DIR, "instance"), exist_ok=True)

    with app.app_context():
        db.create_all()
        load_ai_model()

    print("=" * 50)
    print("  IDS Backend Server")
    print(f"  Model loaded: {model_pipeline is not None}")
    print(f"  Agent key:    {'(default)' if AGENT_KEY == 'changeme' else '(configured)'}")
    print(f"  Listening on: 0.0.0.0:5000")
    print("=" * 50)

    app.run(host='0.0.0.0', port=5000, threaded=False)