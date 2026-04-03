import os
import threading
import datetime
from flask import Flask, jsonify
from extensions import db, cors, socketio
from utils.model_loader import ModelLoader

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Default: if no report in 30 seconds, host is considered offline
HEARTBEAT_TIMEOUT = int(os.environ.get("HEARTBEAT_TIMEOUT", "30"))

# Enable network sensor (default: True)
ENABLE_NETWORK_SENSOR = os.environ.get("ENABLE_NETWORK_SENSOR", "true").lower() == "true"

_network_agent = None  # Global reference to network sensor agent


def _heartbeat_monitor(app):
    """
    Background thread that runs every 10 seconds.
    Marks hosts and agents as 'Offline' if last_seen > HEARTBEAT_TIMEOUT.
    """
    import time
    while True:
        time.sleep(10)
        try:
            with app.app_context():
                from models.host import Host
                from models.registered_agent import RegisteredAgent

                cutoff = datetime.datetime.now() - datetime.timedelta(seconds=HEARTBEAT_TIMEOUT)

                # Mark stale hosts as Offline
                stale_hosts = Host.query.filter(
                    Host.last_seen < cutoff,
                    Host.status != "Offline",
                ).all()
                for h in stale_hosts:
                    h.status = "Offline"
                    print(f"[HEARTBEAT] {h.host_name} ({h.ip}) → Offline (no report for {HEARTBEAT_TIMEOUT}s)")

                # Mark stale agents as Offline
                stale_agents = RegisteredAgent.query.filter(
                    RegisteredAgent.last_seen < cutoff,
                    RegisteredAgent.status != "Offline",
                ).all()
                for a in stale_agents:
                    a.status = "Offline"

                if stale_hosts or stale_agents:
                    db.session.commit()
                    for h in stale_hosts:
                        socketio.emit("host_update", h.to_dict())

        except Exception as e:
            print(f"[HEARTBEAT ERROR] {e}")


def _start_network_sensor(app):
    """
    Start the network IDS sensor in a background thread.
    The sensor sniffs packets and sends alerts to /api/agent/network-alert.
    """
    global _network_agent

    def _sensor_thread():
        try:
            import sys
            import pathlib
            sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

            from agents.network_sensor.network_sensor import NetworkSensorAgent

            # Load the network model
            net_model = ModelLoader.load_network_model()
            if not net_model:
                print("[NETWORK SENSOR] Failed to load network model, skipping")
                return

            # Initialize and start sensor
            _network_agent = NetworkSensorAgent(
                model_engine=net_model,
                hostname="NetworkSensor-1",
                backend_url="http://127.0.0.1:5000/api/agent/network-alert",
                agent_key=app.config.get("AGENT_KEY", "changeme"),
            )
            _network_agent.run_loop()

        except Exception as e:
            print(f"[NETWORK SENSOR ERROR] {e}")

    sensor_daemon = threading.Thread(target=_sensor_thread, daemon=True, name="NetworkSensor")
    sensor_daemon.start()
    print("[OK] Network sensor thread started (running in background)")


def create_app():
    """Application factory — creates and configures the Flask app."""
    app = Flask(__name__)

    # ── Configuration ──
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URI", f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'ids.db')}"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "ids-secret-key")
    app.config["AGENT_KEY"] = os.environ.get("AGENT_KEY", "changeme")
    app.config["HEARTBEAT_TIMEOUT"] = HEARTBEAT_TIMEOUT

    # ── Extensions ──
    db.init_app(app)
    cors.init_app(app)
    socketio.init_app(app)

    # ── Register Blueprints (routes) ──
    from routes.health import health_bp
    from routes.agent import agent_bp
    from routes.dashboard import dashboard_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(agent_bp)
    app.register_blueprint(dashboard_bp)

    # ── Root page — quick status overview ──
    @app.route("/")
    def index():
        from models.host import Host
        from models.registered_agent import RegisteredAgent
        from models.alert import Alert
        return jsonify({
            "service": "AI-Based IDS/IPS Backend",
            "model_loaded": ModelLoader.is_loaded(),
            "network_sensor_enabled": ENABLE_NETWORK_SENSOR,
            "total_hosts": Host.query.count(),
            "online_hosts": Host.query.filter_by(status="Online").count(),
            "registered_agents": RegisteredAgent.query.count(),
            "total_alerts": Alert.query.count(),
            "endpoints": {
                "health": "/api/agent/health",
                "register": "/api/agent/register  [POST]",
                "host_report": "/api/agent/host-report  [POST]",
                "network_alert": "/api/agent/network-alert  [POST]",
                "stats": "/api/dashboard/stats",
                "alerts": "/api/dashboard/alerts",
                "agents": "/api/agents",
            },
        })

    # ── Create tables + load AI model on startup ──
    with app.app_context():
        from models import Host, Alert, RegisteredAgent  # noqa: F401
        os.makedirs(os.path.join(BASE_DIR, "instance"), exist_ok=True)
        db.create_all()
        ModelLoader.load()

    # ── Start heartbeat monitor thread ──
    monitor = threading.Thread(target=_heartbeat_monitor, args=(app,), daemon=True)
    monitor.start()
    print(f"[OK] Heartbeat monitor started (timeout: {HEARTBEAT_TIMEOUT}s)")

    # ── Start network sensor if enabled ──
    if ENABLE_NETWORK_SENSOR:
        _start_network_sensor(app)

    return app


if __name__ == "__main__":
    app = create_app()

    agent_key = app.config["AGENT_KEY"]
    print("=" * 60)
    print("  🔒 AI-Based IDS/IPS Backend Server")
    print(f"  📊 Model loaded:           {ModelLoader.is_loaded()}")
    print(f"  🌐 Network sensor:         {'ENABLED' if ENABLE_NETWORK_SENSOR else 'DISABLED'}")
    print(f"  🔑 Agent key:              {'(default)' if agent_key == 'changeme' else '(configured)'}")
    print(f"  ❤️  Heartbeat timeout:      {HEARTBEAT_TIMEOUT}s")
    print(f"  📡 Listening on:           0.0.0.0:5000")
    print("=" * 60)

    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
