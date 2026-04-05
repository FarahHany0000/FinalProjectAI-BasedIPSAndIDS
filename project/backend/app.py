import os
import threading
import datetime
from flask import Flask, jsonify
from extensions import db, cors, socketio
from src.infra import ModelLoader
from utils.response_orchestrator import InsiderThreatResponseOrchestrator

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


def _udp_discovery_listener(app):
    """
    UDP broadcast listener on port 5001.
    When an agent sends 'IDS_DISCOVER', we respond with our IP:port.
    This allows agents to auto-discover the server on any network.
    """
    import socket as sock
    try:
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
        s.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", 5001))
        s.settimeout(2.0)
        print("[DISCOVERY] UDP listener on port 5001 — agents can auto-discover this server")
        while True:
            try:
                data, addr = s.recvfrom(1024)
                msg = data.decode("utf-8", errors="ignore").strip()
                if msg == "IDS_DISCOVER":
                    # Get our IP facing the requesting agent
                    try:
                        temp = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
                        temp.connect((addr[0], 1))
                        our_ip = temp.getsockname()[0]
                        temp.close()
                    except Exception:
                        our_ip = "0.0.0.0"
                    response = f"IDS_SERVER:{our_ip}:5000"
                    s.sendto(response.encode("utf-8"), addr)
                    print(f"[DISCOVERY] Responded to {addr[0]} → {response}")
            except sock.timeout:
                continue
            except Exception as e:
                print(f"[DISCOVERY] Error: {e}")
    except Exception as e:
        print(f"[DISCOVERY] Could not start: {e}")


def _merge_duplicate_agents():
    """
    Merge duplicate registered agent rows that represent the same physical device.
    Keeps the newest row per (host_name, ip), preserving the freshest status.
    """
    from models.registered_agent import RegisteredAgent

    agents = RegisteredAgent.query.order_by(RegisteredAgent.last_seen.desc()).all()
    dedup = {}
    duplicates = []

    for agent in agents:
        key = f"{(agent.host_name or '').strip().lower()}|{agent.ip or ''}"
        if key not in dedup:
            dedup[key] = agent
        else:
            duplicates.append(agent)

    if duplicates:
        for row in duplicates:
            db.session.delete(row)
        db.session.commit()
        print(f"[CLEANUP] Removed {len(duplicates)} duplicate registered agent row(s).")


def _merge_duplicate_hosts():
    """
    Merge duplicate host rows for the same physical machine.
    Keeps the newest row per (host_name, ip) and removes stale duplicates.
    """
    from models.host import Host

    hosts = Host.query.order_by(Host.last_seen.desc()).all()
    dedup = {}
    duplicates = []

    for host in hosts:
        key = f"{(host.host_name or '').strip().lower()}|{host.ip or ''}"
        if key not in dedup:
            dedup[key] = host
        else:
            duplicates.append(host)

    if duplicates:
        for row in duplicates:
            db.session.delete(row)
        db.session.commit()
        print(f"[CLEANUP] Removed {len(duplicates)} duplicate host row(s).")


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

            # BPF filter to exclude noisy non-attack traffic
            bpf = "not port 53 and not port 1900 and not port 5353 and not port 57621 and not port 137 and not port 138 and not port 5000 and not port 67 and not port 68 and not port 5355 and not port 547 and not host 192.168.253.254 and not dst net 224.0.0.0/4"

            _network_agent = NetworkSensorAgent(
                model_engine=net_model,
                hostname="NetworkSensor-1",
                backend_url="http://127.0.0.1:5000/api/agent/network-alert",
                agent_key=app.config.get("AGENT_KEY", "changeme"),
                bpf_filter=bpf,
            )
            _network_agent.run_loop()

        except Exception as e:
            print(f"[NETWORK SENSOR ERROR] {e}")

    sensor_daemon = threading.Thread(target=_sensor_thread, daemon=True, name="NetworkSensor")
    sensor_daemon.start()
    print("[OK] Network sensor thread started (running in background)")


def _migrate_db(app):
    """Add missing columns to existing SQLite tables."""
    import sqlite3
    db_path = app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "")
    if not os.path.exists(db_path):
        return
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(alerts)")
        existing_cols = {row[1] for row in cursor.fetchall()}

        new_cols = {
            "is_blocked": "BOOLEAN DEFAULT 0",
            "src_ip": "VARCHAR(50) DEFAULT ''",
            "dst_ip": "VARCHAR(50) DEFAULT ''",
            "src_port": "INTEGER DEFAULT 0",
            "dst_port": "INTEGER DEFAULT 0",
        }
        for col_name, col_type in new_cols.items():
            if col_name not in existing_cols:
                cursor.execute(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_type}")
                print(f"[MIGRATE] Added column alerts.{col_name}")

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[MIGRATE] Warning: {e}")

    # Migrate registered_agents table
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(registered_agents)")
        cols = [row[1] for row in cursor.fetchall()]
        if "hardware_id" not in cols:
            cursor.execute("ALTER TABLE registered_agents ADD COLUMN hardware_id VARCHAR(128)")
            print("[MIGRATE] Added 'hardware_id' to registered_agents")
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[MIGRATE] registered_agents: {e}")


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
    app.config["TEST_MODE"] = os.environ.get("TEST_MODE", "true")
    app.config["PREVENTION_LOG_PATH"] = os.environ.get(
        "PREVENTION_LOG_PATH",
        os.path.join(BASE_DIR, "instance", "prevention_actions.log"),
    )

    # ── Extensions ──
    db.init_app(app)
    cors.init_app(app)
    socketio.init_app(app)

    # ── Register Blueprints (routes) ──
    from routes.health import health_bp
    from routes.agent import agent_bp
    from routes.dashboard import dashboard_bp
    from routes.prevention import prevention_bp
    from src.api import api_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(agent_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(prevention_bp)
    app.register_blueprint(api_bp)

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
                "prevention_status": "/api/prevention/status",
                "prevention_logs": "/api/prevention/logs",
                "prevention_thresholds": "/api/prevention/thresholds [GET|POST]",
            },
        })

    # ── Create tables + load AI model on startup ──
    with app.app_context():
        from models import Host, Alert, RegisteredAgent  # noqa: F401
        from models.prediction_log import PredictionLog  # noqa: F401
        os.makedirs(os.path.join(BASE_DIR, "instance"), exist_ok=True)
        db.create_all()

        # Migrate FIRST: add new columns before any queries that use them
        _migrate_db(app)

        _merge_duplicate_agents()
        _merge_duplicate_hosts()


        ModelLoader.load()
        InsiderThreatResponseOrchestrator.initialize_and_reset(app.config)

    # ── Start heartbeat monitor thread ──
    monitor = threading.Thread(target=_heartbeat_monitor, args=(app,), daemon=True)
    monitor.start()
    print(f"[OK] Heartbeat monitor started (timeout: {HEARTBEAT_TIMEOUT}s)")

    # ── UDP Discovery listener — agents find us automatically ──
    disc_thread = threading.Thread(target=_udp_discovery_listener, args=(app,), daemon=True)
    disc_thread.start()

    # ── Start network sensor if enabled ──
    if ENABLE_NETWORK_SENSOR:
        _start_network_sensor(app)

    return app


if __name__ == "__main__":
    app = create_app()

    agent_key = app.config["AGENT_KEY"]
    print("=" * 60)
    print("  AI-Based IDS/IPS Backend Server")
    print(f"  Model loaded:           {ModelLoader.is_loaded()}")
    print(f"  Network sensor:         {'ENABLED' if ENABLE_NETWORK_SENSOR else 'DISABLED'}")
    print(f"  Agent key:              {'(default)' if agent_key == 'changeme' else '(configured)'}")
    print(f"  Test mode:              {app.config['TEST_MODE']}")
    print(f"  Heartbeat timeout:      {HEARTBEAT_TIMEOUT}s")
    print(f"  Listening on:           0.0.0.0:5000")
    print("=" * 60)

    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
