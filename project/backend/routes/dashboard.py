import os
import shutil
import datetime
from flask import Blueprint, jsonify, request
from controllers.host_controller import HostController
from controllers.alert_controller import AlertController
from controllers.network_alert_controller import NetworkAlertController
from models.registered_agent import RegisteredAgent
from models.alert import Alert
from extensions import db, socketio

dashboard_bp = Blueprint("dashboard", __name__)

# ── Runtime config (modifiable via API) ──
_runtime_config = {
    "threshold": 0.70,
    "classification_threshold": 0.50,
    "prevention_enabled": True,
    "blocked_ips": [],
    "display_mode": "full",      # "full" = binary+classification, "binary" = binary only
}


@dashboard_bp.route("/api/hosts", methods=["GET"])
def get_hosts():
    return jsonify(HostController.get_all_hosts())


@dashboard_bp.route("/api/agents", methods=["GET"])
def get_agents():
    """Return all registered agents (for frontend)."""
    agents = RegisteredAgent.query.order_by(RegisteredAgent.last_seen.desc()).all()
    dedup = {}
    for agent in agents:
        key = f"{(agent.host_name or '').strip().lower()}|{agent.ip or ''}"
        if key not in dedup:
            dedup[key] = agent
    return jsonify([a.to_dict() for a in dedup.values()])


@dashboard_bp.route("/api/alerts/<hostname>", methods=["GET"])
def get_alerts(hostname):
    return jsonify(AlertController.get_alerts_for_host(hostname))


@dashboard_bp.route("/api/alerts", methods=["GET"])
def get_all_alerts():
    return jsonify(AlertController.get_all_alerts())


@dashboard_bp.route("/api/dashboard/stats", methods=["GET"])
def dashboard_stats():
    return jsonify(AlertController.get_dashboard_stats())


# ── Network-specific endpoints ──

@dashboard_bp.route("/api/network/alerts", methods=["GET"])
def get_network_alerts():
    """Get network alerts with optional limit."""
    limit = request.args.get("limit", 50, type=int)
    return jsonify(NetworkAlertController.get_network_alerts(limit))


@dashboard_bp.route("/api/network/stats", methods=["GET"])
def get_network_stats():
    """Get network alert statistics."""
    return jsonify(NetworkAlertController.get_network_stats())


# ── Threshold control ──

@dashboard_bp.route("/api/network/threshold", methods=["GET"])
def get_threshold():
    return jsonify({
        "threshold": _runtime_config["threshold"],
        "classification_threshold": _runtime_config["classification_threshold"],
        "display_mode": _runtime_config.get("display_mode", "full"),
    })


@dashboard_bp.route("/api/network/threshold", methods=["POST"])
def set_threshold():
    data = request.get_json()
    new_threshold = data.get("threshold")
    new_class_threshold = data.get("classification_threshold")

    if new_threshold is not None:
        if not (0.0 <= float(new_threshold) <= 1.0):
            return jsonify({"error": "Threshold must be between 0.0 and 1.0"}), 400
        _runtime_config["threshold"] = float(new_threshold)

    if new_class_threshold is not None:
        if not (0.0 <= float(new_class_threshold) <= 1.0):
            return jsonify({"error": "Classification threshold must be between 0.0 and 1.0"}), 400
        _runtime_config["classification_threshold"] = float(new_class_threshold)

    new_display_mode = data.get("display_mode")
    if new_display_mode in ("full", "binary"):
        _runtime_config["display_mode"] = new_display_mode

    # Update the running sniffer's thresholds if available
    try:
        from app import _network_agent
        if _network_agent and hasattr(_network_agent, 'sniffer'):
            _network_agent.sniffer.threshold = _runtime_config["threshold"]
            _network_agent.sniffer.classification_threshold = _runtime_config["classification_threshold"]
    except Exception:
        pass

    socketio.emit("config_update", {
        "threshold": _runtime_config["threshold"],
        "classification_threshold": _runtime_config["classification_threshold"],
        "display_mode": _runtime_config.get("display_mode", "full"),
    })
    return jsonify({
        "status": "ok",
        "threshold": _runtime_config["threshold"],
        "classification_threshold": _runtime_config["classification_threshold"],
        "display_mode": _runtime_config.get("display_mode", "full"),
    })


# ── Prevention control ──

@dashboard_bp.route("/api/network/prevention", methods=["GET"])
def get_prevention():
    return jsonify({
        "enabled": _runtime_config["prevention_enabled"],
        "blocked_ips": _runtime_config["blocked_ips"],
    })


@dashboard_bp.route("/api/network/prevention", methods=["POST"])
def set_prevention():
    data = request.get_json()
    enabled = data.get("enabled")
    if enabled is not None:
        _runtime_config["prevention_enabled"] = bool(enabled)

        if not bool(enabled):
            # When disabling prevention, remove all firewall rules
            _remove_all_firewall_rules()
            _runtime_config["blocked_ips"] = []

    socketio.emit("config_update", {
        "prevention_enabled": _runtime_config["prevention_enabled"],
        "blocked_ips": _runtime_config["blocked_ips"],
    })
    return jsonify({
        "status": "ok",
        "enabled": _runtime_config["prevention_enabled"],
        "blocked_ips": _runtime_config["blocked_ips"],
    })


@dashboard_bp.route("/api/network/prevention/block", methods=["POST"])
def block_ip():
    """Manually block an IP address."""
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP required"}), 400

    if ip not in _runtime_config["blocked_ips"]:
        _runtime_config["blocked_ips"].append(ip)
        _apply_firewall_block(ip)

    socketio.emit("config_update", {"blocked_ips": _runtime_config["blocked_ips"]})
    return jsonify({"status": "blocked", "ip": ip})


@dashboard_bp.route("/api/network/prevention/unblock", methods=["POST"])
def unblock_ip():
    """Manually unblock an IP address."""
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP required"}), 400

    if ip in _runtime_config["blocked_ips"]:
        _runtime_config["blocked_ips"].remove(ip)
        _remove_firewall_block(ip)

    socketio.emit("config_update", {"blocked_ips": _runtime_config["blocked_ips"]})
    return jsonify({"status": "unblocked", "ip": ip})


@dashboard_bp.route("/api/network/prevention/reset", methods=["POST"])
def reset_prevention():
    """Remove all firewall rules and reset prevention state."""
    _remove_all_firewall_rules()
    _runtime_config["blocked_ips"] = []
    _runtime_config["prevention_enabled"] = False

    socketio.emit("config_update", {
        "prevention_enabled": False,
        "blocked_ips": [],
    })
    return jsonify({"status": "ok", "message": "All firewall rules removed, prevention disabled"})


# ── Archive ──

@dashboard_bp.route("/api/alerts/archive", methods=["POST"])
def archive_alerts():
    """Move all current alerts to archive and clear the active table."""
    try:
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        archive_dir = os.path.join(BASE_DIR, "..", "instance", "archive")
        os.makedirs(archive_dir, exist_ok=True)

        alert_count = Alert.query.count()
        if alert_count == 0:
            return jsonify({"status": "ok", "message": "No alerts to archive", "archived": 0})

        # Export alerts to a timestamped JSON file
        alerts = Alert.query.order_by(Alert.time.desc()).all()
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_file = os.path.join(archive_dir, f"alerts_{timestamp}.json")

        import json
        alert_data = [a.to_dict() for a in alerts]
        with open(archive_file, "w") as f:
            json.dump(alert_data, f, indent=2, default=str)

        # Delete all alerts from the active table
        Alert.query.delete()
        db.session.commit()

        # Flush sniffer buffer to avoid stale detections
        try:
            from app import _network_agent
            if _network_agent and hasattr(_network_agent, 'sniffer'):
                _network_agent.sniffer.packet_buffer = []
                # Drain the result queue
                while not _network_agent.sniffer.result_queue.empty():
                    try:
                        _network_agent.sniffer.result_queue.get_nowait()
                    except Exception:
                        break
        except Exception:
            pass

        return jsonify({
            "status": "ok",
            "message": f"Archived {alert_count} alerts",
            "archived": alert_count,
            "archive_file": os.path.basename(archive_file),
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/alerts/archives", methods=["GET"])
def list_archives():
    """List all archived alert files."""
    try:
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        archive_dir = os.path.join(BASE_DIR, "..", "instance", "archive")
        if not os.path.exists(archive_dir):
            return jsonify([])

        archives = []
        for f in sorted(os.listdir(archive_dir), reverse=True):
            if f.endswith(".json"):
                path = os.path.join(archive_dir, f)
                size = os.path.getsize(path)
                archives.append({"filename": f, "size_kb": round(size / 1024, 1)})

        return jsonify(archives)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/alerts/archives/<filename>", methods=["GET"])
def get_archive(filename):
    """Get the contents of a specific archive file."""
    try:
        import json
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        archive_path = os.path.join(BASE_DIR, "..", "instance", "archive", filename)
        if not os.path.exists(archive_path):
            return jsonify({"error": "Archive not found"}), 404
        with open(archive_path) as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Firewall helper functions (Windows netsh) ──

def _apply_firewall_block(ip: str):
    """Add a Windows Firewall rule to block an IP."""
    import subprocess
    rule_name = f"IDS_BLOCK_{ip.replace('.', '_')}"
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=in", "action=block",
             f"remoteip={ip}", "enable=yes"],
            capture_output=True, text=True, timeout=10
        )
        print(f"[PREVENTION] Blocked IP: {ip}")
    except Exception as e:
        print(f"[PREVENTION] Failed to block {ip}: {e}")


def _remove_firewall_block(ip: str):
    """Remove a Windows Firewall rule for an IP."""
    import subprocess
    rule_name = f"IDS_BLOCK_{ip.replace('.', '_')}"
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             f"name={rule_name}"],
            capture_output=True, text=True, timeout=10
        )
        print(f"[PREVENTION] Unblocked IP: {ip}")
    except Exception as e:
        print(f"[PREVENTION] Failed to unblock {ip}: {e}")


def _remove_all_firewall_rules():
    """Remove all IDS-created firewall rules."""
    import subprocess
    try:
        # List all rules matching our naming pattern
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
            capture_output=True, text=True, timeout=15
        )
        lines = result.stdout.split("\n")
        for line in lines:
            if "IDS_BLOCK_" in line:
                rule_name = line.split(":")[-1].strip()
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule",
                     f"name={rule_name}"],
                    capture_output=True, text=True, timeout=10
                )
        print("[PREVENTION] All IDS firewall rules removed")
    except Exception as e:
        print(f"[PREVENTION] Failed to remove all rules: {e}")
