import os
import json
import shutil
import datetime
from flask import Blueprint, jsonify, request
from controllers.host_controller import HostController
from controllers.alert_controller import AlertController
from controllers.network_alert_controller import NetworkAlertController
from models.registered_agent import RegisteredAgent
from models.alert import Alert
from models.prediction_log import PredictionLog
from routes.agent import _agent_alert_events
from extensions import db, socketio

dashboard_bp = Blueprint("dashboard", __name__)

# ── Threshold persistence ──
_THRESHOLD_FILE = os.path.join(os.path.dirname(__file__), "..", "threshold_config.json")
_DEFAULT_CONFIG = {
    "threshold": 0.70,
    "classification_threshold": 0.50,
    "prevention_enabled": True,
    "host_prevention_enabled": True,
    "blocked_ips": [],
    "display_mode": "full",
}

def _load_persisted_config():
    """Load thresholds from JSON file if it exists, else use defaults."""
    config = dict(_DEFAULT_CONFIG)
    try:
        if os.path.exists(_THRESHOLD_FILE):
            with open(_THRESHOLD_FILE, "r") as f:
                saved = json.load(f)
            for key in ("threshold", "classification_threshold", "display_mode"):
                if key in saved:
                    config[key] = saved[key]
            print(f"[CONFIG] Loaded persisted thresholds: binary={config['threshold']}, "
                  f"classification={config['classification_threshold']}")
    except Exception as e:
        print(f"[CONFIG] Could not load threshold file: {e}")
    return config

def _save_persisted_config():
    """Save current thresholds to JSON file for persistence across restarts."""
    try:
        to_save = {
            "threshold": _runtime_config["threshold"],
            "classification_threshold": _runtime_config["classification_threshold"],
            "display_mode": _runtime_config.get("display_mode", "full"),
        }
        with open(_THRESHOLD_FILE, "w") as f:
            json.dump(to_save, f, indent=2)
    except Exception as e:
        print(f"[CONFIG] Could not save threshold file: {e}")

# ── Runtime config (loads persisted values on startup) ──
_runtime_config = _load_persisted_config()


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


# ── Host Detail & Prediction Timeline ──

@dashboard_bp.route("/api/hosts/<hostname>/predictions", methods=["GET"])
def get_host_predictions(hostname):
    """Get prediction timeline for a specific host (last 30 min default)."""
    from models.prediction_log import PredictionLog
    minutes = request.args.get("minutes", 30, type=int)
    limit = request.args.get("limit", 200, type=int)
    cutoff = datetime.datetime.now() - datetime.timedelta(minutes=minutes)
    logs = (PredictionLog.query
            .filter(PredictionLog.host_name == hostname,
                    PredictionLog.time >= cutoff)
            .order_by(PredictionLog.time.desc())
            .limit(limit)
            .all())
    return jsonify([l.to_dict() for l in logs])


@dashboard_bp.route("/api/hosts/<hostname>/detail", methods=["GET"])
def get_host_detail(hostname):
    """Get comprehensive host detail including latest features, predictions, alerts."""
    from models.prediction_log import PredictionLog
    from models.host import Host

    # Latest host record
    host = Host.query.filter_by(host_name=hostname).order_by(Host.last_seen.desc()).first()
    host_data = host.to_dict() if host else {}

    # Fallback: get os_info from RegisteredAgent if host doesn't have it
    if host_data and not host_data.get("os_info"):
        from models.registered_agent import RegisteredAgent
        agent = RegisteredAgent.query.filter_by(host_name=hostname).first()
        if agent and agent.os_info:
            host_data["os_info"] = agent.os_info

    # Latest prediction with features
    latest_pred = (PredictionLog.query
                   .filter_by(host_name=hostname)
                   .order_by(PredictionLog.time.desc())
                   .first())
    latest_pred_data = latest_pred.to_dict() if latest_pred else None

    # Recent alerts for this host
    alerts = (Alert.query
              .filter_by(host_name=hostname)
              .order_by(Alert.time.desc())
              .limit(20)
              .all())

    # Prediction stats (last 30 min)
    cutoff = datetime.datetime.now() - datetime.timedelta(minutes=30)
    recent_preds = (PredictionLog.query
                    .filter(PredictionLog.host_name == hostname,
                            PredictionLog.time >= cutoff)
                    .all())

    attack_count = sum(1 for p in recent_preds if p.prediction == "Attack")
    avg_prob = sum(p.probability for p in recent_preds) / len(recent_preds) if recent_preds else 0

    # Alert stats for this host
    total_host_alerts = Alert.query.filter_by(host_name=hostname).count()
    malicious_alerts = Alert.query.filter(
        Alert.host_name == hostname,
        Alert.threat_type != "Normal",
        Alert.threat_type != None
    ).count()

    return jsonify({
        "host": host_data,
        "latest_prediction": latest_pred_data,
        "alerts": [a.to_dict() for a in alerts],
        "stats": {
            "total_predictions_30m": len(recent_preds),
            "attack_predictions_30m": attack_count,
            "avg_probability_30m": round(avg_prob, 4),
            "total_alerts": total_host_alerts,
            "malicious_count": malicious_alerts,
        }
    })


@dashboard_bp.route("/api/alerts/trends", methods=["GET"])
def get_alert_trends():
    """Get alert counts grouped by hour for the last 24 hours."""
    hours = request.args.get("hours", 24, type=int)
    cutoff = datetime.datetime.now() - datetime.timedelta(hours=hours)
    alerts = Alert.query.filter(Alert.time >= cutoff).all()

    # Group by hour
    hourly = {}
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for alert in alerts:
        hour_key = alert.time.strftime("%Y-%m-%d %H:00") if alert.time else "unknown"
        hourly[hour_key] = hourly.get(hour_key, 0) + 1
        sev = alert.severity or "Medium"
        if sev in severity_counts:
            severity_counts[sev] += 1

    return jsonify({
        "hourly": hourly,
        "severity": severity_counts,
        "total": len(alerts),
    })


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
            print(f"[THRESHOLD] Updated sniffer: binary={_runtime_config['threshold']}, "
                  f"classification={_runtime_config['classification_threshold']}")
        else:
            print("[THRESHOLD] Warning: network agent not available for live update")
    except Exception as e:
        print(f"[THRESHOLD] Warning: could not push to sniffer: {e}")

    # Persist thresholds to disk for next restart
    _save_persisted_config()

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
    # Dedup blocked_ips before returning
    _runtime_config["blocked_ips"] = list(dict.fromkeys(_runtime_config["blocked_ips"]))
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
    """Manually unblock an IP address — removes firewall rules + clears from list."""
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP required"}), 400

    if ip in _runtime_config["blocked_ips"]:
        _runtime_config["blocked_ips"].remove(ip)
    _remove_firewall_block(ip)  # always try to remove rules even if not in list

    # Clear alert history for this IP so it doesn't re-block instantly
    try:
        NetworkAlertController._ip_alert_history.pop(ip, None)
    except Exception:
        pass

    _save_persisted_config()
    socketio.emit("config_update", {"blocked_ips": _runtime_config["blocked_ips"]})
    return jsonify({"status": "unblocked", "ip": ip})


@dashboard_bp.route("/api/network/prevention/reset", methods=["POST"])
def reset_prevention():
    """Remove all firewall rules and reset prevention state completely."""
    _remove_all_firewall_rules()
    _runtime_config["blocked_ips"] = []
    _runtime_config["prevention_enabled"] = True  # keep enabled, just clear blocks
    _save_persisted_config()

    # Clear auto-block alert history so counters start fresh
    try:
        NetworkAlertController._ip_alert_history.clear()
    except Exception:
        pass

    socketio.emit("config_update", {
        "prevention_enabled": True,
        "blocked_ips": [],
    })
    return jsonify({
        "status": "ok",
        "message": "All firewall rules removed, blocked IPs cleared, system clean"
    })


# ── Archive ──

@dashboard_bp.route("/api/alerts/archive", methods=["POST"])
def archive_alerts():
    """Move all current alerts to archive and clear the active table."""
    try:
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        archive_dir = os.path.join(BASE_DIR, "..", "instance", "archive", "network")
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
        archive_dir = os.path.join(BASE_DIR, "..", "instance", "archive", "network")
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
        archive_path = os.path.join(BASE_DIR, "..", "instance", "archive", "network", filename)
        if not os.path.exists(archive_path):
            return jsonify({"error": "Archive not found"}), 404
        with open(archive_path) as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Host Archive ──

@dashboard_bp.route("/api/host-alerts/archive", methods=["POST"])
def archive_host_alerts():
    """Archive host prediction logs + agent events, then clear them."""
    try:
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        archive_dir = os.path.join(BASE_DIR, "..", "instance", "archive", "host")
        os.makedirs(archive_dir, exist_ok=True)

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        # Archive prediction logs
        predictions = PredictionLog.query.order_by(PredictionLog.time.desc()).all()
        pred_count = len(predictions)
        if pred_count > 0:
            pred_file = os.path.join(archive_dir, f"host_predictions_{timestamp}.json")
            with open(pred_file, "w") as f:
                json.dump([p.to_dict() for p in predictions], f, indent=2, default=str)

        # Archive agent alert events
        all_events = []
        for host_events in _agent_alert_events.values():
            all_events.extend(host_events)
        events_count = len(all_events)
        if events_count > 0:
            events_file = os.path.join(archive_dir, f"agent_events_{timestamp}.json")
            with open(events_file, "w") as f:
                json.dump(all_events, f, indent=2, default=str)

        if pred_count == 0 and events_count == 0:
            return jsonify({"status": "ok", "message": "Nothing to archive",
                            "predictions_archived": 0, "events_archived": 0})

        # Clear prediction logs from DB
        PredictionLog.query.delete()
        db.session.commit()

        # Clear agent events and notify frontend
        _agent_alert_events.clear()
        socketio.emit("prevention_reset", {"host_name": "__all__"})

        return jsonify({
            "status": "ok",
            "message": f"Archived {pred_count} predictions + {events_count} agent events",
            "predictions_archived": pred_count,
            "events_archived": events_count,
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/host-alerts/archives", methods=["GET"])
def list_host_archives():
    """List all host archive files (predictions + agent events)."""
    try:
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        archive_dir = os.path.join(BASE_DIR, "..", "instance", "archive", "host")
        if not os.path.exists(archive_dir):
            return jsonify([])

        archives = []
        for f in sorted(os.listdir(archive_dir), reverse=True):
            if f.endswith(".json"):
                path = os.path.join(archive_dir, f)
                size = os.path.getsize(path)
                file_type = "predictions" if f.startswith("host_predictions") else "agent_events"
                archives.append({"filename": f, "size_kb": round(size / 1024, 1), "type": file_type})

        return jsonify(archives)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/host-alerts/archives/<filename>", methods=["GET"])
def get_host_archive(filename):
    """Get contents of a specific host archive file."""
    try:
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        archive_path = os.path.join(BASE_DIR, "..", "instance", "archive", "host", filename)
        if not os.path.exists(archive_path):
            return jsonify({"error": "Archive not found"}), 404
        with open(archive_path) as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/host-alerts/archives/<filename>", methods=["DELETE"])
def delete_host_archive(filename):
    """Delete a specific host archive file."""
    try:
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        archive_path = os.path.join(BASE_DIR, "..", "instance", "archive", "host", filename)
        if not os.path.exists(archive_path):
            return jsonify({"error": "Archive not found"}), 404
        os.remove(archive_path)
        return jsonify({"status": "ok", "message": f"Deleted {filename}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/host-alerts/clear", methods=["POST"])
def clear_host_alerts():
    """Delete all host prediction logs and agent events without archiving."""
    try:
        pred_count = PredictionLog.query.count()
        PredictionLog.query.delete()
        db.session.commit()

        events_count = sum(len(v) for v in _agent_alert_events.values())
        _agent_alert_events.clear()
        socketio.emit("prevention_reset", {"host_name": "__all__"})

        return jsonify({
            "status": "ok",
            "message": f"Cleared {pred_count} predictions + {events_count} agent events",
            "predictions_cleared": pred_count,
            "events_cleared": events_count,
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


# ── Firewall helper functions (Windows netsh) ──

def _apply_firewall_block(ip: str):
    """Add Windows Firewall rules to fully block an IP (inbound + outbound)."""
    import subprocess
    if ip.startswith("127.") or ip == "::1" or ip == "localhost":
        print(f"[PREVENTION] Skipping localhost IP {ip} — firewall can't block loopback")
        return False
    rule_name_in = f"IDS_BLOCK_{ip.replace('.', '_')}_IN"
    rule_name_out = f"IDS_BLOCK_{ip.replace('.', '_')}_OUT"
    try:
        r1 = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name_in}", "dir=in", "action=block",
             f"remoteip={ip}", "protocol=any", "enable=yes"],
            capture_output=True, text=True, timeout=10
        )
        r2 = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name_out}", "dir=out", "action=block",
             f"remoteip={ip}", "protocol=any", "enable=yes"],
            capture_output=True, text=True, timeout=10
        )
        if r1.returncode == 0 or r2.returncode == 0:
            print(f"[PREVENTION] ✓ Blocked IP: {ip} (in+out) — ping/traffic will be blocked")
            return True
        else:
            err = (r1.stderr or r1.stdout or "").strip()
            if "elevation" in err.lower():
                print(f"[PREVENTION] ⚠ Need Administrator for firewall! Run backend as admin.")
            else:
                print(f"[PREVENTION] Failed to block {ip}: {err}")
            return False
    except Exception as e:
        print(f"[PREVENTION] Failed to block {ip}: {e}")
        return False


def _remove_firewall_block(ip: str):
    """Remove Windows Firewall rules for an IP (inbound + outbound)."""
    import subprocess
    # Method 1: delete by known rule names
    for suffix in ("_IN", "_OUT", ""):
        rule_name = f"IDS_BLOCK_{ip.replace('.', '_')}{suffix}"
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={rule_name}"],
                capture_output=True, text=True, timeout=10
            )
        except Exception:
            pass
    # Method 2: delete ANY rule blocking this remoteip (catches all patterns)
    for direction in ("in", "out"):
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 "name=all", f"dir={direction}", f"remoteip={ip}"],
                capture_output=True, text=True, timeout=10
            )
        except Exception:
            pass
    print(f"[PREVENTION] Unblocked IP: {ip}")


def _remove_all_firewall_rules():
    """Remove ALL IDS/IPS firewall rules (network + host)."""
    import subprocess
    removed = 0

    # 1. Delete by known blocked IPs (most reliable)
    for ip in list(_runtime_config.get("blocked_ips", [])):
        _remove_firewall_block(ip)
        removed += 1

    # 2. Sweep by rule name pattern (catches orphaned rules)
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
            capture_output=True, text=True, timeout=15
        )
        for line in result.stdout.split("\n"):
            if "IDS_BLOCK_" in line or "IPS_HOST_BLOCK_" in line:
                rule_name = line.split(":")[-1].strip()
                if rule_name:
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "delete", "rule",
                         f"name={rule_name}"],
                        capture_output=True, text=True, timeout=10
                    )
                    removed += 1
    except Exception as e:
        print(f"[PREVENTION] Rule sweep error: {e}")

    # 3. Also clear host-level blocks
    try:
        from utils.response_orchestrator import InsiderThreatResponseOrchestrator
        host_removed = InsiderThreatResponseOrchestrator.remove_all_host_blocks()
        removed += host_removed
    except Exception as e:
        print(f"[PREVENTION] Host block cleanup error: {e}")

    print(f"[PREVENTION] Removed {removed} total firewall rules — system clean")
