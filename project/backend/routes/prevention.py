from flask import Blueprint, jsonify, request
from utils.response_orchestrator import InsiderThreatResponseOrchestrator

prevention_bp = Blueprint("prevention", __name__)


@prevention_bp.route("/api/prevention/status", methods=["GET"])
def prevention_status():
    """Current prevention mode/state for observability."""
    return jsonify(InsiderThreatResponseOrchestrator.get_status())


@prevention_bp.route("/api/prevention/logs", methods=["GET"])
def prevention_logs():
    """Return recent prevention log entries."""
    limit = request.args.get("limit", default=100, type=int)
    return jsonify(InsiderThreatResponseOrchestrator.get_recent_logs(limit=limit))


@prevention_bp.route("/api/prevention/thresholds", methods=["GET", "POST"])
def prevention_thresholds():
    """
    GET: return current low/medium/critical thresholds.
    POST: update thresholds at runtime.
    """
    if request.method == "GET":
        return jsonify(InsiderThreatResponseOrchestrator.get_thresholds())

    data = request.get_json(silent=True) or {}
    try:
        low = float(data.get("low"))
        medium = float(data.get("medium"))
        critical = float(data.get("critical"))
        updated = InsiderThreatResponseOrchestrator.update_thresholds(
            low=low, medium=medium, critical=critical
        )
        return jsonify({"status": "updated", "thresholds": updated})
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


@prevention_bp.route("/api/prevention/mode", methods=["POST"])
def prevention_mode():
    """Switch between TEST and LIVE mode."""
    data = request.get_json(silent=True) or {}
    test_mode = data.get("test_mode")
    if test_mode is None:
        return jsonify({"error": "test_mode required (true/false)"}), 400

    InsiderThreatResponseOrchestrator.set_test_mode(bool(test_mode))
    InsiderThreatResponseOrchestrator._write_log({
        "event": "mode_change",
        "test_mode": bool(test_mode),
    })
    mode = "TEST" if test_mode else "LIVE"
    print(f"[PREVENTION] Mode changed to {mode}")
    return jsonify({"status": "ok", "test_mode": bool(test_mode), "mode": mode})


@prevention_bp.route("/api/prevention/host/block", methods=["POST"])
def manual_host_block():
    """Manually block a host IP via firewall."""
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    host_name = data.get("host_name", "manual")
    if not ip:
        return jsonify({"error": "ip required"}), 400

    success = InsiderThreatResponseOrchestrator._apply_host_firewall_block(ip, host_name, "MANUAL")
    if success:
        return jsonify({"status": "blocked", "ip": ip})
    return jsonify({"error": "Failed to apply firewall rule. Run as Administrator."}), 500


@prevention_bp.route("/api/prevention/host/unblock", methods=["POST"])
def manual_host_unblock():
    """Remove a firewall block for a host IP."""
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400

    success = InsiderThreatResponseOrchestrator.remove_host_block(ip)
    if success:
        return jsonify({"status": "unblocked", "ip": ip})
    return jsonify({"error": "Failed to remove firewall rule"}), 500


@prevention_bp.route("/api/prevention/host/blocked", methods=["GET"])
def blocked_hosts():
    """List all currently blocked host IPs."""
    return jsonify(InsiderThreatResponseOrchestrator.get_blocked_hosts())


@prevention_bp.route("/api/prevention/host/verify", methods=["GET"])
def verify_host_rules():
    """Verify which IPS_HOST_BLOCK firewall rules exist in the OS."""
    rules = InsiderThreatResponseOrchestrator.verify_firewall_rules()
    return jsonify({"rules": rules, "count": len(rules)})


@prevention_bp.route("/api/prevention/host/clear-all", methods=["POST"])
def clear_all_host_blocks():
    """Remove all IPS_HOST_BLOCK firewall rules."""
    removed = InsiderThreatResponseOrchestrator.remove_all_host_blocks()
    return jsonify({"status": "cleared", "removed": removed})
