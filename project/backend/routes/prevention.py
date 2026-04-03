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
