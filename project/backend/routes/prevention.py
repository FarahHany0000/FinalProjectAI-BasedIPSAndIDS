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
