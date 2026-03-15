from flask import Blueprint, jsonify
from controllers.host_controller import HostController
from controllers.alert_controller import AlertController
from models.registered_agent import RegisteredAgent

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/api/hosts", methods=["GET"])
def get_hosts():
    """Return all registered hosts (for frontend)."""
    return jsonify(HostController.get_all_hosts())


@dashboard_bp.route("/api/agents", methods=["GET"])
def get_agents():
    """Return all registered agents (for frontend)."""
    agents = RegisteredAgent.query.all()
    return jsonify([a.to_dict() for a in agents])


@dashboard_bp.route("/api/alerts/<hostname>", methods=["GET"])
def get_alerts(hostname):
    """Return alert logs for a specific host."""
    return jsonify(AlertController.get_alerts_for_host(hostname))


@dashboard_bp.route("/api/alerts", methods=["GET"])
def get_all_alerts():
    """Return all alerts across all hosts."""
    return jsonify(AlertController.get_all_alerts())


@dashboard_bp.route("/api/dashboard/stats", methods=["GET"])
def dashboard_stats():
    """Aggregate stats for the dashboard."""
    return jsonify(AlertController.get_dashboard_stats())
