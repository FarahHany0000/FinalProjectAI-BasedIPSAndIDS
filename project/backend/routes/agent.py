import datetime
import platform
from flask import Blueprint, request, jsonify
from middleware.auth import require_agent_key, require_registered_agent, validate_json
from controllers.host_controller import HostController
from models.registered_agent import RegisteredAgent
from extensions import db

agent_bp = Blueprint("agent", __name__)


@agent_bp.route("/api/agent/register", methods=["POST"])
@require_agent_key
@validate_json("agent_id", "host_name")
def register_agent():
    """
    Agent calls this once on first startup to introduce itself.
    Stores agent_id + host info in the database.
    If already registered, just updates last_seen and returns OK.
    """
    data = request.get_json()
    agent_id = data["agent_id"]
    host_name = data["host_name"]
    ip = data.get("ip", request.remote_addr)
    os_info = data.get("os_info", "")

    now = datetime.datetime.now()
    agent = RegisteredAgent.query.filter_by(agent_id=agent_id).first()

    if agent:
        # Already registered — update info and return
        agent.host_name = host_name
        agent.ip = ip
        agent.os_info = os_info
        agent.last_seen = now
        agent.status = "Online"
        db.session.commit()
        return jsonify({
            "status": "already_registered",
            "agent_id": agent_id,
            "is_approved": agent.is_approved,
        })

    # New registration
    agent = RegisteredAgent(
        agent_id=agent_id,
        host_name=host_name,
        ip=ip,
        os_info=os_info,
        registered_at=now,
        last_seen=now,
        is_approved=True,
        status="Online",
    )
    db.session.add(agent)
    db.session.commit()

    print(f"[REGISTER] New agent: {host_name} ({ip}) id={agent_id[:8]}...")

    return jsonify({
        "status": "registered",
        "agent_id": agent_id,
        "is_approved": True,
    }), 201


@agent_bp.route("/api/agent/host-report", methods=["POST", "OPTIONS"])
@require_registered_agent
@validate_json("host_name", "features")
def host_report():
    """
    Receive 15 features from the host agent, run CNN prediction, return result.
    Agent must be registered first. Real-time detection — no dummy data.
    """
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    data = request.get_json()
    agent_id = request.headers.get("X-Agent-ID", data.get("agent_id", ""))
    ip = data.get("ip", request.remote_addr)

    try:
        # Update agent last_seen
        agent = RegisteredAgent.query.filter_by(agent_id=agent_id).first()
        if agent:
            agent.last_seen = datetime.datetime.now()
            agent.status = "Online"

        result = HostController.process_report(
            agent_id=agent_id,
            host_name=data["host_name"],
            ip=ip,
            features=data["features"],
        )
        return jsonify(result)

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        print(f"[CRITICAL] agent_report error: {e}")
        return jsonify({"error": "Internal Error"}), 500
