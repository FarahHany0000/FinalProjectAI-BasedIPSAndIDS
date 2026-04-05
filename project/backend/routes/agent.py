import json
import datetime
import platform
from flask import Blueprint, request, jsonify
from middleware.auth import require_agent_key, require_registered_agent, validate_json
from controllers.host_controller import HostController
from controllers.network_alert_controller import NetworkAlertController
from models.registered_agent import RegisteredAgent
from models.prediction_log import PredictionLog
from extensions import db, socketio

agent_bp = Blueprint("agent", __name__)


@agent_bp.route("/api/agent/register", methods=["POST"])
@require_agent_key
@validate_json("agent_id", "host_name")
def register_agent():
    """
    Agent calls this once on first startup to introduce itself.
    New devices require admin approval (is_approved=False).
    Hardware fingerprint prevents agent cloning.
    """
    data = request.get_json()
    agent_id = data["agent_id"]
    host_name = data["host_name"]
    ip = data.get("ip", request.remote_addr)
    os_info = data.get("os_info", "")
    hardware_id = data.get("hardware_id", "")

    now = datetime.datetime.now()
    agent = RegisteredAgent.query.filter_by(agent_id=agent_id).first()

    if agent:
        # Agent ID exists — check hardware fingerprint
        if hardware_id and agent.hardware_id and hardware_id != agent.hardware_id:
            # SECURITY: Someone copied the agent to a different machine
            print(f"[SECURITY] Agent clone detected! agent_id={agent_id[:8]} "
                  f"expected_hw={agent.hardware_id[:12]} got_hw={hardware_id[:12]}")
            return jsonify({
                "status": "rejected",
                "error": "Hardware fingerprint mismatch. This agent may have been cloned.",
                "is_approved": False,
            }), 403

        # Same hardware or no hardware_id yet — update info
        agent.host_name = host_name
        agent.ip = ip
        agent.os_info = os_info
        agent.last_seen = now
        agent.status = "Online"
        if hardware_id and not agent.hardware_id:
            agent.hardware_id = hardware_id
        db.session.commit()

        # Emit agent update to frontend
        socketio.emit("agent_update", agent.to_dict())

        return jsonify({
            "status": "already_registered",
            "agent_id": agent_id,
            "is_approved": agent.is_approved,
        })

    # Check if this hardware already has a registered agent (device reinstalled)
    if hardware_id:
        existing_hw = RegisteredAgent.query.filter_by(hardware_id=hardware_id).first()
        if existing_hw:
            # Same physical device, new agent_id — rebind
            existing_hw.agent_id = agent_id
            existing_hw.host_name = host_name
            existing_hw.ip = ip
            existing_hw.os_info = os_info
            existing_hw.last_seen = now
            existing_hw.status = "Online"
            db.session.commit()
            socketio.emit("agent_update", existing_hw.to_dict())
            return jsonify({
                "status": "rebound_existing_device",
                "agent_id": agent_id,
                "is_approved": existing_hw.is_approved,
            })

    # Recovery: rebind by hostname+ip if no hardware_id match
    existing_device = None
    if ip:
        existing_device = (
            RegisteredAgent.query
            .filter_by(host_name=host_name, ip=ip)
            .order_by(RegisteredAgent.last_seen.desc())
            .first()
        )
    if not existing_device:
        existing_device = (
            RegisteredAgent.query
            .filter_by(host_name=host_name)
            .order_by(RegisteredAgent.last_seen.desc())
            .first()
        )

    if existing_device:
        existing_device.agent_id = agent_id
        existing_device.host_name = host_name
        existing_device.ip = ip
        existing_device.os_info = os_info
        existing_device.last_seen = now
        existing_device.status = "Online"
        if hardware_id:
            existing_device.hardware_id = hardware_id
        db.session.commit()
        socketio.emit("agent_update", existing_device.to_dict())
        return jsonify({
            "status": "rebound_existing_device",
            "agent_id": agent_id,
            "is_approved": existing_device.is_approved,
        })

    # ── NEW DEVICE — requires admin approval ──
    agent = RegisteredAgent(
        agent_id=agent_id,
        hardware_id=hardware_id or None,
        host_name=host_name,
        ip=ip,
        os_info=os_info,
        registered_at=now,
        last_seen=now,
        is_approved=False,  # Pending admin approval
        status="Pending",
    )
    db.session.add(agent)
    db.session.commit()

    print(f"[REGISTER] New device PENDING approval: {host_name} ({ip}) id={agent_id[:8]}...")
    socketio.emit("agent_update", agent.to_dict())
    socketio.emit("pending_device", {
        "host_name": host_name,
        "ip": ip,
        "os_info": os_info,
        "agent_id": agent_id,
        "time": now.isoformat(),
    })

    return jsonify({
        "status": "pending_approval",
        "agent_id": agent_id,
        "is_approved": False,
    }), 201


@agent_bp.route("/api/agent/host-report", methods=["POST", "OPTIONS"])
@require_registered_agent
@validate_json("host_name", "features")
def host_report():
    """
    Receive 15 features from the host agent, run prediction, return result.
    Also logs prediction for risk timeline.
    """
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    data = request.get_json()
    agent_id = request.headers.get("X-Agent-ID", data.get("agent_id", ""))
    ip = data.get("ip", request.remote_addr)
    activity_type = data.get("activity_type", "FILE")

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
            activity_type=activity_type,
            os_info=data.get("os_info") or (agent.os_info if agent else None),
        )

        # Log prediction for risk timeline
        try:
            models_data = result.get("models", {})
            log_entry = PredictionLog(
                host_name=data["host_name"],
                agent_id=agent_id,
                prediction=result.get("prediction", "Normal"),
                probability=result.get("probability", 0.0),
                xgb_prediction=models_data.get("XGBoost", {}).get("prediction", ""),
                xgb_probability=models_data.get("XGBoost", {}).get("probability", 0.0),
                rf_prediction=models_data.get("RandomForest", {}).get("prediction", ""),
                rf_probability=models_data.get("RandomForest", {}).get("probability", 0.0),
                features=json.dumps(data["features"]),
                prevention_level=result.get("prevention", {}).get("level", "NONE"),
                prevention_action=result.get("prevention", {}).get("action", ""),
                time=datetime.datetime.now(),
            )
            db.session.add(log_entry)
            db.session.commit()
        except Exception as e:
            print(f"[WARN] Failed to log prediction: {e}")

        return jsonify(result)

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        print(f"[CRITICAL] agent_report error: {e}")
        return jsonify({"error": "Internal Error"}), 500


@agent_bp.route("/api/agent/network-alert", methods=["POST"])
@require_agent_key
@validate_json("source", "attack_type", "confidence")
def network_alert():
    """Receive network attack detection from the network sensor."""
    try:
        data = request.get_json()
        result = NetworkAlertController.process_network_detection(data)
        if result["status"] == "success":
            return jsonify(result), 201
        else:
            return jsonify(result), 400
    except Exception as e:
        print(f"[NETWORK ALERT] Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Admin: Approve / Reject Agents ──

@agent_bp.route("/api/agents/<int:agent_db_id>/approve", methods=["POST"])
def approve_agent(agent_db_id):
    """Admin approves a pending agent."""
    agent = RegisteredAgent.query.get(agent_db_id)
    if not agent:
        return jsonify({"error": "Agent not found"}), 404
    agent.is_approved = True
    agent.status = "Online"
    db.session.commit()
    socketio.emit("agent_update", agent.to_dict())
    print(f"[ADMIN] Approved agent: {agent.host_name} ({agent.ip})")
    return jsonify({"status": "approved", "agent": agent.to_dict()})


@agent_bp.route("/api/agents/<int:agent_db_id>/reject", methods=["POST"])
def reject_agent(agent_db_id):
    """Admin rejects and removes a pending agent."""
    agent = RegisteredAgent.query.get(agent_db_id)
    if not agent:
        return jsonify({"error": "Agent not found"}), 404
    agent_dict = agent.to_dict()
    db.session.delete(agent)
    db.session.commit()
    socketio.emit("agent_removed", agent_dict)
    print(f"[ADMIN] Rejected agent: {agent_dict['host_name']}")
    return jsonify({"status": "rejected"})
