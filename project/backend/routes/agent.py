from flask import Blueprint, request, jsonify
from middleware.auth import require_agent_key, validate_json
from controllers.host_controller import HostController

agent_bp = Blueprint("agent", __name__)


@agent_bp.route("/api/agent/host-report", methods=["POST", "OPTIONS"])
@require_agent_key
@validate_json("host_name", "ip", "features")
def host_report():
    """
    Receive 15 features from the host agent, run CNN prediction, return result.
    Real-time detection — no dummy data.
    """
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    data = request.get_json()

    try:
        result = HostController.process_report(
            host_name=data["host_name"],
            ip=data["ip"],
            features=data["features"],
        )
        return jsonify(result)

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        print(f"[CRITICAL] agent_report error: {e}")
        return jsonify({"error": "Internal Error"}), 500
