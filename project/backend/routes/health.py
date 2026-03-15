import datetime
from flask import Blueprint, jsonify
from utils.model_loader import ModelLoader

health_bp = Blueprint("health", __name__)


@health_bp.route("/api/agent/health", methods=["GET"])
def health_check():
    """Heartbeat endpoint — agents ping this to check if backend is alive."""
    return jsonify({
        "status": "ok",
        "model_loaded": ModelLoader.is_loaded(),
        "time": datetime.datetime.now().isoformat(),
    })
