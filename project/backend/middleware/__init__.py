from functools import wraps
from flask import request, jsonify, current_app


def require_agent_key(f):
    """Middleware decorator: validates X-Agent-Key header on agent endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        agent_key = request.headers.get("X-Agent-Key", "")
        expected_key = current_app.config.get("AGENT_KEY", "changeme")
        if agent_key != expected_key:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated
