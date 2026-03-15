from functools import wraps
from flask import request, jsonify, current_app


def require_agent_key(f):
    """Validate X-Agent-Key header. Returns 401 if key is missing or wrong."""
    @wraps(f)
    def decorated(*args, **kwargs):
        agent_key = request.headers.get("X-Agent-Key", "")
        expected_key = current_app.config.get("AGENT_KEY", "changeme")
        if agent_key != expected_key:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def validate_json(*required_fields):
    """Validate that request has JSON body with required fields."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json(silent=True)
            if not data:
                return jsonify({"error": "Request body must be JSON"}), 400
            missing = [field for field in required_fields if field not in data]
            if missing:
                return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400
            return f(*args, **kwargs)
        return decorated
    return decorator
