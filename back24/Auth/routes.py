from flask import Blueprint, request, jsonify
import jwt
import datetime

auth_bp = Blueprint("auth", __name__)

SECRET_KEY = "mysecret123"

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data:
        return jsonify({"message": "No data sent"}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    # إنشاء JWT token
    token = jwt.encode(
        {
            "username": username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        },
        SECRET_KEY,
        algorithm="HS256"
    )

    return jsonify({
        "access_token": token,
        "role": "admin"
    }), 200
