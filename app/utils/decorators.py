from functools import wraps
from flask import request, jsonify, g
import jwt
from app.config import Config


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(
                token,
                Config.JWT_SECRET,
                algorithms=["HS256"]
            )
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        g.user = payload

        return f(*args, **kwargs)

    return decorated
def role_required(required_role):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get("Authorization")

            if not auth_header or not auth_header.startswith("Bearer "):
                return jsonify({"error": "Missing token"}), 401

            token = auth_header.split(" ")[1]

            try:
                payload = jwt.decode(
                    token,
                    Config.JWT_SECRET,
                    algorithms=["HS256"]
                )
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token expired"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Invalid token"}), 401

            # 🔥 Role enforcement
            user_role = payload.get("role")

            if user_role != required_role:
                return jsonify({"error": "Forbidden: insufficient privileges"}), 403

            g.user = payload

            return f(*args, **kwargs)

        return decorated
    return wrapper