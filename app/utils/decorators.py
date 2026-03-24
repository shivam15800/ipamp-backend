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
                Config.JWT_SECRET_KEY,
                algorithms=["HS256"]
            )
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        g.user = payload
        return f(*args, **kwargs)

    return decorated


def role_required(required_roles):
    """
    required_roles can be a string ("admin") or a list (["admin", "super_admin"])
    """
    if isinstance(required_roles, str):
        required_roles = [required_roles]

    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_claims = g.get("user")
            if not user_claims:
                return jsonify({"error": "Unauthorized"}), 401

            roles = user_claims.get("roles", [])
            if not any(role in roles for role in required_roles):
                return jsonify({"error": "Forbidden: insufficient privileges"}), 403

            return f(*args, **kwargs)
        return decorated
    return wrapper