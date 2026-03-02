from flask import Blueprint, jsonify, request, g
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError

from app.models.user import User
from app.extensions import db
from app.utils.jwt import generate_token
from app.utils.decorators import login_required, role_required



auth_bp = Blueprint("auth", __name__, url_prefix="/api")


# ---------------- REGISTER ----------------
@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not username or not email or not password:
        return jsonify({"error": "Missing fields"}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        role="employee"
    )

    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "User already exists"}), 400
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Server error"}), 500

    return jsonify({"message": "User created successfully"}), 201


# ---------------- LOGIN ----------------
@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    if not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401

    try:
        token = generate_token(user)
    except Exception:
        return jsonify({"error": "Token generation failed"}), 500

    return jsonify({
        "token": token,
        "user": {
            "user_id": user.id,
            "username": user.username,
            "role": user.role
        }
    }), 200


# ---------------- PROFILE ----------------
@auth_bp.route("/profile", methods=["GET"])
@login_required
def profile():
    user_claims = g.get("user")

    if not user_claims:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({
        "user_id": user_claims.get("user_id"),
        "username": user_claims.get("username"),
        "role": user_claims.get("role")
    }), 200

