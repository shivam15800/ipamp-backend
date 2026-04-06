from flask import Blueprint, jsonify, request, g, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from app.models.user import User
from app.models.role import Role
from app.extensions import db
from app.utils.jwt import generate_token
from app.utils.decorators import login_required
from app.models.audit_log import AuditLog 
from datetime import datetime
from sqlalchemy import text
from app.utils.decorators import token_required, role_required

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
        password_hash=generate_password_hash(password)
    )

    # 🚨 Always enforce default role, ignore client input
    default_role = Role.query.filter_by(name="employee").first()
    if default_role:
        user.roles.append(default_role)

    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "User already exists"}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    # Log action
    try:
        log = AuditLog(
            action="User_created",
            performed_by=user.id,            
            timestamp=datetime.utcnow(),
            ip=request.remote_addr,
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Audit log failed for register: {e}")

    return jsonify({"message": "User created successfully"}), 201

# ---------------- LOGIN ----------------
auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    if current_app.config["ENABLE_VULNS"]:
        # Vulnerable demo:
        user = db.session.query(User).filter(text(f"username = '{username}'")).first()
    else:
        # Secure demo: ORM + hashing
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({"error": "Invalid credentials"}), 401


    try:
        token = generate_token(user)
    except Exception:
        return jsonify({"error": "Token generation failed"}), 500

    # Audit logging (only in secure mode if you want)
    if not current_app.config["ENABLE_VULNS"]:
        try:
            log = AuditLog(
                action="login_success",
                performed_by=user.id,
                timestamp=datetime.utcnow(),
                ip=request.remote_addr,
            )
            db.session.add(log)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Audit log failed for login: {e}")

    return jsonify({
        "token": token,
        "user": {
            "user_id": user.id,
            "username": user.username,
            "roles": [role.name for role in user.roles]
        }
    }), 200

# ---------------- PROFILE ----------------
@auth_bp.route("/profile", methods=["GET"])
@token_required
def profile():
    user_claims = g.get("user")

    if not user_claims:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({
        "user_id": user_claims.get("user_id"),
        "username": user_claims.get("username"),
        "roles": user_claims.get("roles")
    }), 200

