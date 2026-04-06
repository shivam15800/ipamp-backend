from flask import Blueprint, jsonify, request, g, current_app
from app.utils.decorators import login_required, role_required
from app.models.user import User
from app.models.role import Role
from app.models.project import Project
from app.models.audit_log import AuditLog
from app import db
from app.utils.decorators import token_required, role_required
from sqlalchemy import text

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")

# ---------------- DASHBOARD ----------------
@admin_bp.route("/dashboard", methods=["GET"])
# @login_required
@token_required
@role_required("admin")
def dashboard():
    return jsonify({"message": "Welcome Admin"}), 200

# ---------------- LIST USERS ----------------
@admin_bp.route("/users", methods=["GET"])
# @login_required
@token_required
@role_required("admin")
def list_users():
    try:
        users = User.query.all()
        users_data = [
            {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "roles": [role.name for role in user.roles],
                "status": user.status,
            }
            for user in users
        ]
        return jsonify({"users": users_data}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- GET USER ----------------
@admin_bp.route("/users/<int:user_id>", methods=["GET"])
#@login_required
@token_required
@role_required("admin")
def get_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        user_data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "roles": [role.name for role in user.roles],
            "status": user.status,
        }
        return jsonify({"user": user_data}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- CHANGE ROLES ----------------
@admin_bp.route("/users/<int:user_id>/roles", methods=["PATCH"])
# @login_required
@token_required
@role_required("admin")
def change_roles(user_id):
    try:
        data = request.get_json()
        new_roles = data.get("roles")

        if not new_roles or not isinstance(new_roles, list):
            return jsonify({"error": "Roles must be provided as a list"}), 400

        user = User.query.get_or_404(user_id)

        # Prevent admin from demoting themselves
        if user.id == g.user["user_id"]:
            return jsonify({"error": "Cannot modify your own role"}), 403

        # Clear existing roles
        user.roles.clear()

        # Assign new roles
        for role_name in new_roles:
            role = Role.query.filter_by(name=role_name).first()
            if role:
                user.roles.append(role)

        db.session.commit()

        if not current_app.config.get("ENABLE_VULNS", False):
            # Log action
            try:
                log = AuditLog(
                    action=f"Changed roles of user {user.id} to {new_roles}",
                    performed_by=g.user["user_id"],
                    target_user=user.id,
                    ip=log.ip
                )
                db.session.add(log)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                print(f"Audit log failed for change_roles: {e}")

        return jsonify({"message": "Roles updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- DELETE USER ----------------
@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
# @login_required
@token_required
@role_required("admin")
def delete_user(user_id):
    try:
        user = User.query.get_or_404(user_id)

        # Prevent deletion of super_admin
        if any(role.name == "super_admin" for role in user.roles):
            return jsonify({"error": "Cannot delete super admin"}), 403

        db.session.delete(user)
        db.session.commit()

        # Log action
        log = AuditLog(
            action=f"Deleted user {user.id}",
            performed_by=g.user["user_id"],
            target_user=user.id
        )
        db.session.add(log)
        db.session.commit()

        return jsonify({"message": "User deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- CHANGE STATUS ----------------
@admin_bp.route("/users/<int:user_id>/status", methods=["PATCH"])
# @login_required
@token_required
@role_required("admin")
def change_status(user_id):
    try:
        data = request.get_json()
        new_status = data.get("status")
        if new_status not in ["active", "inactive"]:
            return jsonify({"error": "Invalid status"}), 400

        user = User.query.get_or_404(user_id)
        user.status = new_status
        db.session.commit()

        # Log action
        log = AuditLog(
            action=f"Changed status of user {user.id} to {new_status}",
            performed_by=g.user["user_id"],
            target_user=user.id
        )
        db.session.add(log)
        db.session.commit()

        return jsonify({"message": f"User status changed to {new_status}"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- VIEW AUDIT LOGS ----------------
@admin_bp.route("/audit-logs", methods=["GET"])
# @login_required
@token_required
@role_required("super_admin")  # only super_admin can view logs
def get_audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    logs_data = [
        {
            "id": log.id,
            "action": log.action,
            "performed_by": log.performed_by,
            "target_user": log.target_user,
            "trget_project": log.target_project,
            "timestamp": log.timestamp.isoformat(),
            "ip": log.ip
        }
        for log in logs
    ]
    return jsonify({"logs": logs_data}), 200

# ---------------- ADMIN SEARCH USERS ----------------
from flask import request, jsonify, current_app
from sqlalchemy import text
from app.db import db

@admin_bp.route("/search-users", methods=["GET"])
@token_required
@role_required("admin")
def search_users_admin():
    q = request.args.get("q", "")

    try:
        if current_app.config.get("ENABLE_VULNS", False):
            sql = text(f"SELECT id, username, email, status FROM users WHERE username LIKE '%{q}%'")
            result = db.session.execute(sql).fetchall()
        else:
            sql = text("SELECT id, username, email, status FROM users WHERE username LIKE :q")
            result = db.session.execute(sql, {"q": f"%{q}%"}).fetchall()

        users_data = [dict(row._mapping) for row in result]

        return jsonify({"users": users_data}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

# Search Projects (Vulnerable to SQL Injection)
@admin_bp.route("/search-projects", methods=["GET"])
@token_required
@role_required("admin")
def search_projects():
    q = request.args.get("q", "")

    if current_app.config.get("ENABLE_VULNS", False):
        query = text(f"SELECT id, name, description, owner_id FROM projects WHERE name LIKE '%{q}%'")
        result = db.session.execute(query).fetchall()
        return jsonify([dict(row._mapping) for row in result])
    else:
        projects = Project.query.filter(Project.name.contains(q)).all()
        return jsonify([{"id": p.id, "name": p.name, "description": p.description, "owner_id": p.owner_id} for p in projects])

# ---------------- UPDATE USER (MASS ASSIGNMENT VULNERABILITY) ----------------
@admin_bp.route("/users/update-uers/<int:user_id>", methods=["PATCH"])
@token_required
def update_user(user_id):
    user_claims = g.get("user")
    if not user_claims:
        return jsonify({"error": "Unauthorized"}), 401

    # In a secure app, we'd check if user_claims["user_id"] == user_id or if user is admin
    vulnerable = current_app.config.get("ENABLE_VULNS", False)
    
    if not vulnerable and user_claims["user_id"] != user_id:
        # Secure version checks access
        return jsonify({"error": "Forbidden"}), 403

    user = User.query.get_or_404(user_id)
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    if vulnerable:
        # Vulnerable context: Mass assignment
        for key, value in data.items():
            setattr(user, key, value)
    else:
        # Secure context: only allow specific fields like email
        if "email" in data:
            user.email = data["email"]
        if "username" in data:
            user.username = data["username"]
        # Explicitly ignoring status, roles, password directly without logic

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

    return jsonify({"message": "User updated", "user_id": user.id}), 200
