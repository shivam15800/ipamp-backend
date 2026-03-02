from flask import Blueprint, jsonify
from app.utils.decorators import login_required, role_required
from app.models.user import User
from app import db
from flask import request

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@admin_bp.route("/dashboard", methods=["GET"])
@login_required
@role_required("admin")
def dashboard():
    return jsonify({"message": "Welcome Admin"}), 200


@admin_bp.route("/users", methods=["GET"])
@login_required
@role_required("admin")
def list_users():
    try:
        users = User.query.all()
        users_data = [
            {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
            }
            for user in users
        ]
        return jsonify({"users": users_data}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 5004
    
@admin_bp.route("/users/<int:user_id>", methods=["GET"])
@login_required
@role_required("admin")
def get_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        user_data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "status": user.status,
        }
        return jsonify({"user": user_data}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@admin_bp.route("/users/<int:user_id>/role", methods=["PATCH"])
@login_required
@role_required("admin")
def change_role(user_id):
    try:
        data = request.get_json()
        new_role = data.get("role")
        if not new_role:
            return jsonify({"error": "Role is required"}), 400

        user = User.query.get_or_404(user_id)
        user.role = new_role
        db.session.commit()
        return jsonify({"message": "Role updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
@login_required
@role_required("admin")
def delete_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@admin_bp.route("/users/<int:user_id>/status", methods=["PATCH"])
@login_required
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
        return jsonify({"message": f"User status changed to {new_status}"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500