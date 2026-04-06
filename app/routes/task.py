from flask import Blueprint, request, jsonify, abort, g, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.extensions import db
from app.models import Task, Project, User
from datetime import datetime
from app.utils.decorators import token_required, role_required

tasks_bp = Blueprint("tasks", __name__)


# HELPERS 

def current_user():
    uid = get_jwt_identity()
    return User.query.get(uid)


def has_role(user, *roles):
    # DB user (secure mode)
    if hasattr(user, "roles"):
        return any(r.name in roles for r in user.roles)

    # Token user (vuln mode)
    if isinstance(user, dict):
        token_roles = user.get("roles", [])
        return any(r in roles for r in token_roles)

    return False


# 🔐 SECURE ROUTES

# List my tasks
@tasks_bp.route("/tasks", methods=["GET"])
@jwt_required()
def list_my_tasks_secure():
    user = current_user()

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Admin sees everything
    if has_role(user, "admin"):
        tasks = Task.query.all()
    else:
        tasks = Task.query.filter_by(assigned_to=user.id).all()

    return jsonify([
        {
            "id": t.id,
            "title": t.title,
            "description": t.description,
            "status": t.status,
            "project_id": t.project_id,
            "assigned_to": t.assigned_to
        }
        for t in tasks
    ]), 200


# Update task
@tasks_bp.route("/tasks/<int:tid>", methods=["PATCH"])
@jwt_required()
def update_task(tid):
    user = current_user()
    task = Task.query.get_or_404(tid)
    project = Project.query.get(task.project_id)

    if not project:
        abort(404)

    if has_role(user, "admin") or project.owner_id == user.id or task.assigned_to == user.id:
        data = request.get_json() or {}

        if "status" in data:
            allowed = {"pending", "in_progress", "done"}
            if data["status"] not in allowed:
                abort(400, description="Invalid status")
            task.status = data["status"]

        if "title" in data and has_role(user, "admin", "manager"):
            task.title = data["title"]

        if "description" in data:
            task.description = data["description"]

        db.session.commit()

        return jsonify({
            "id": task.id,
            "title": task.title,
            "description": task.description,
            "status": task.status
        })

    abort(403)


# Delete task
@tasks_bp.route("/tasks/<int:tid>", methods=["DELETE"])
@jwt_required()
def delete_task(tid):
    user = current_user()
    task = Task.query.get_or_404(tid)
    project = Project.query.get(task.project_id)

    if has_role(user, "admin") or project.owner_id == user.id:
        db.session.delete(task)
        db.session.commit()
        return jsonify({"msg": "Task deleted"}), 200

    abort(403)


# 💀 VULNERABLE ROUTES

# List my tasks (vulnerable → JWT tampering)
@tasks_bp.route("/tasks_vuln", methods=["GET"])
@token_required
def list_my_tasks_vuln():
    user = g.user

    user_id = user.get("id")   # 🔥 FIXED (consistent key)

    tasks = Task.query.filter_by(assigned_to=user_id).all()

    return jsonify([
        {
            "id": t.id,
            "title": t.title,
            "description": t.description,
            "status": t.status,
            "project_id": t.project_id,
            "assigned_to": t.assigned_to
        }
        for t in tasks
    ]), 200


# List project tasks (vulnerable → IDOR + role escalation)
@tasks_bp.route("/projects/<int:pid>/tasks", methods=["GET"])
@token_required
def list_project_tasks(pid):
    user = g.user
    project = Project.query.get_or_404(pid)

    user_id = user.get("id")

    # Vulnerable logic (trusts token completely)
    if has_role(user, "admin", "manager") or project.owner_id == user_id:
        tasks = Task.query.filter_by(project_id=pid).all()
    else:
        tasks = Task.query.filter_by(project_id=pid, assigned_to=user_id).all()

    return jsonify([
        {
            "id": t.id,
            "title": t.title,
            "description": t.description,
            "status": t.status,
            "assigned_to": t.assigned_to
        }
        for t in tasks
    ]), 200


# Assign task (vulnerable → privilege escalation)
@tasks_bp.route("/projects/<int:pid>/tasks", methods=["POST"])
@token_required
def assign_task(pid):
    user = g.user

    # Vulnerable: trusts token role
    if not has_role(user, "admin", "manager"):
        abort(403)

    data = request.get_json()

    task = Task(
        project_id=pid,
        assigned_to=data["assigned_to"],
        title=data["title"],
        description=data.get("description", ""),
        status=data.get("status", "pending"),
        created_by=user.get("id")
    )

    db.session.add(task)
    db.session.commit()

    return jsonify({
        "id": task.id,
        "title": task.title
    }), 201