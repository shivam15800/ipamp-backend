from flask import Blueprint, request, jsonify, abort
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.extensions import db
from app.models import Task, Project, User
from app.models.audit_log import AuditLog
from datetime import datetime

tasks_bp = Blueprint("tasks", __name__)

def current_user():
    uid = get_jwt_identity()
    return User.query.get(uid)

def has_role(user, *roles):
    return any(r.name in roles for r in user.roles)

# List all tasks assigned to current user (global)
@tasks_bp.route("/tasks", methods=["GET"])
@jwt_required()
def list_my_tasks():
    user = current_user()
    tasks = Task.query.filter_by(assigned_to=user.id).all()
    return jsonify([
        {"id": t.id, "title": t.title, "status": t.status, "project_id": t.project_id}
        for t in tasks
    ])

# List tasks in a project
@tasks_bp.route("/projects/<int:pid>/tasks", methods=["GET"])
@jwt_required()
def list_project_tasks(pid):
    user = current_user()
    project = Project.query.get_or_404(pid)

    if has_role(user, "admin", "manager") or project.owner_id == user.id:
        tasks = Task.query.filter_by(project_id=pid).all()
    else:
        tasks = Task.query.filter_by(project_id=pid, assigned_to=user.id).all()

    return jsonify([
        {"id": t.id, "title": t.title, "status": t.status, "assigned_to": t.assigned_to}
        for t in tasks
    ])

# Assign Task (manager/admin only)
@tasks_bp.route("/projects/<int:pid>/tasks", methods=["POST"])
@jwt_required()
def assign_task(pid):
    user = current_user()
    if not has_role(user, "manager", "admin"):
        abort(403)

    data = request.get_json()
    task = Task(
        project_id=pid,
        assigned_to=data["assigned_to"],
        title=data["title"],
        status=data.get("status", "pending"),
        created_by=user.id
    )
    db.session.add(task)
    db.session.commit()

    try:
        log = AuditLog(
            action="assigned_task",
            performed_by=user.id, 
            target_user=task.assigned_to,  
            target_project=pid,         
            timestamp=datetime.utcnow(),
            ip=request.remote_addr,
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Audit log failed for assign task: {e}")
    
    return jsonify({"id": task.id, "title": task.title}), 201

# Update Task (status for assignee, title for manager/admin)
@tasks_bp.route("/tasks/<int:tid>", methods=["PATCH"])
@jwt_required()
def update_task(tid):
    user = current_user()
    task = Task.query.get_or_404(tid)
    project = Project.query.get(task.project_id)

    if has_role(user, "admin") or project.owner_id == user.id or task.assigned_to == user.id:
        data = request.get_json()
        if "status" in data:
            allowed_statuses = {"pending", "in_progress", "done"}
            if data["status"] not in allowed_statuses:
                abort(400, description="Invalid status value")
            task.status = data["status"]
        if "title" in data and has_role(user, "manager", "admin"):
            task.title = data["title"]
        db.session.commit()
        return jsonify({"id": task.id, "title": task.title, "status": task.status})
    abort(403)

# Delete Task (admin or project owner only)
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