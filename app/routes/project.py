from flask import Blueprint, request, jsonify, abort
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.extensions import db
from app.models import Project, Task, User
from app.models.audit_log import AuditLog
from datetime import datetime


projects_bp = Blueprint("projects", __name__)

def current_user():
    uid = get_jwt_identity()
    return User.query.get(uid)

def has_role(user, *roles):
    return any(r.name in roles for r in user.roles)

# Create Project
@projects_bp.route("/projects", methods=["POST"])
@jwt_required()
def create_project():
    user = current_user()
    if not has_role(user, "manager"):
        abort(403)
    data = request.get_json()
    project = Project(
        name=data["name"],
        description=data.get("description"),
        owner_id=user.id
    )
    db.session.add(project)
    db.session.commit()

    # Log action
    try:
        log = AuditLog(
            action="project_created",
            performed_by=user.id,            
            timestamp=datetime.utcnow(),
            ip=request.remote_addr,
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Audit log failed for creating project: {e}")

    return jsonify({"id": project.id, "name": project.name}), 201

# List Projects
@projects_bp.route("/projects", methods=["GET"])
@jwt_required()
def list_projects():
    user = current_user()
    if has_role(user, "admin"):
        projects = Project.query.all()
    elif has_role(user, "manager"):
        projects = Project.query.filter_by(owner_id=user.id).all()
    else:  # employee
        projects = Project.query.join(Task).filter(Task.assigned_to == user.id).all()
    return jsonify([{"id": p.id, "name": p.name} for p in projects])

# Get Project
@projects_bp.route("/projects/<int:pid>", methods=["GET"])
@jwt_required()
def get_project(pid):
    user = current_user()
    project = Project.query.get_or_404(pid)
    if has_role(user, "admin") or project.owner_id == user.id or \
       any(t.assigned_to == user.id for t in project.tasks):
        return jsonify({
            "id": project.id,
            "name": project.name,
            "description": project.description,
            "created_at": project.created_at
        })
    abort(403)

# Update Project
@projects_bp.route("/projects/<int:pid>", methods=["PATCH"])
@jwt_required()
def update_project(pid):
    user = current_user()
    project = Project.query.get_or_404(pid)
    if not (has_role(user, "admin") or project.owner_id == user.id):
        abort(403)
    data = request.get_json()
    if "name" in data: project.name = data["name"]
    if "description" in data: project.description = data["description"]
    db.session.commit()

     # Log action
    try:
        log = AuditLog(
            action="project_updated, project_id: {projects.id}",
            performed_by=user.id,            
            timestamp=datetime.utcnow(),
            ip=request.remote_addr,
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Audit log failed for updating project: {e}")
    return jsonify({"id": project.id, "name": project.name})

# Delete Project
@projects_bp.route("/projects/<int:pid>", methods=["DELETE"])
@jwt_required()
def delete_project(pid):
    user = current_user()
    project = Project.query.get_or_404(pid)
    if not (has_role(user, "admin") or project.owner_id == user.id):
        abort(403)
    db.session.delete(project)
    db.session.commit()

     # Log action
    try:
        log = AuditLog(
            action="project_deleted",
            performed_by=user.id, 
            target_project=project.id,           
            timestamp=datetime.utcnow(),
            ip=request.remote_addr,
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Audit log failed for deleting project: {e}")
    return jsonify({"msg": "Project deleted"})