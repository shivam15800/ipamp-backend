from flask import Blueprint, request, jsonify, abort
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.extensions import db
from app.models import Project, Task, User
from app.models.audit_log import AuditLog
from datetime import datetime
from app.utils.decorators import token_required
from sqlalchemy import text

projects_bp = Blueprint("projects", __name__)


# ---------------- HELPERS ----------------

def current_user():
    uid = get_jwt_identity()
    return User.query.get(uid)


def has_role(user, *roles):
    return any(r.name in roles for r in user.roles)


# =========================================================
# 🔐 SECURE ROUTES
# =========================================================

# Create Project
@projects_bp.route("/projects", methods=["POST"])
@jwt_required()
def create_project_secure():
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
        print(f"Audit log failed: {e}")

    return jsonify({"id": project.id, "name": project.name}), 201


# List Projects
@projects_bp.route("/projects", methods=["GET"])
@jwt_required()
def list_projects_secure():
    user = current_user()

    if has_role(user, "admin"):
        projects = Project.query.all()
    elif has_role(user, "manager"):
        projects = Project.query.filter_by(owner_id=user.id).all()
    else:
        projects = Project.query.join(Task).filter(Task.assigned_to == user.id).all()

    return jsonify([{"id": p.id, "name": p.name} for p in projects])


# Get Project
@projects_bp.route("/projects/<int:pid>", methods=["GET"])
@jwt_required()
def get_project_secure(pid):
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
def update_project_secure(pid):
    user = current_user()
    project = Project.query.get_or_404(pid)

    if not (has_role(user, "admin") or project.owner_id == user.id):
        abort(403)

    data = request.get_json()

    if "name" in data:
        project.name = data["name"]
    if "description" in data:
        project.description = data["description"]

    db.session.commit()

    try:
        log = AuditLog(
            action=f"project_updated:{project.id}",
            performed_by=user.id,
            timestamp=datetime.utcnow(),
            ip=request.remote_addr,
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Audit log failed: {e}")

    return jsonify({"id": project.id, "name": project.name})


# Delete Project
@projects_bp.route("/projects/<int:pid>", methods=["DELETE"])
@jwt_required()
def delete_project_secure(pid):
    user = current_user()
    project = Project.query.get_or_404(pid)

    if not (has_role(user, "admin") or project.owner_id == user.id):
        abort(403)

    db.session.delete(project)
    db.session.commit()

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
        print(f"Audit log failed: {e}")

    return jsonify({"msg": "Project deleted"}), 200


# =========================================================
# 💀 VULNERABLE ROUTES
# =========================================================

# Create Project (vulnerable → no role check)
@projects_bp.route("/projects_vuln", methods=["POST"])
@token_required
def create_project_vuln():
    user = g.user
    data = request.get_json()

    project = Project(
        name=data["name"],
        description=data.get("description"),
        owner_id=user.get("id")
    )

    db.session.add(project)
    db.session.commit()

    return jsonify({"id": project.id, "name": project.name}), 201


# List Projects (vulnerable → full disclosure)
@projects_bp.route("/projects_vuln", methods=["GET"])
@token_required
def list_projects_vuln():
    projects = Project.query.all()

    return jsonify([
        {"id": p.id, "name": p.name, "owner_id": p.owner_id}
        for p in projects
    ])


# Get Project (vulnerable → IDOR)
@projects_bp.route("/projects_vuln/<int:pid>", methods=["GET"])
@token_required
def get_project_vuln(pid):
    project = Project.query.get_or_404(pid)

    return jsonify({
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "owner_id": project.owner_id
    })


# Update Project (vulnerable → no ownership check)
@projects_bp.route("/projects_vuln/<int:pid>", methods=["PATCH"])
@token_required
def update_project_vuln(pid):
    project = Project.query.get_or_404(pid)
    data = request.get_json()

    if "name" in data:
        project.name = data["name"]
    if "description" in data:
        project.description = data["description"]

    db.session.commit()

    return jsonify({"id": project.id, "name": project.name})


# Delete Project (vulnerable → anyone can delete)
@projects_bp.route("/projects_vuln/<int:pid>", methods=["DELETE"])
@token_required
def delete_project_vuln(pid):
    project = Project.query.get_or_404(pid)

    db.session.delete(project)
    db.session.commit()

    return jsonify({"msg": "Project deleted"}), 200