from flask import Blueprint, request, jsonify, abort, g, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.extensions import db
from app.models import Task, Project, User
from datetime import datetime
from app.utils.decorators import token_required, role_required
import html

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

def get_user_id(user):
    if hasattr(user, "id"):
        return user.id
    return user.get("user_id") or user.get("id")


@tasks_bp.route("/tasks", methods=["GET"])
def list_tasks():

    # ---------------- VULN MODE ----------------
    if current_app.config.get("ENABLE_VULNS"):
        
        @token_required
        def vuln():
            user = g.user
            user_id = get_user_id(user)

            tasks = Task.query.all()

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
            ])

        return vuln()

    # ---------------- SECURE MODE ----------------
    else:
        from flask_jwt_extended import verify_jwt_in_request

        verify_jwt_in_request()

        user = current_user()
        user_id = get_user_id(user)

        if has_role(user, "admin"):
            tasks = Task.query.all()
        else:
            tasks = Task.query.filter_by(assigned_to=user_id).all()

        return jsonify([
            {
                "id": t.id,
                "title": t.title,
                "description": html.escape(t.description or ""),
                "status": t.status,
                "project_id": t.project_id,
                "assigned_to": t.assigned_to
            }
            for t in tasks
        ])
    
@tasks_bp.route("/projects/<int:pid>/tasks", methods=["GET"])
def list_project_tasks(pid):

    project = Project.query.get_or_404(pid)

    # ---------------- VULN MODE ----------------
    if current_app.config.get("ENABLE_VULNS"):
        
        @token_required
        def vuln():
            user = g.user
            user_id = user.get("id")

            if has_role(user, "admin", "manager") or project.owner_id == user_id:
                tasks = Task.query.filter_by(project_id=pid).all()
            else:
                tasks = Task.query.filter_by(project_id=pid, assigned_to=user_id).all()

            return jsonify([
                {
                    "id": t.id,
                    "title": t.title,
                    "description": t.description,  # 🔴 XSS
                    "assigned_to": t.assigned_to
                }
                for t in tasks
            ])

        return vuln()

    # ---------------- SECURE MODE ----------------
    else:
        from flask_jwt_extended import verify_jwt_in_request

        verify_jwt_in_request()

        user = current_user()

        if (
            has_role(user, "admin") or
            project.owner_id == user.id or
            any(t.assigned_to == user.id for t in project.tasks)
        ):
            tasks = Task.query.filter_by(project_id=pid).all()
        else:
            abort(403)

        return jsonify([
            {
                "id": t.id,
                "title": t.title,
                "description": html.escape(t.description or ""),
                "assigned_to": t.assigned_to
            }
            for t in tasks
        ])
    
@tasks_bp.route("/projects/<int:pid>/tasks", methods=["POST"])
def assign_task(pid):

    # ---------------- VULN MODE ----------------
    if current_app.config.get("ENABLE_VULNS"):
        from app.utils.decorators import token_required

        @token_required
        def vuln():
            user = g.user

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

            return jsonify({"id": task.id}), 201

        return vuln()

    # ---------------- SECURE MODE ----------------
    else:
        from flask_jwt_extended import verify_jwt_in_request

        verify_jwt_in_request()

        user = current_user()

        if not has_role(user, "admin", "manager"):
            abort(403)

        data = request.get_json()

        task = Task(
            project_id=pid,
            assigned_to=data["assigned_to"],
            title=data["title"],
            description=data.get("description", ""),
            status=data.get("status", "pending"),
            created_by=user.id
        )

        db.session.add(task)
        db.session.commit()

        return jsonify({"id": task.id}), 201