from flask import Blueprint, request, jsonify, abort
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.extensions import db
from app.models import Document, Project, Task, User

upload_bp = Blueprint("upload", __name__)

def current_user():
    uid = get_jwt_identity()
    return User.query.get(uid)

def has_role(user, *roles):
    return any(r.name in roles for r in user.roles)

# Upload Document
@upload_bp.route("/projects/<int:pid>/documents", methods=["POST"])
@jwt_required()
def upload_document(pid):
    user = current_user()
    project = Project.query.get_or_404(pid)

    if has_role(user, "employee") and not any(t.assigned_to == user.id for t in project.tasks):
        abort(403)

    data = request.get_json()
    doc = Document(
        project_id=pid,
        filename=data["filename"],
        filepath=data["filepath"],
        uploaded_by=user.id,
        mime_type=data.get("mime_type")
    )
    db.session.add(doc)
    db.session.commit()
    return jsonify({"id": doc.id, "filename": doc.filename}), 201

# List Documents
@upload_bp.route("/projects/<int:pid>/documents", methods=["GET"])
@jwt_required()
def list_documents(pid):
    user = current_user()
    project = Project.query.get_or_404(pid)

    if has_role(user, "admin") or project.owner_id == user.id or \
       any(t.assigned_to == user.id for t in project.tasks):
        docs = Document.query.filter_by(project_id=pid).all()
        return jsonify([{
            "id": d.id,
            "filename": d.filename,
            "uploaded_at": d.uploaded_at,
            "mime_type": d.mime_type
        } for d in docs])
    abort(403)