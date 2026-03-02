from app.extensions import db

class ProjectMembers(db.Model):
    __tablename__ = "projectmembers"

    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)