from app.extensions import db

class Project(db.Model):
    __tablename__ = "projects"   

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(500))
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=db.func.now())

    #added lines
    tasks = db.relationship("Task", backref="project", lazy=True)
    document = db.relationship("Document", backref="project", lazy=True)
