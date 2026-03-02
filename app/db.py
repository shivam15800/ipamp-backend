from app.extensions import db
from app.models import User, Project, ProjectMembers, Task, Document

def init_db(app):
    with app.app_context():
        db.create_all()
        # print("Tables created successfully!")