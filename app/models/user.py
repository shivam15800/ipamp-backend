from app.extensions import db
from app.models.role import user_roles

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    # role = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    status = db.Column(db.String(20), default="active", nullable=False)

    #Many-to-many relationship with role
    roles = db.relationship("Role", secondary=user_roles, backref="users")
