from app.extensions import db
from datetime import datetime

class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(255), nullable=False)
    performed_by = db.Column(db.Integer, nullable=False)  # admin user_id
    target_user = db.Column(db.Integer, nullable=True)    # affected user_id
    target_project=db.Column(db.Integer, nullable=True)
    
    ip = db.Column(db.String(45), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)