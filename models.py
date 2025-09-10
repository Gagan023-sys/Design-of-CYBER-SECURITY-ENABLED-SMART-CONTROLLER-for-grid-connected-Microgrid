from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary, nullable=False)
    role = db.Column(db.String(20), nullable=False, default="operator")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(80), nullable=True)  # username or 'system'
    action = db.Column(db.String(120), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class PatchLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patch_version = db.Column(db.String(50), nullable=False)
    applied_by = db.Column(db.String(80), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
