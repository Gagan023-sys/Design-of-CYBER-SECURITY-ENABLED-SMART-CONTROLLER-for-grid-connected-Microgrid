import bcrypt
from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt
)
from models import db, User
from logger import audit_log

bp = Blueprint("auth", __name__, url_prefix="/auth")

# Role-based access decorator
def role_required(*roles):
    def wrapper(fn):
        from functools import wraps
        @wraps(fn)
        @jwt_required()
        def inner(*args, **kwargs):
            claims = get_jwt()
            if claims.get("role") not in roles:
                return jsonify({"msg": "insufficient role"}), 403
            return fn(*args, **kwargs)
        return inner
    return wrapper

# Admin creates new users
@bp.post("/register")
@role_required("admin")
def register():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "operator")

    if not username or not password:
        return jsonify({"msg": "username & password required"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "user exists"}), 409

    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    user = User(username=username, password_hash=pw_hash, role=role)
    db.session.add(user)
    db.session.commit()

    # Audit log for new user creation
    audit_log(get_jwt().get("sub"), "register_user", f"user={username}, role={role}")

    return jsonify({"msg": "user created", "username": username, "role": role}), 201

# User login
@bp.post("/login")
def login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password") or ""

    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.checkpw(password.encode("utf-8"), user.password_hash):
        IDS.record_failed_login()  # log failed attempts for IDS
        return jsonify({"msg": "bad credentials"}), 401

    claims = {"role": user.role}
    token = create_access_token(identity=username, additional_claims=claims)

    # Audit log for successful login
    audit_log(username, "login_success")

    return jsonify({"access_token": token, "role": user.role})
