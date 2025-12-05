"""
Authentication and authorization helpers.
"""

from __future__ import annotations

import datetime as dt
import functools
import os
from typing import Any, Callable, Iterable

import jwt
from flask import Request, current_app, g, jsonify, request
from passlib.context import CryptContext

from .models import SessionLocal, User
from .utils import sanitize_text


pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("CYBERGRID_ACCESS_TOKEN_MIN", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("CYBERGRID_REFRESH_TOKEN_DAYS", "5"))
JWT_SECRET = os.getenv("CYBERGRID_JWT_SECRET", "change-this-secret")
JWT_ALGORITHM = "HS256"
VALID_ROLES = {"admin", "operator", "analyst", "viewer"}


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_user(username: str, password: str, role: str = "operator") -> User:
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role '{role}'. Valid roles: {', '.join(sorted(VALID_ROLES))}")
    with SessionLocal() as session:
        user = session.query(User).filter_by(username=username).one_or_none()
        if user:
            raise ValueError("User already exists")
        user = User(username=sanitize_text(username), password_hash=hash_password(password), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        return user


def authenticate_user(username: str, password: str) -> User | None:
    with SessionLocal() as session:
        user = session.query(User).filter_by(username=sanitize_text(username)).one_or_none()
        if not user:
            return None
        if not verify_password(password, user.password_hash):
            return None
        # Detach to avoid session closing issues
        session.expunge(user)
    return user


def list_users() -> list[dict[str, Any]]:
    with SessionLocal() as session:
        users = session.query(User).order_by(User.username).all()
        return [{"username": u.username, "role": u.role, "is_active": u.is_active} for u in users]


def set_user_status(username: str, is_active: bool) -> None:
    with SessionLocal() as session:
        user = session.query(User).filter_by(username=username).one_or_none()
        if not user:
            raise ValueError("User not found")
        user.is_active = is_active
        session.commit()


def update_user_role(username: str, role: str) -> None:
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role '{role}'. Valid roles: {', '.join(sorted(VALID_ROLES))}")
    with SessionLocal() as session:
        user = session.query(User).filter_by(username=username).one_or_none()
        if not user:
            raise ValueError("User not found")
        user.role = role
        session.commit()


def _create_token(subject: str, expires_delta: dt.timedelta, token_type: str) -> str:
    payload = {
        "sub": subject,
        "iat": dt.datetime.utcnow(),
        "exp": dt.datetime.utcnow() + expires_delta,
        "type": token_type,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_access_token(username: str) -> str:
    return _create_token(username, dt.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES), "access")


def create_refresh_token(username: str) -> str:
    return _create_token(username, dt.timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS), "refresh")


def decode_token(token: str) -> dict[str, Any] | None:
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        return None
    return decoded


def _extract_token(http_request: Request) -> str | None:
    auth_header = http_request.headers.get("Authorization")
    if not auth_header:
        return None
    if not auth_header.lower().startswith("bearer "):
        return None
    return auth_header.split(" ", maxsplit=1)[1].strip()


def token_required(view: Callable) -> Callable:
    """
    Decorator enforcing JWT authentication on Flask routes.
    """

    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        token = _extract_token(request)
        if not token:
            return jsonify({"detail": "Missing authorization header"}), 401

        payload = decode_token(token)
        if not payload or payload.get("type") != "access":
            return jsonify({"detail": "Invalid token"}), 401

        username = payload.get("sub")
        if not username:
            return jsonify({"detail": "Invalid token subject"}), 401

        with SessionLocal() as session:
            user = session.query(User).filter_by(username=username).one_or_none()
            if not user or not user.is_active:
                return jsonify({"detail": "Inactive user"}), 403
            session.expunge(user)
            g.current_user = user

        return view(*args, **kwargs)

    return wrapper


def role_required(roles: Iterable[str]) -> Callable:
    """
    Decorator stacking on top of token_required to enforce RBAC.
    """

    def decorator(view: Callable) -> Callable:
        @functools.wraps(view)
        @token_required
        def wrapped(*args, **kwargs):
            user: User = g.current_user  # type: ignore[assignment]
            if user.role not in roles:
                current_app.logger.warning("RBAC violation by user=%s role=%s", user.username, user.role)
                return jsonify({"detail": "Insufficient role"}), 403
            return view(*args, **kwargs)

        return wrapped

    return decorator


