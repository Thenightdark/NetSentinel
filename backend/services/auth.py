from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from backend.config import get_settings
from backend.models import User, UserSession

AUTH_COOKIE_NAME = "netsentinel_session"
JWT_ALGORITHM = "HS256"
JWT_AUDIENCE = "netsentinel-dashboard"
JWT_ISSUER = "netsentinel-api"

logger = logging.getLogger(__name__)
password_hasher = PasswordHash.recommended()
_DUMMY_PASSWORD_HASH = password_hasher.hash("not-a-real-netsentinel-password")


def normalize_username(username: str) -> str:
    return username.strip().casefold()


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def create_user(
    database: Session,
    *,
    username: str,
    password: str,
    role: str = "viewer",
) -> User:
    normalized = normalize_username(username)
    if not normalized:
        raise ValueError("Username cannot be empty")
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters")
    if database.scalar(select(User).where(User.username == normalized)) is not None:
        raise ValueError("Username already exists")
    user = User(
        username=normalized,
        password_hash=hash_password(password),
        role=role,
        is_active=True,
    )
    database.add(user)
    database.commit()
    database.refresh(user)
    return user


def bootstrap_initial_admin(database: Session) -> None:
    settings = get_settings()
    username = settings.initial_admin_username
    configured_password = settings.initial_admin_password
    if username is None and configured_password is None:
        return
    if username is None or configured_password is None:
        logger.warning(
            "Initial admin was not created because both admin environment variables are required"
        )
        return
    normalized = normalize_username(username)
    if database.scalar(select(User.id).where(User.username == normalized)) is not None:
        return
    create_user(
        database,
        username=normalized,
        password=configured_password.get_secret_value(),
        role="admin",
    )
    logger.info("Created initial NetSentinel administrator %s", normalized)


def authenticate_user(database: Session, username: str, password: str) -> User | None:
    normalized = normalize_username(username)
    user = database.scalar(select(User).where(User.username == normalized))
    stored_hash = user.password_hash if user is not None else _DUMMY_PASSWORD_HASH
    password_valid = password_hasher.verify(password, stored_hash)
    if user is None or not password_valid or not user.is_active:
        return None
    return user


def _auth_secret() -> str:
    secret = get_settings().auth_secret
    if secret is None:
        raise RuntimeError("Dashboard authentication is not configured")
    return secret.get_secret_value()


def create_user_session(database: Session, user: User) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=get_settings().auth_session_minutes)
    session_id = str(uuid4())
    database.execute(delete(UserSession).where(UserSession.expires_at <= now))
    database.add(
        UserSession(
            id=session_id,
            user_id=user.id,
            created_at=now,
            expires_at=expires_at,
        )
    )
    user.last_login_at = now
    database.commit()
    token = jwt.encode(
        {
            "sub": str(user.id),
            "sid": session_id,
            "iat": now,
            "exp": expires_at,
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
        },
        _auth_secret(),
        algorithm=JWT_ALGORITHM,
    )
    return token, expires_at


def resolve_session(database: Session, token: str | None) -> tuple[User, UserSession] | None:
    if not token:
        return None
    try:
        payload = jwt.decode(
            token,
            _auth_secret(),
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"require": ["sub", "sid", "iat", "exp"]},
        )
        user_id = int(payload["sub"])
        session_id = str(payload["sid"])
    except (InvalidTokenError, KeyError, TypeError, ValueError, RuntimeError):
        return None

    auth_session = database.get(UserSession, session_id)
    user = database.get(User, user_id)
    if auth_session is None or user is None:
        return None
    expires_at = auth_session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if (
        auth_session.user_id != user.id
        or auth_session.revoked_at is not None
        or expires_at <= datetime.now(timezone.utc)
        or not user.is_active
    ):
        return None
    return user, auth_session


def revoke_session(database: Session, auth_session: UserSession) -> None:
    auth_session.revoked_at = datetime.now(timezone.utc)
    database.commit()
