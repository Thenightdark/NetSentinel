from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, Security, status
from sqlalchemy.orm import Session

from backend.api.dependencies import require_dashboard_user, session_cookie
from backend.config import get_settings
from backend.database.session import get_db
from backend.models import User
from backend.schemas import LoginRequest, LoginResponse, LogoutResponse, UserRead
from backend.services.auth import (
    AUTH_COOKIE_NAME,
    authenticate_user,
    create_user_session,
    resolve_session,
    revoke_session,
)

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/login", response_model=LoginResponse)
def login(
    credentials: LoginRequest,
    response: Response,
    database: Session = Depends(get_db),
) -> LoginResponse:
    if get_settings().auth_secret is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Dashboard authentication is not configured",
        )
    user = authenticate_user(database, credentials.username, credentials.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    token, expires_at = create_user_session(database, user)
    max_age = max(0, int((expires_at - datetime.now(timezone.utc)).total_seconds()))
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token,
        max_age=max_age,
        httponly=True,
        secure=get_settings().auth_cookie_secure,
        samesite="lax",
        path="/",
    )
    return LoginResponse(user=UserRead.model_validate(user))


@router.post("/logout", response_model=LogoutResponse)
def logout(
    response: Response,
    token: str | None = Security(session_cookie),
    database: Session = Depends(get_db),
) -> LogoutResponse:
    resolved = resolve_session(database, token)
    if resolved is not None:
        revoke_session(database, resolved[1])
    response.delete_cookie(key=AUTH_COOKIE_NAME, path="/")
    return LogoutResponse()


@router.get("/me", response_model=UserRead)
def current_user(user: User = Depends(require_dashboard_user)) -> User:
    return user
