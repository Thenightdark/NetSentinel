import secrets

from fastapi import Depends, Header, HTTPException, Security, status
from fastapi.security import APIKeyCookie, APIKeyHeader
from sqlalchemy.orm import Session

from backend.config import get_settings
from backend.database.session import get_db
from backend.models import CollectorAgent, User
from backend.services.agents import authenticate_agent
from backend.services.auth import AUTH_COOKIE_NAME, resolve_session

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
session_cookie = APIKeyCookie(name=AUTH_COOKIE_NAME, auto_error=False)


def require_agent_enrollment_key(
    supplied_key: str | None = Security(api_key_header),
) -> None:
    settings = get_settings()
    configured_secret = settings.agent_enrollment_key or settings.ingest_api_key
    if configured_secret is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Agent enrollment is not configured",
        )
    if supplied_key is None or not secrets.compare_digest(
        supplied_key, configured_secret.get_secret_value()
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing enrollment key",
        )


def require_collector_agent(
    supplied_key: str | None = Security(api_key_header),
    agent_id: str | None = Header(default=None, alias="X-Agent-ID"),
    database: Session = Depends(get_db),
) -> CollectorAgent:
    agent = authenticate_agent(database, agent_id, supplied_key)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing collector credentials",
        )
    return agent


def require_dashboard_user(
    token: str | None = Security(session_cookie),
    database: Session = Depends(get_db),
) -> User:
    resolved = resolve_session(database, token)
    if resolved is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return resolved[0]
