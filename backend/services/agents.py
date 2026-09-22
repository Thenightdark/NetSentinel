from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.config import get_settings
from backend.models import CollectorAgent
from backend.schemas import AgentRead, AgentRegistrationRequest


def hash_agent_key(api_key: str) -> str:
    """Hash a high-entropy generated API key before database storage."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def register_agent(
    database: Session, registration: AgentRegistrationRequest
) -> tuple[CollectorAgent, str]:
    if database.get(CollectorAgent, registration.agent_id) is not None:
        raise ValueError("Agent identity is already registered")
    now = datetime.now(timezone.utc)
    api_key = secrets.token_urlsafe(32)
    agent = CollectorAgent(
        agent_id=registration.agent_id,
        hostname=registration.hostname.strip(),
        operating_system=registration.operating_system.strip(),
        ip_address=str(registration.ip_address),
        version=registration.version.strip(),
        first_seen=now,
        last_seen=now,
        status="ONLINE",
        api_key_hash=hash_agent_key(api_key),
    )
    database.add(agent)
    database.commit()
    database.refresh(agent)
    return agent, api_key


def authenticate_agent(
    database: Session, agent_id: str | None, api_key: str | None
) -> CollectorAgent | None:
    if not agent_id or not api_key:
        return None
    agent = database.get(CollectorAgent, agent_id)
    if agent is None or not secrets.compare_digest(
        agent.api_key_hash, hash_agent_key(api_key)
    ):
        return None
    agent.last_seen = datetime.now(timezone.utc)
    agent.status = "ONLINE"
    database.commit()
    return agent


def serialize_agent(agent: CollectorAgent) -> AgentRead:
    timeout = get_settings().agent_online_timeout_seconds
    last_seen = agent.last_seen
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    status = (
        "ONLINE"
        if datetime.now(timezone.utc) - last_seen <= timedelta(seconds=timeout)
        else "OFFLINE"
    )
    return AgentRead(
        agent_id=agent.agent_id,
        hostname=agent.hostname,
        operating_system=agent.operating_system,
        ip_address=agent.ip_address,
        version=agent.version,
        first_seen=agent.first_seen,
        last_seen=agent.last_seen,
        status=status,
    )


def list_agents(database: Session) -> tuple[list[AgentRead], int]:
    agents = list(
        database.scalars(
            select(CollectorAgent).order_by(CollectorAgent.last_seen.desc())
        )
    )
    return [serialize_agent(agent) for agent in agents], int(
        database.scalar(select(func.count()).select_from(CollectorAgent)) or 0
    )
