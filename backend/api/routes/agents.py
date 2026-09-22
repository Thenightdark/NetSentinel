from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.api.dependencies import (
    require_agent_enrollment_key,
    require_collector_agent,
    require_dashboard_user,
)
from backend.database.session import get_db
from backend.models import CollectorAgent
from backend.schemas import (
    AgentHeartbeatResponse,
    AgentPage,
    AgentRead,
    AgentRegistrationRequest,
    AgentRegistrationResponse,
)
from backend.services.agents import list_agents, register_agent, serialize_agent

router = APIRouter(prefix="/agents", tags=["agents"])


@router.post(
    "/register",
    response_model=AgentRegistrationResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_agent_enrollment_key)],
)
def register(
    registration: AgentRegistrationRequest,
    database: Session = Depends(get_db),
) -> AgentRegistrationResponse:
    try:
        agent, api_key = register_agent(database, registration)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return AgentRegistrationResponse(agent_id=agent.agent_id, api_key=api_key)


@router.post("/heartbeat", response_model=AgentHeartbeatResponse)
def heartbeat(agent: CollectorAgent = Depends(require_collector_agent)) -> AgentHeartbeatResponse:
    return AgentHeartbeatResponse(agent_id=agent.agent_id, status="ONLINE")


@router.get("", response_model=AgentPage, dependencies=[Depends(require_dashboard_user)])
def agents(database: Session = Depends(get_db)) -> AgentPage:
    items, total = list_agents(database)
    return AgentPage(items=items, total=total)


@router.get(
    "/{agent_id}", response_model=AgentRead, dependencies=[Depends(require_dashboard_user)]
)
def agent_detail(agent_id: str, database: Session = Depends(get_db)) -> AgentRead:
    agent = database.get(CollectorAgent, agent_id)
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    return serialize_agent(agent)
