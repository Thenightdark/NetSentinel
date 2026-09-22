from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.database.session import get_db
from backend.schemas import NetworkMapResponse
from backend.services.network_map import build_network_map

router = APIRouter(prefix="/map", tags=["network map"])


@router.get("", response_model=NetworkMapResponse)
def network_map(
    minutes: int = Query(60, ge=5, le=10_080),
    agent_id: str | None = None,
    max_external_nodes: int = Query(12, ge=3, le=40),
    max_lan_nodes: int = Query(40, ge=5, le=100),
    database: Session = Depends(get_db),
) -> NetworkMapResponse:
    return build_network_map(
        database,
        window_minutes=minutes,
        agent_id=agent_id,
        max_external_nodes=max_external_nodes,
        max_lan_nodes=max_lan_nodes,
    )
