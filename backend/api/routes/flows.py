from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.database.session import get_db
from backend.schemas import FlowPage
from backend.services.queries import list_flows

router = APIRouter(prefix="/flows", tags=["flows"])


@router.get("", response_model=FlowPage)
def flows(
    protocol: str | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    agent_id: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    database: Session = Depends(get_db),
) -> FlowPage:
    items, total = list_flows(
        database,
        limit=limit,
        offset=offset,
        protocol=protocol,
        source_ip=source_ip,
        destination_ip=destination_ip,
        agent_id=agent_id,
    )
    return FlowPage(items=items, total=total, limit=limit, offset=offset)


@router.get("/recent", response_model=FlowPage)
def recent_flows(
    minutes: int = Query(60, ge=1, le=10_080),
    protocol: str | None = None,
    agent_id: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    database: Session = Depends(get_db),
) -> FlowPage:
    seen_after = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    items, total = list_flows(
        database,
        limit=limit,
        offset=offset,
        protocol=protocol,
        seen_after=seen_after,
        agent_id=agent_id,
    )
    return FlowPage(items=items, total=total, limit=limit, offset=offset)
