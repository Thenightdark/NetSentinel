from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.config import get_settings
from backend.database.session import get_db
from backend.models import Host
from backend.schemas import HostDetail, HostPage
from backend.services.hosts import get_host_detail, serialize_host
from backend.services.queries import list_hosts

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("", response_model=HostPage)
def hosts(
    search: str | None = None,
    active: bool | None = None,
    agent_id: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    database: Session = Depends(get_db),
) -> HostPage:
    timeout = get_settings().host_active_timeout_seconds
    items, total = list_hosts(
        database,
        limit=limit,
        offset=offset,
        search=search,
        active=active,
        active_timeout_seconds=timeout,
        agent_id=agent_id,
    )
    return HostPage(
        items=[serialize_host(item, timeout) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{host_id}", response_model=HostDetail)
def host_detail(
    host_id: int,
    database: Session = Depends(get_db),
) -> HostDetail:
    host = database.get(Host, host_id)
    if host is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Host not found",
        )
    return get_host_detail(database, host, get_settings().host_active_timeout_seconds)
