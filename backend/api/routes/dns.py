from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.database.session import get_db
from backend.schemas import DNSObservationPage, TopDomain
from backend.services.dns import list_dns_observations, top_domains

router = APIRouter(prefix="/dns", tags=["dns"])


@router.get("", response_model=DNSObservationPage)
def dns_observations(
    requesting_host: str | None = None,
    domain: str | None = None,
    query_type: str | None = None,
    response_status: str | None = None,
    minutes: int | None = Query(default=None, ge=1, le=10_080),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    database: Session = Depends(get_db),
) -> DNSObservationPage:
    seen_after = (
        datetime.now(timezone.utc) - timedelta(minutes=minutes)
        if minutes is not None
        else None
    )
    items, total = list_dns_observations(
        database,
        limit=limit,
        offset=offset,
        requesting_host=requesting_host,
        domain=domain,
        query_type=query_type,
        response_status=response_status,
        seen_after=seen_after,
    )
    return DNSObservationPage(items=items, total=total, limit=limit, offset=offset)


@router.get("/top-domains", response_model=list[TopDomain])
def most_requested_domains(
    minutes: int = Query(60, ge=1, le=10_080),
    limit: int = Query(10, ge=1, le=100),
    database: Session = Depends(get_db),
) -> list[TopDomain]:
    return top_domains(database, minutes=minutes, limit=limit)
