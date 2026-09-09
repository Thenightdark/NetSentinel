from datetime import datetime, timedelta, timezone

from sqlalchemy import distinct, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.models import DNSIngestBatch, DNSObservation
from backend.schemas import DNSIngestRequest, TopDomain


def ingest_dns_batch(
    database: Session, request: DNSIngestRequest
) -> tuple[int, bool, list[DNSObservation]]:
    batch_id = str(request.batch_id)
    existing = database.get(DNSIngestBatch, batch_id)
    if existing is not None:
        return existing.observation_count, True, []

    observations = [
        DNSObservation(
            requesting_host=str(item.requesting_host),
            queried_domain=item.queried_domain,
            timestamp=item.timestamp,
            query_type=item.query_type,
            response_status=item.response_status,
            is_response=item.is_response,
        )
        for item in request.observations
    ]
    database.add_all(observations)
    database.add(
        DNSIngestBatch(batch_id=batch_id, observation_count=len(observations))
    )
    try:
        database.commit()
    except IntegrityError:
        database.rollback()
        existing = database.get(DNSIngestBatch, batch_id)
        if existing is None:
            raise
        return existing.observation_count, True, []
    return len(observations), False, observations


def list_dns_observations(
    database: Session,
    *,
    limit: int,
    offset: int,
    requesting_host: str | None = None,
    domain: str | None = None,
    query_type: str | None = None,
    response_status: str | None = None,
    seen_after: datetime | None = None,
) -> tuple[list[DNSObservation], int]:
    filters = []
    if requesting_host:
        filters.append(DNSObservation.requesting_host == requesting_host)
    if domain:
        filters.append(DNSObservation.queried_domain.ilike(f"%{domain}%"))
    if query_type:
        filters.append(func.upper(DNSObservation.query_type) == query_type.upper())
    if response_status:
        filters.append(
            func.upper(DNSObservation.response_status) == response_status.upper()
        )
    if seen_after:
        filters.append(DNSObservation.timestamp >= seen_after)
    query = (
        select(DNSObservation)
        .where(*filters)
        .order_by(DNSObservation.timestamp.desc())
    )
    count_query = select(func.count()).select_from(DNSObservation).where(*filters)
    return (
        list(database.scalars(query.offset(offset).limit(limit))),
        int(database.scalar(count_query) or 0),
    )


def top_domains(
    database: Session, *, minutes: int, limit: int
) -> list[TopDomain]:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    rows = database.execute(
        select(
            DNSObservation.queried_domain,
            func.count(DNSObservation.id),
            func.count(distinct(DNSObservation.requesting_host)),
        )
        .where(
            DNSObservation.timestamp >= cutoff,
            DNSObservation.is_response.is_(False),
        )
        .group_by(DNSObservation.queried_domain)
        .order_by(func.count(DNSObservation.id).desc(), DNSObservation.queried_domain)
        .limit(limit)
    ).all()
    return [
        TopDomain(domain=domain, query_count=int(count), unique_clients=int(clients))
        for domain, count, clients in rows
    ]
