from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from backend.models import Host, NetworkFlow, SecurityAlert


def list_flows(
    database: Session,
    *,
    limit: int,
    offset: int,
    protocol: str | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    seen_after: datetime | None = None,
) -> tuple[list[NetworkFlow], int]:
    filters = []
    if protocol:
        filters.append(func.upper(NetworkFlow.protocol) == protocol.upper())
    if source_ip:
        filters.append(NetworkFlow.source_ip == source_ip)
    if destination_ip:
        filters.append(NetworkFlow.destination_ip == destination_ip)
    if seen_after:
        filters.append(NetworkFlow.last_seen >= seen_after)

    query = select(NetworkFlow).where(*filters).order_by(NetworkFlow.last_seen.desc())
    count_query = select(func.count()).select_from(NetworkFlow).where(*filters)
    items = list(database.scalars(query.offset(offset).limit(limit)))
    total = int(database.scalar(count_query) or 0)
    return items, total


def list_hosts(
    database: Session,
    *,
    limit: int,
    offset: int,
    search: str | None = None,
    active: bool | None = None,
    active_timeout_seconds: float = 300.0,
) -> tuple[list[Host], int]:
    filters = []
    if search:
        pattern = f"%{search}%"
        filters.append(or_(Host.ip_address.ilike(pattern), Host.hostname.ilike(pattern)))
    if active is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=active_timeout_seconds)
        filters.append(Host.last_seen >= cutoff if active else Host.last_seen < cutoff)
    query = select(Host).where(*filters).order_by(Host.last_seen.desc())
    count_query = select(func.count()).select_from(Host).where(*filters)
    return (
        list(database.scalars(query.offset(offset).limit(limit))),
        int(database.scalar(count_query) or 0),
    )


def list_alerts(
    database: Session,
    *,
    limit: int,
    offset: int,
    severity: str | None = None,
    status: str | None = None,
    alert_type: str | None = None,
) -> tuple[list[SecurityAlert], int]:
    filters = []
    if severity:
        filters.append(func.lower(SecurityAlert.severity) == severity.lower())
    if status:
        filters.append(func.lower(SecurityAlert.status) == status.lower())
    if alert_type:
        filters.append(SecurityAlert.alert_type == alert_type)
    query = select(SecurityAlert).where(*filters).order_by(SecurityAlert.timestamp.desc())
    count_query = select(func.count()).select_from(SecurityAlert).where(*filters)
    return (
        list(database.scalars(query.offset(offset).limit(limit))),
        int(database.scalar(count_query) or 0),
    )


def get_stats_summary(database: Session) -> dict[str, object]:
    protocol_rows = database.execute(
        select(NetworkFlow.protocol, func.count(NetworkFlow.id))
        .group_by(NetworkFlow.protocol)
        .order_by(func.count(NetworkFlow.id).desc(), NetworkFlow.protocol.asc())
    ).all()
    return {
        "hosts": int(database.scalar(select(func.count()).select_from(Host)) or 0),
        "flows": int(database.scalar(select(func.count()).select_from(NetworkFlow)) or 0),
        "alerts": int(database.scalar(select(func.count()).select_from(SecurityAlert)) or 0),
        "open_alerts": int(
            database.scalar(
                select(func.count()).select_from(SecurityAlert).where(
                    func.lower(SecurityAlert.status) == "open"
                )
            ) or 0
        ),
        "total_bytes": int(database.scalar(select(func.sum(NetworkFlow.bytes))) or 0),
        "total_packets": int(database.scalar(select(func.sum(NetworkFlow.packet_count))) or 0),
        "protocols": [
            {"protocol": protocol, "flow_count": int(count)}
            for protocol, count in protocol_rows
        ],
    }
