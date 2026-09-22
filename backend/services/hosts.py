"""Passive host discovery and host-level traffic statistics."""

from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
import logging
import socket

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from backend.models import HistoricalHostMetricBucket, Host, NetworkFlow, SecurityAlert
from backend.schemas import (
    FlowIngestItem,
    HostDestinationStats,
    HostDetail,
    HostPortStats,
    HostProtocolStats,
    HostRead,
    HostTimelinePoint,
)

LOGGER = logging.getLogger(__name__)
LOCAL_NETWORKS = (
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
    ip_network("::1/128"),
)


def is_local_network_address(value: str) -> bool:
    try:
        parsed = ip_address(value)
    except ValueError:
        return False
    return any(parsed in network for network in LOCAL_NETWORKS)


def resolve_hostname(value: str) -> str | None:
    """Ask the local OS resolver for a name; never contact the host itself."""
    try:
        hostname, _, _ = socket.gethostbyaddr(value)
    except OSError:
        return None
    normalized = hostname.rstrip(".")
    return normalized if normalized and normalized != value else None


def track_local_hosts_for_flow(
    database: Session,
    item: FlowIngestItem,
    cache: dict[str, Host],
    agent_id: str | None = None,
) -> set[str]:
    newly_observed: set[str] = set()
    for value in {str(item.source_ip), str(item.destination_ip)}:
        if not is_local_network_address(value):
            continue
        host = cache.get(value)
        if host is None:
            host = database.scalar(
                select(Host).where(Host.ip_address == value, Host.agent_id == agent_id)
            )
            if host is None:
                host = Host(
                    agent_id=agent_id,
                    ip_address=value,
                    hostname=resolve_hostname(value),
                    first_seen=item.first_seen,
                    last_seen=item.last_seen,
                    total_bytes=0,
                    total_connections=0,
                )
                database.add(host)
                newly_observed.add(value)
                LOGGER.info("Discovered local host %s", value)
            cache[value] = host

        host.first_seen = min(_as_utc(host.first_seen), _as_utc(item.first_seen))
        host.last_seen = max(_as_utc(host.last_seen), _as_utc(item.last_seen))
        host.total_bytes += item.bytes
        host.total_connections += 1
    return newly_observed


def host_is_active(
    host: Host, timeout_seconds: float, as_of: datetime | None = None
) -> bool:
    reference = as_of or datetime.now(timezone.utc)
    return reference - _as_utc(host.last_seen) <= timedelta(seconds=timeout_seconds)


def serialize_host(host: Host, timeout_seconds: float) -> HostRead:
    return HostRead(
        id=host.id,
        agent_id=host.agent_id,
        ip_address=host.ip_address,
        hostname=host.hostname,
        first_seen=host.first_seen,
        last_seen=host.last_seen,
        total_bytes=host.total_bytes,
        total_connections=host.total_connections,
        is_active=host_is_active(host, timeout_seconds),
    )


def get_host_detail(
    database: Session, host: Host, timeout_seconds: float
) -> HostDetail:
    host_filter = or_(
        NetworkFlow.source_ip == host.ip_address,
        NetworkFlow.destination_ip == host.ip_address,
    )
    host_filter = (host_filter, NetworkFlow.agent_id == host.agent_id)
    alert_filter = or_(
        SecurityAlert.source_ip == host.ip_address,
        SecurityAlert.destination_ip == host.ip_address,
    )
    destination_rows = database.execute(
        select(
            NetworkFlow.destination_ip,
            func.sum(NetworkFlow.bytes),
            func.count(NetworkFlow.id),
        )
        .where(NetworkFlow.source_ip == host.ip_address, NetworkFlow.agent_id == host.agent_id)
        .group_by(NetworkFlow.destination_ip)
        .order_by(func.sum(NetworkFlow.bytes).desc())
        .limit(5)
    ).all()
    protocol_rows = database.execute(
        select(
            NetworkFlow.protocol,
            func.sum(NetworkFlow.bytes),
            func.count(NetworkFlow.id),
        )
        .where(*host_filter)
        .group_by(NetworkFlow.protocol)
        .order_by(func.sum(NetworkFlow.bytes).desc())
        .limit(10)
    ).all()
    port_rows = database.execute(
        select(
            NetworkFlow.destination_port,
            func.sum(NetworkFlow.bytes),
            func.count(NetworkFlow.id),
        )
        .where(
            NetworkFlow.source_ip == host.ip_address,
            NetworkFlow.agent_id == host.agent_id,
            NetworkFlow.destination_port.is_not(None),
        )
        .group_by(NetworkFlow.destination_port)
        .order_by(func.sum(NetworkFlow.bytes).desc())
        .limit(10)
    ).all()
    recent_flows = list(
        database.scalars(
            select(NetworkFlow)
            .where(*host_filter)
            .order_by(NetworkFlow.last_seen.desc())
            .limit(10)
        )
    )
    recent_alerts = list(
        database.scalars(
            select(SecurityAlert)
            .where(alert_filter, SecurityAlert.agent_id == host.agent_id)
            .order_by(SecurityAlert.timestamp.desc())
            .limit(10)
        )
    )
    risk_score = int(
        database.scalar(
            select(func.max(SecurityAlert.risk_score)).where(
                alert_filter, SecurityAlert.agent_id == host.agent_id,
                func.upper(SecurityAlert.status) != "RESOLVED",
            )
        )
        or 0
    )
    activity = _host_activity(database, host.ip_address, host.agent_id)
    base = serialize_host(host, timeout_seconds)
    return HostDetail(
        **base.model_dump(),
        risk_score=risk_score,
        top_destinations=[
            HostDestinationStats(
                ip_address=destination,
                bytes=int(total_bytes or 0),
                connections=int(connections),
            )
            for destination, total_bytes, connections in destination_rows
        ],
        top_destination_ports=[
            HostPortStats(
                port=int(port),
                bytes=int(total_bytes or 0),
                connections=int(connections),
            )
            for port, total_bytes, connections in port_rows
        ],
        most_used_protocols=[
            HostProtocolStats(
                protocol=protocol,
                bytes=int(total_bytes or 0),
                connections=int(connections),
            )
            for protocol, total_bytes, connections in protocol_rows
        ],
        activity_over_time=activity,
        recent_flows=recent_flows,
        recent_alerts=recent_alerts,
    )


def _host_activity(database: Session, host_address: str, agent_id: str | None) -> list[HostTimelinePoint]:
    """Read the host's bounded hourly rollups instead of scanning raw flows."""
    now = datetime.now(timezone.utc)
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    first_hour = current_hour - timedelta(hours=23)
    rows = database.execute(
            select(
            HistoricalHostMetricBucket.bucket_start,
            HistoricalHostMetricBucket.bytes_uploaded,
            HistoricalHostMetricBucket.bytes_downloaded,
            HistoricalHostMetricBucket.flow_count,
        ).where(
            HistoricalHostMetricBucket.host_ip == host_address,
            HistoricalHostMetricBucket.agent_id == agent_id,
            HistoricalHostMetricBucket.granularity == "hour",
            HistoricalHostMetricBucket.bucket_start >= first_hour,
        )
    ).all()
    buckets = {
        first_hour + timedelta(hours=index): {"bytes": 0, "connections": 0}
        for index in range(24)
    }
    for bucket_start, uploaded, downloaded, flow_count in rows:
        seen = _as_utc(bucket_start)
        bucket = buckets.get(seen)
        if bucket is not None:
            bucket["bytes"] += int(uploaded or 0) + int(downloaded or 0)
            bucket["connections"] += int(flow_count or 0)
    return [
        HostTimelinePoint(
            timestamp=timestamp,
            bytes=values["bytes"],
            connections=values["connections"],
        )
        for timestamp, values in buckets.items()
    ]


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
