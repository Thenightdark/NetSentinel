"""Passive host discovery and host-level traffic statistics."""

from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
import logging
import socket

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from backend.models import Host, NetworkFlow
from backend.schemas import (
    FlowIngestItem,
    HostDestinationStats,
    HostDetail,
    HostProtocolStats,
    HostRead,
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
) -> set[str]:
    newly_observed: set[str] = set()
    for value in {str(item.source_ip), str(item.destination_ip)}:
        if not is_local_network_address(value):
            continue
        host = cache.get(value)
        if host is None:
            host = database.scalar(select(Host).where(Host.ip_address == value))
            if host is None:
                host = Host(
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
    destination_rows = database.execute(
        select(
            NetworkFlow.destination_ip,
            func.sum(NetworkFlow.bytes),
            func.count(NetworkFlow.id),
        )
        .where(NetworkFlow.source_ip == host.ip_address)
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
        .where(
            or_(
                NetworkFlow.source_ip == host.ip_address,
                NetworkFlow.destination_ip == host.ip_address,
            )
        )
        .group_by(NetworkFlow.protocol)
        .order_by(func.sum(NetworkFlow.bytes).desc())
        .limit(10)
    ).all()
    base = serialize_host(host, timeout_seconds)
    return HostDetail(
        **base.model_dump(),
        top_destinations=[
            HostDestinationStats(
                ip_address=destination,
                bytes=int(total_bytes or 0),
                connections=int(connections),
            )
            for destination, total_bytes, connections in destination_rows
        ],
        most_used_protocols=[
            HostProtocolStats(
                protocol=protocol,
                bytes=int(total_bytes or 0),
                connections=int(connections),
            )
            for protocol, total_bytes, connections in protocol_rows
        ],
    )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
