from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.models import NetworkFlow
from backend.schemas import LiveSummary, LiveUpdate, NetworkFlowRead, ProtocolCount


def build_live_update(
    database: Session, completed_flows: list[NetworkFlow]
) -> LiveUpdate:
    """Build a compact dashboard snapshot without exposing packet payloads."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=1)
    recent_query = (
        select(NetworkFlow)
        .where(NetworkFlow.last_seen >= cutoff)
        .order_by(NetworkFlow.last_seen.desc())
        .limit(25)
    )
    recent = list(database.scalars(recent_query))
    recent_bytes = int(
        database.scalar(
            select(func.sum(NetworkFlow.bytes)).where(NetworkFlow.last_seen >= cutoff)
        )
        or 0
    )
    active_connections = int(
        database.scalar(
            select(func.count()).select_from(NetworkFlow).where(
                NetworkFlow.last_seen >= cutoff
            )
        )
        or 0
    )
    total_flows = int(database.scalar(select(func.count()).select_from(NetworkFlow)) or 0)
    total_bytes = int(database.scalar(select(func.sum(NetworkFlow.bytes))) or 0)
    total_packets = int(database.scalar(select(func.sum(NetworkFlow.packet_count))) or 0)
    protocol_rows = database.execute(
        select(NetworkFlow.protocol, func.count(NetworkFlow.id))
        .group_by(NetworkFlow.protocol)
        .order_by(func.count(NetworkFlow.id).desc(), NetworkFlow.protocol.asc())
    ).all()

    return LiveUpdate(
        timestamp=now,
        summary=LiveSummary(
            throughput_bps=(recent_bytes * 8) / 60,
            active_connections=active_connections,
            total_flows=total_flows,
            total_bytes=total_bytes,
            total_packets=total_packets,
            protocols=[
                ProtocolCount(protocol=protocol, flow_count=int(count))
                for protocol, count in protocol_rows
            ],
        ),
        recent_flows=[NetworkFlowRead.model_validate(flow) for flow in recent],
        completed_flows=[
            NetworkFlowRead.model_validate(flow) for flow in completed_flows[-25:]
        ],
    )
