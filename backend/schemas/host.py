from datetime import datetime

from pydantic import BaseModel, ConfigDict

from .alert import SecurityAlertRead
from .flow import NetworkFlowRead


class HostRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    agent_id: str | None
    ip_address: str
    hostname: str | None
    first_seen: datetime
    last_seen: datetime
    total_bytes: int
    total_connections: int
    is_active: bool


class HostDestinationStats(BaseModel):
    ip_address: str
    bytes: int
    connections: int


class HostProtocolStats(BaseModel):
    protocol: str
    bytes: int
    connections: int


class HostPortStats(BaseModel):
    port: int
    bytes: int
    connections: int


class HostTimelinePoint(BaseModel):
    timestamp: datetime
    bytes: int
    connections: int


class HostDetail(HostRead):
    risk_score: int
    top_destinations: list[HostDestinationStats]
    top_destination_ports: list[HostPortStats]
    most_used_protocols: list[HostProtocolStats]
    activity_over_time: list[HostTimelinePoint]
    recent_flows: list[NetworkFlowRead]
    recent_alerts: list[SecurityAlertRead]


class HostPage(BaseModel):
    items: list[HostRead]
    total: int
    limit: int
    offset: int
