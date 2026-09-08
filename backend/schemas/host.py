from datetime import datetime

from pydantic import BaseModel, ConfigDict


class HostRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
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


class HostDetail(HostRead):
    top_destinations: list[HostDestinationStats]
    most_used_protocols: list[HostProtocolStats]


class HostPage(BaseModel):
    items: list[HostRead]
    total: int
    limit: int
    offset: int
