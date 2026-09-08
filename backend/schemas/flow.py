from datetime import datetime

from pydantic import BaseModel, ConfigDict


class NetworkFlowRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    protocol: str
    bytes: int
    packet_count: int
    first_seen: datetime
    last_seen: datetime


class FlowPage(BaseModel):
    items: list[NetworkFlowRead]
    total: int
    limit: int
    offset: int

