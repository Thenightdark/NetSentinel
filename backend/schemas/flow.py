from datetime import datetime

from pydantic import BaseModel, ConfigDict


class NetworkFlowRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    agent_id: str | None
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    protocol: str
    process_id: int | None
    process_name: str | None
    executable_name: str | None
    bytes: int
    packet_count: int
    first_seen: datetime
    last_seen: datetime


class FlowPage(BaseModel):
    items: list[NetworkFlowRead]
    total: int
    limit: int
    offset: int
