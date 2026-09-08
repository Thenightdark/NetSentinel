from datetime import datetime

from pydantic import BaseModel

from .flow import NetworkFlowRead
from .stats import ProtocolCount


class LiveSummary(BaseModel):
    throughput_bps: float
    active_connections: int
    total_flows: int
    total_bytes: int
    total_packets: int
    protocols: list[ProtocolCount]


class LiveUpdate(BaseModel):
    type: str = "live.update"
    timestamp: datetime
    summary: LiveSummary
    recent_flows: list[NetworkFlowRead]
    completed_flows: list[NetworkFlowRead]
