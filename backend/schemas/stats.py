from pydantic import BaseModel


class ProtocolCount(BaseModel):
    protocol: str
    flow_count: int


class StatsSummary(BaseModel):
    hosts: int
    flows: int
    alerts: int
    open_alerts: int
    total_bytes: int
    total_packets: int
    protocols: list[ProtocolCount]

