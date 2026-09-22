from pydantic import BaseModel


class NetworkMapNode(BaseModel):
    id: str
    label: str
    ip_address: str | None
    kind: str
    agent_id: str | None
    host_id: int | None
    connections: int
    bytes: int
    grouped_destinations: int = 0


class NetworkMapEdge(BaseModel):
    id: str
    source: str
    target: str
    connections: int
    bytes: int
    protocols: list[str]


class NetworkMapResponse(BaseModel):
    window_minutes: int
    nodes: list[NetworkMapNode]
    edges: list[NetworkMapEdge]
    aggregated_flow_groups: int
