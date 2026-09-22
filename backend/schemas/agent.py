from datetime import datetime

from pydantic import BaseModel, Field, IPvAnyAddress


class AgentRegistrationRequest(BaseModel):
    agent_id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    hostname: str = Field(min_length=1, max_length=255)
    operating_system: str = Field(min_length=1, max_length=255)
    ip_address: IPvAnyAddress
    version: str = Field(min_length=1, max_length=40)


class AgentRegistrationResponse(BaseModel):
    agent_id: str
    api_key: str


class AgentRead(BaseModel):
    agent_id: str
    hostname: str
    operating_system: str
    ip_address: str
    version: str
    first_seen: datetime
    last_seen: datetime
    status: str


class AgentPage(BaseModel):
    items: list[AgentRead]
    total: int


class AgentHeartbeatResponse(BaseModel):
    agent_id: str
    status: str
