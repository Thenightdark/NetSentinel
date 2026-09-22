from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from .flow import NetworkFlowRead


class AlertSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class SecurityAlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    agent_id: str | None
    timestamp: datetime
    severity: AlertSeverity
    risk_score: int = Field(ge=0, le=100)
    alert_type: str
    source_ip: str | None
    destination_ip: str | None
    description: str
    evidence: dict[str, object]
    status: AlertStatus


class AlertStatusUpdate(BaseModel):
    status: AlertStatus


class AlertPage(BaseModel):
    items: list[SecurityAlertRead]
    total: int
    limit: int
    offset: int


class SecurityEventHost(BaseModel):
    id: int
    ip_address: str
    hostname: str | None
    first_seen: datetime
    last_seen: datetime
    total_bytes: int
    total_connections: int
    is_active: bool


class SecurityEventDetail(SecurityAlertRead):
    why_flagged: str
    related_flows: list[NetworkFlowRead]
    host: SecurityEventHost | None
    recommended_investigation_steps: list[str]
