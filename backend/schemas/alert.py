from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


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
