from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SecurityAlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    severity: str
    alert_type: str
    source_ip: str | None
    destination_ip: str | None
    description: str
    evidence: dict[str, object]
    status: str


class AlertPage(BaseModel):
    items: list[SecurityAlertRead]
    total: int
    limit: int
    offset: int
