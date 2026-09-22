from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.base import Base


class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    severity: Mapped[str] = mapped_column(String(20), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    alert_type: Mapped[str] = mapped_column(String(80), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    description: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict[str, object]] = mapped_column(
        JSON, default=dict, server_default=text("'{}'")
    )
    status: Mapped[str] = mapped_column(String(20), default="NEW", index=True)
