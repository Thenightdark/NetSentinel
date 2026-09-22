from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.base import Base


class DNSObservation(Base):
    __tablename__ = "dns_observations"
    __table_args__ = (
        Index("ix_dns_domain_timestamp", "queried_domain", "timestamp"),
        Index("ix_dns_client_timestamp", "requesting_host", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    requesting_host: Mapped[str] = mapped_column(String(45), index=True)
    queried_domain: Mapped[str] = mapped_column(String(253), index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    query_type: Mapped[str] = mapped_column(String(20), index=True)
    response_status: Mapped[str | None] = mapped_column(String(30), nullable=True, index=True)
    is_response: Mapped[bool] = mapped_column(Boolean, default=False, index=True)


class DNSIngestBatch(Base):
    __tablename__ = "dns_ingest_batches"

    batch_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    observation_count: Mapped[int] = mapped_column(Integer)
