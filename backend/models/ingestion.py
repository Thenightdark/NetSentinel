from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.base import Base


class IngestBatch(Base):
    """Idempotency record so collector retries cannot duplicate flows."""

    __tablename__ = "ingest_batches"

    batch_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    flow_count: Mapped[int] = mapped_column(Integer)

