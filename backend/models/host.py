from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, Integer, String, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Host(Base):
    __tablename__ = "hosts"
    __table_args__ = (UniqueConstraint("agent_id", "ip_address", name="uq_host_agent_ip"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    total_bytes: Mapped[int] = mapped_column(BigInteger, default=0, server_default=text("0"))
    total_connections: Mapped[int] = mapped_column(
        BigInteger, default=0, server_default=text("0")
    )
