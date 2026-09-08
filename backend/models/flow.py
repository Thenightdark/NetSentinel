from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.base import Base


class NetworkFlow(Base):
    __tablename__ = "network_flows"
    __table_args__ = (
        Index("ix_flow_endpoints", "source_ip", "destination_ip"),
        Index("ix_flow_protocol_last_seen", "protocol", "last_seen"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    destination_ip: Mapped[str] = mapped_column(String(45), index=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(20), index=True)
    bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    packet_count: Mapped[int] = mapped_column(BigInteger, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

