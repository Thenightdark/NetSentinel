from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.base import Base


class DetectionSettings(Base):
    __tablename__ = "detection_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    port_scan_unique_ports: Mapped[int] = mapped_column(Integer, default=25)
    port_scan_window_seconds: Mapped[int] = mapped_column(Integer, default=10)
    bandwidth_spike_megabytes: Mapped[int] = mapped_column(Integer, default=500)
    bandwidth_spike_window_seconds: Mapped[int] = mapped_column(Integer, default=300)
    connection_spike_connections: Mapped[int] = mapped_column(Integer, default=500)
    connection_spike_window_seconds: Mapped[int] = mapped_column(Integer, default=60)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
