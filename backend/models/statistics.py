from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.base import Base


class HistoricalMetricBucket(Base):
    __tablename__ = "historical_metric_buckets"
    __table_args__ = (
        UniqueConstraint("granularity", "bucket_start", name="uq_metric_bucket_time"),
        Index("ix_metric_bucket_range", "granularity", "bucket_start"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    granularity: Mapped[str] = mapped_column(String(20))
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    bytes_uploaded: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_downloaded: Mapped[int] = mapped_column(BigInteger, default=0)
    flow_count: Mapped[int] = mapped_column(BigInteger, default=0)
    active_hosts: Mapped[int] = mapped_column(Integer, default=0)
    alerts: Mapped[int] = mapped_column(BigInteger, default=0)


class HistoricalHostMetricBucket(Base):
    __tablename__ = "historical_host_metric_buckets"
    __table_args__ = (
        UniqueConstraint(
            "host_ip", "granularity", "bucket_start", name="uq_host_metric_bucket_time"
        ),
        Index(
            "ix_host_metric_bucket_range", "host_ip", "granularity", "bucket_start"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_ip: Mapped[str] = mapped_column(String(45))
    granularity: Mapped[str] = mapped_column(String(20))
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    bytes_uploaded: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_downloaded: Mapped[int] = mapped_column(BigInteger, default=0)
    flow_count: Mapped[int] = mapped_column(BigInteger, default=0)
