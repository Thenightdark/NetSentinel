from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from backend.models import (
    HistoricalHostMetricBucket,
    HistoricalMetricBucket,
    NetworkFlow,
    SecurityAlert,
)
from backend.schemas import HistoricalMetricPoint, HistoricalStatsResponse, HistoryRange
from backend.services.hosts import is_local_network_address


@dataclass(frozen=True, slots=True)
class RollupSpec:
    granularity: str
    bucket_seconds: int
    points: int
    retention_seconds: int


RANGE_SPECS: dict[HistoryRange, RollupSpec] = {
    "5m": RollupSpec("minute", 60, 5, 15 * 60),
    "1h": RollupSpec("five_minutes", 5 * 60, 12, 2 * 60 * 60),
    "24h": RollupSpec("hour", 60 * 60, 24, 2 * 24 * 60 * 60),
    "7d": RollupSpec("six_hours", 6 * 60 * 60, 28, 8 * 24 * 60 * 60),
}


def record_flow_statistics(database: Session, flows: list[NetworkFlow]) -> None:
    bucket_cache: dict[tuple[str, datetime], HistoricalMetricBucket] = {}
    host_bucket_cache: dict[tuple[str, str, datetime], HistoricalHostMetricBucket] = {}
    for flow in flows:
        local_hosts = {
            address
            for address in (flow.source_ip, flow.destination_ip)
            if is_local_network_address(address)
        }
        uploaded = flow.bytes if is_local_network_address(flow.source_ip) else 0
        downloaded = flow.bytes if is_local_network_address(flow.destination_ip) else 0
        for spec in RANGE_SPECS.values():
            start = floor_time(flow.last_seen, spec.bucket_seconds)
            bucket = _get_bucket(database, spec, start, bucket_cache)
            bucket.bytes_uploaded += uploaded
            bucket.bytes_downloaded += downloaded
            bucket.flow_count += 1
            for host_address in local_hosts:
                host_bucket, created = _get_host_bucket(
                    database, spec, start, host_address, host_bucket_cache
                )
                if created:
                    bucket.active_hosts += 1
                if flow.source_ip == host_address:
                    host_bucket.bytes_uploaded += flow.bytes
                if flow.destination_ip == host_address:
                    host_bucket.bytes_downloaded += flow.bytes
                host_bucket.flow_count += 1
    _prune_expired(database, datetime.now(timezone.utc))


def record_alert_statistics(database: Session, alerts: list[SecurityAlert]) -> None:
    bucket_cache: dict[tuple[str, datetime], HistoricalMetricBucket] = {}
    for alert in alerts:
        for spec in RANGE_SPECS.values():
            start = floor_time(alert.timestamp, spec.bucket_seconds)
            bucket = _get_bucket(database, spec, start, bucket_cache)
            bucket.alerts += 1
    _prune_expired(database, datetime.now(timezone.utc))


def get_historical_statistics(
    database: Session,
    history_range: HistoryRange,
    as_of: datetime | None = None,
) -> HistoricalStatsResponse:
    spec = RANGE_SPECS[history_range]
    end = floor_time(as_of or datetime.now(timezone.utc), spec.bucket_seconds)
    start = end - timedelta(seconds=spec.bucket_seconds * (spec.points - 1))
    stored = {
        _as_utc(bucket.bucket_start): bucket
        for bucket in database.scalars(
            select(HistoricalMetricBucket).where(
                HistoricalMetricBucket.granularity == spec.granularity,
                HistoricalMetricBucket.bucket_start >= start,
                HistoricalMetricBucket.bucket_start <= end,
            )
        )
    }
    items = []
    for index in range(spec.points):
        timestamp = start + timedelta(seconds=index * spec.bucket_seconds)
        bucket = stored.get(timestamp)
        items.append(
            HistoricalMetricPoint(
                timestamp=timestamp,
                bytes_uploaded=bucket.bytes_uploaded if bucket else 0,
                bytes_downloaded=bucket.bytes_downloaded if bucket else 0,
                flow_count=bucket.flow_count if bucket else 0,
                active_hosts=bucket.active_hosts if bucket else 0,
                alerts=bucket.alerts if bucket else 0,
            )
        )
    return HistoricalStatsResponse(
        range=history_range,
        bucket_seconds=spec.bucket_seconds,
        start=start,
        end=end + timedelta(seconds=spec.bucket_seconds),
        items=items,
    )


def floor_time(value: datetime, bucket_seconds: int) -> datetime:
    value = _as_utc(value)
    epoch = int(value.timestamp())
    return datetime.fromtimestamp(
        epoch - (epoch % bucket_seconds),
        tz=timezone.utc,
    )


def _get_bucket(
    database: Session,
    spec: RollupSpec,
    start: datetime,
    cache: dict[tuple[str, datetime], HistoricalMetricBucket],
) -> HistoricalMetricBucket:
    key = (spec.granularity, start)
    if key in cache:
        return cache[key]
    bucket = database.scalar(
        select(HistoricalMetricBucket).where(
            HistoricalMetricBucket.granularity == spec.granularity,
            HistoricalMetricBucket.bucket_start == start,
        ).with_for_update()
    )
    if bucket is None:
        bucket = HistoricalMetricBucket(
            granularity=spec.granularity,
            bucket_start=start,
            bytes_uploaded=0,
            bytes_downloaded=0,
            flow_count=0,
            active_hosts=0,
            alerts=0,
        )
        database.add(bucket)
        database.flush()
    cache[key] = bucket
    return bucket


def _get_host_bucket(
    database: Session,
    spec: RollupSpec,
    start: datetime,
    host_address: str,
    cache: dict[tuple[str, str, datetime], HistoricalHostMetricBucket],
) -> tuple[HistoricalHostMetricBucket, bool]:
    key = (host_address, spec.granularity, start)
    if key in cache:
        return cache[key], False
    bucket = database.scalar(
        select(HistoricalHostMetricBucket).where(
            HistoricalHostMetricBucket.host_ip == host_address,
            HistoricalHostMetricBucket.granularity == spec.granularity,
            HistoricalHostMetricBucket.bucket_start == start,
        ).with_for_update()
    )
    created = bucket is None
    if bucket is None:
        bucket = HistoricalHostMetricBucket(
            host_ip=host_address,
            granularity=spec.granularity,
            bucket_start=start,
            bytes_uploaded=0,
            bytes_downloaded=0,
            flow_count=0,
        )
        database.add(bucket)
    cache[key] = bucket
    return bucket, created


def _prune_expired(database: Session, as_of: datetime) -> None:
    for spec in RANGE_SPECS.values():
        cutoff = as_of - timedelta(seconds=spec.retention_seconds)
        database.execute(
            delete(HistoricalHostMetricBucket).where(
                HistoricalHostMetricBucket.granularity == spec.granularity,
                HistoricalHostMetricBucket.bucket_start < cutoff,
            ).execution_options(synchronize_session="fetch")
        )
        database.execute(
            delete(HistoricalMetricBucket).where(
                HistoricalMetricBucket.granularity == spec.granularity,
                HistoricalMetricBucket.bucket_start < cutoff,
            ).execution_options(synchronize_session="fetch")
        )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
