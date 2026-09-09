from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.database.base import Base
from backend.api.dependencies import require_dashboard_user
from backend.database.session import get_db
from backend.main import app
from backend.models import (
    HistoricalHostMetricBucket,
    HistoricalMetricBucket,
    NetworkFlow,
    SecurityAlert,
)
from backend.services.statistics import (
    RANGE_SPECS,
    get_historical_statistics,
    record_alert_statistics,
    record_flow_statistics,
)


def flow(source: str, destination: str, size: int, seen: datetime) -> NetworkFlow:
    return NetworkFlow(
        source_ip=source,
        destination_ip=destination,
        source_port=51000,
        destination_port=443,
        protocol="TCP",
        bytes=size,
        packet_count=4,
        first_seen=seen - timedelta(seconds=2),
        last_seen=seen,
    )


def test_rollups_track_direction_counts_and_distinct_active_hosts() -> None:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)
    with Session(engine) as database:
        flows = [
            flow("192.168.1.20", "8.8.8.8", 100, now),
            flow("1.1.1.1", "192.168.1.20", 250, now),
        ]
        alert = SecurityAlert(
            timestamp=now,
            severity="LOW",
            risk_score=25,
            alert_type="test_signal",
            source_ip="192.168.1.20",
            description="Test signal",
            evidence={},
            status="NEW",
        )
        record_flow_statistics(database, flows)
        record_alert_statistics(database, [alert])
        database.commit()

        history = get_historical_statistics(database, "5m", as_of=now)
        latest = history.items[-1]
        assert latest.bytes_uploaded == 100
        assert latest.bytes_downloaded == 250
        assert latest.flow_count == 2
        assert latest.active_hosts == 1
        assert latest.alerts == 1
        assert len(history.items) == 5
        assert database.scalar(
            select(func.count()).select_from(HistoricalMetricBucket)
        ) == len(RANGE_SPECS)
        assert database.scalar(
            select(func.count()).select_from(HistoricalHostMetricBucket)
        ) == len(RANGE_SPECS)
    engine.dispose()


def test_history_api_returns_fixed_small_bucket_sets() -> None:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)

    def override_database():
        with Session(engine) as database:
            yield database

    app.dependency_overrides[get_db] = override_database
    app.dependency_overrides[require_dashboard_user] = lambda: object()
    try:
        with TestClient(app) as client:
            expected = {"5m": (5, 60), "1h": (12, 300), "24h": (24, 3600), "7d": (28, 21600)}
            for history_range, (points, seconds) in expected.items():
                response = client.get("/api/stats/history", params={"range": history_range})
                assert response.status_code == 200
                assert len(response.json()["items"]) == points
                assert response.json()["bucket_seconds"] == seconds
            assert client.get("/api/stats/history", params={"range": "30d"}).status_code == 422
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_delayed_flows_outside_retention_are_pruned_safely() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)
    with Session(engine) as database:
        record_flow_statistics(
            database,
            [flow("192.168.1.20", "8.8.8.8", 100, now - timedelta(days=30))],
        )
        record_alert_statistics(
            database,
            [
                SecurityAlert(
                    timestamp=now,
                    severity="INFO",
                    risk_score=5,
                    alert_type="test_signal",
                    source_ip="192.168.1.20",
                    description="Test signal",
                    evidence={},
                    status="NEW",
                )
            ],
        )
        database.commit()
        assert database.scalar(
            select(func.count()).select_from(HistoricalMetricBucket)
        ) == len(RANGE_SPECS)
    engine.dispose()
