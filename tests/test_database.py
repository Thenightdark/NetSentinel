"""Database behavior that protects counters and collector idempotency."""

from datetime import datetime, timezone
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.database.base import Base
from backend.models import Host, IngestBatch, NetworkFlow
from backend.schemas import FlowIngestRequest
from backend.services.ingestion import ingest_flow_batch


def _database() -> tuple[Session, object]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return Session(engine, expire_on_commit=False), engine


def _request(batch_id: str, byte_count: int) -> FlowIngestRequest:
    now = datetime.now(timezone.utc)
    return FlowIngestRequest.model_validate(
        {
            "batch_id": batch_id,
            "flows": [
                {
                    "source_ip": "fd00::10",
                    "destination_ip": "2001:db8::20",
                    "source_port": None,
                    "destination_port": None,
                    "protocol": "icmpv6",
                    "bytes": byte_count,
                    "packet_count": 1,
                    "first_seen": now.isoformat(),
                    "last_seen": now.isoformat(),
                }
            ],
        }
    )


def test_large_64_bit_traffic_values_round_trip_without_overflow() -> None:
    database, engine = _database()
    five_terabytes = 5 * 1024**4
    try:
        accepted, duplicate, _, _ = ingest_flow_batch(
            database,
            _request("40000000-0000-4000-8000-000000000001", five_terabytes),
            "agent-a",
        )
        stored = database.scalar(select(NetworkFlow))
        host = database.scalar(select(Host).where(Host.ip_address == "fd00::10"))

        assert (accepted, duplicate) == (1, False)
        assert stored is not None and stored.bytes == five_terabytes
        assert host is not None and host.total_bytes == five_terabytes
    finally:
        database.close()
        engine.dispose()


def test_duplicate_batch_is_atomic_and_does_not_double_count_hosts() -> None:
    database, engine = _database()
    request = _request("40000000-0000-4000-8000-000000000002", 4096)
    try:
        assert ingest_flow_batch(database, request, "agent-a")[:2] == (1, False)
        assert ingest_flow_batch(database, request, "agent-a")[:2] == (1, True)

        assert database.scalar(select(func.count()).select_from(NetworkFlow)) == 1
        assert database.scalar(select(func.count()).select_from(IngestBatch)) == 1
        host = database.scalar(select(Host).where(Host.ip_address == "fd00::10"))
        assert host is not None
        assert host.total_connections == 1
        assert host.total_bytes == 4096
    finally:
        database.close()
        engine.dispose()
