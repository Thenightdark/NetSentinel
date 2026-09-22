from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.config import get_settings
from backend.api.dependencies import require_dashboard_user
from backend.database.base import Base
from backend.database.session import get_db
from backend.main import app
from backend.models import CollectorAgent, DNSObservation
from backend.services.agents import hash_agent_key
from backend.services.detection import (
    HighDNSQueryRateRule,
    LongDomainNameRule,
    RepeatedFailedDNSLookupRule,
)


@pytest.fixture
def database() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        yield session
    engine.dispose()


@pytest.fixture
def client(database: Session, monkeypatch) -> TestClient:
    def override_database():
        yield database

    monkeypatch.setattr(
        get_settings(), "ingest_api_key", SecretStr("dns-test-key")
    )
    app.dependency_overrides[get_db] = override_database
    app.dependency_overrides[require_dashboard_user] = lambda: object()
    now = datetime.now(timezone.utc)
    database.add(CollectorAgent(agent_id="22222222-2222-4222-8222-222222222222", hostname="dns-agent", operating_system="Test OS", ip_address="192.168.1.3", version="0.4.0", first_seen=now, last_seen=now, status="ONLINE", api_key_hash=hash_agent_key("dns-test-key")))
    database.commit()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def observation(
    *,
    client: str = "192.168.1.20",
    domain: str = "example.com",
    timestamp: datetime | None = None,
    status: str | None = None,
    is_response: bool = False,
) -> DNSObservation:
    return DNSObservation(
        requesting_host=client,
        queried_domain=domain,
        timestamp=timestamp or datetime.now(timezone.utc),
        query_type="A",
        response_status=status,
        is_response=is_response,
    )


def test_dns_api_ingests_lists_and_aggregates_only_queries(client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    payload = {
        "batch_id": str(uuid4()),
        "observations": [
            {
                "requesting_host": "192.168.1.20",
                "queried_domain": "Example.COM.",
                "timestamp": now.isoformat(),
                "query_type": "a",
                "response_status": None,
                "is_response": False,
            },
            {
                "requesting_host": "192.168.1.21",
                "queried_domain": "example.com",
                "timestamp": now.isoformat(),
                "query_type": "AAAA",
                "response_status": None,
                "is_response": False,
            },
            {
                "requesting_host": "192.168.1.20",
                "queried_domain": "example.com",
                "timestamp": now.isoformat(),
                "query_type": "A",
                "response_status": "NOERROR",
                "is_response": True,
            },
        ],
    }

    ingested = client.post(
        "/api/ingest/dns", json=payload, headers={"X-Agent-ID": "22222222-2222-4222-8222-222222222222", "X-API-Key": "dns-test-key"}
    )
    listed = client.get("/api/dns", params={"domain": "example"})
    top = client.get("/api/dns/top-domains", params={"minutes": 60})

    assert ingested.status_code == 202
    assert ingested.json() == {"accepted": 3, "duplicate": False}
    assert listed.status_code == 200
    assert listed.json()["total"] == 3
    assert listed.json()["items"][0]["queried_domain"] == "example.com"
    assert top.json() == [
        {"domain": "example.com", "query_count": 2, "unique_clients": 2}
    ]


def test_dns_ingestion_requires_api_key(client: TestClient) -> None:
    response = client.post(
        "/api/ingest/dns",
        json={"batch_id": str(uuid4()), "observations": []},
    )
    assert response.status_code == 401


def test_high_dns_query_rate_rule_uses_configured_window(database: Session) -> None:
    now = datetime.now(timezone.utc)
    recent = [
        observation(timestamp=now - timedelta(seconds=index)) for index in range(3)
    ]
    database.add_all(recent)
    database.commit()

    alerts = HighDNSQueryRateRule(query_threshold=3, window_seconds=30).evaluate(
        database, recent, now
    )

    assert len(alerts) == 1
    assert alerts[0].detection_name == "high_dns_query_rate"
    assert alerts[0].evidence["dns_queries_in_window"] == 3
    assert "can be legitimate" in alerts[0].description


def test_long_domain_rule_treats_length_as_a_signal() -> None:
    long_domain = f"{'a' * 45}.example.com"
    item = observation(domain=long_domain)

    alerts = LongDomainNameRule(length_threshold=40).evaluate([item])

    assert len(alerts) == 1
    assert alerts[0].detection_name == "unusually_long_domain"
    assert alerts[0].evidence["domain_length"] == len(long_domain)
    assert "not proof" in alerts[0].description


def test_repeated_failed_dns_rule_counts_response_metadata(database: Session) -> None:
    now = datetime.now(timezone.utc)
    failures = [
        observation(
            domain="missing.example",
            timestamp=now - timedelta(seconds=index),
            status="NXDOMAIN",
            is_response=True,
        )
        for index in range(3)
    ]
    database.add_all(failures)
    database.commit()

    alerts = RepeatedFailedDNSLookupRule(
        failure_threshold=3, window_seconds=60
    ).evaluate(database, failures, now)

    assert len(alerts) == 1
    assert alerts[0].detection_name == "repeated_failed_dns_lookups"
    assert alerts[0].evidence["failed_lookups"] == 3
    assert "Configuration errors" in alerts[0].description
