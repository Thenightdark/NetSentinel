from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.database.base import Base
from backend.models import NetworkFlow
from backend.services.detection import (
    BandwidthSpikeRule,
    ConnectionSpikeRule,
    NewHostRule,
    PortScanRule,
    UnusualDestinationPortRule,
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


def make_flow(
    *,
    source_ip: str = "192.168.1.10",
    destination_ip: str = "198.51.100.20",
    destination_port: int = 443,
    size: int = 1_000,
    seen_at: datetime | None = None,
) -> NetworkFlow:
    timestamp = seen_at or datetime.now(timezone.utc)
    return NetworkFlow(
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=51_000,
        destination_port=destination_port,
        protocol="TCP",
        bytes=size,
        packet_count=4,
        first_seen=timestamp - timedelta(seconds=1),
        last_seen=timestamp,
    )


def test_possible_port_scan_uses_distinct_ports_and_evidence(database: Session) -> None:
    now = datetime.now(timezone.utc)
    flows = [make_flow(destination_port=port, seen_at=now) for port in (80, 443, 8080)]
    database.add_all(flows)
    database.commit()

    alerts = PortScanRule(unique_port_threshold=3, window_seconds=30).evaluate(
        database, flows, now
    )

    assert len(alerts) == 1
    assert alerts[0].detection_name == "possible_port_scan"
    assert "Possible port scan" in alerts[0].description
    assert alerts[0].evidence["unique_destination_ports"] == 3
    assert alerts[0].evidence["port_threshold"] == 3


def test_connection_spike_compares_current_window_with_baseline(
    database: Session,
) -> None:
    now = datetime.now(timezone.utc)
    historical = [
        make_flow(seen_at=now - timedelta(minutes=2, seconds=index))
        for index in range(2)
    ]
    recent = [
        make_flow(destination_port=8_000 + index, seen_at=now - timedelta(seconds=index))
        for index in range(6)
    ]
    database.add_all([*historical, *recent])
    database.commit()

    alerts = ConnectionSpikeRule(
        window_seconds=60,
        baseline_seconds=300,
        multiplier=3,
        minimum_connections=5,
    ).evaluate(database, recent, now)

    assert len(alerts) == 1
    assert alerts[0].detection_name == "connection_spike"
    assert "Unusual traffic pattern" in alerts[0].description
    assert alerts[0].evidence["connections_in_window"] == 6
    assert alerts[0].evidence["multiplier"] == 3


def test_unusual_destination_port_only_uses_configured_ports() -> None:
    rule = UnusualDestinationPortRule([23, 3389])
    flagged = make_flow(destination_port=3389)
    ordinary = make_flow(destination_port=443)

    alerts = rule.evaluate([flagged, ordinary])

    assert len(alerts) == 1
    assert alerts[0].detection_name == "unusual_destination_port"
    assert "Potentially suspicious connection activity" in alerts[0].description
    assert alerts[0].evidence["destination_port"] == 3389


def test_bandwidth_spike_distinguishes_outbound_and_inbound_transfers() -> None:
    rule = BandwidthSpikeRule(outbound_bytes=2_000, inbound_bytes=3_000)
    outbound = make_flow(
        source_ip="192.168.1.10", destination_ip="8.8.8.8", size=2_500
    )
    inbound = make_flow(
        source_ip="8.8.8.8", destination_ip="192.168.1.10", size=3_500
    )

    alerts = rule.evaluate([outbound, inbound])

    assert len(alerts) == 2
    assert {alert.evidence["direction"] for alert in alerts} == {"inbound", "outbound"}
    assert all(alert.detection_name == "bandwidth_spike" for alert in alerts)
    assert all("should be reviewed in context" in alert.description for alert in alerts)


def test_new_host_is_informational_and_passive() -> None:
    alerts = NewHostRule().evaluate({"192.168.1.42"})

    assert len(alerts) == 1
    assert alerts[0].severity == "info"
    assert alerts[0].detection_name == "new_host"
    assert "does not imply malicious activity" in alerts[0].description
    assert alerts[0].evidence == {
        "host_ip": "192.168.1.42",
        "discovery_method": "passive_flow_observation",
    }
