from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.database.base import Base
from backend.models import NetworkFlow, SecurityAlert
from backend.services.detection import (
    AlertCandidate,
    BandwidthSpikeRule,
    ConnectionSpikeRule,
    NewHostRule,
    PortScanRule,
    UnusualDestinationPortRule,
    score_candidate,
    severity_for_score,
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


def test_bandwidth_spike_aggregates_outbound_and_inbound_window(
    database: Session,
) -> None:
    rule = BandwidthSpikeRule(threshold_bytes=2_000, window_seconds=300)
    outbound = make_flow(
        source_ip="192.168.1.10", destination_ip="8.8.8.8", size=2_500
    )
    inbound = make_flow(
        source_ip="8.8.8.8", destination_ip="192.168.1.20", size=3_500
    )
    database.add_all([outbound, inbound])
    database.commit()

    alerts = rule.evaluate(database, [outbound, inbound])

    assert len(alerts) == 2
    assert {alert.evidence["direction"] for alert in alerts} == {"inbound", "outbound"}
    assert all(alert.detection_name == "bandwidth_spike" for alert in alerts)
    assert all("should be reviewed in context" in alert.description for alert in alerts)
    assert all(alert.evidence["window_seconds"] == 300 for alert in alerts)


def test_new_host_is_informational_and_passive() -> None:
    alerts = NewHostRule().evaluate({"192.168.1.42"})

    assert len(alerts) == 1
    assert alerts[0].detection_name == "new_host"
    assert "does not imply malicious activity" in alerts[0].description
    assert alerts[0].evidence == {
        "host_ip": "192.168.1.42",
        "discovery_method": "passive_flow_observation",
    }


@pytest.mark.parametrize(
    ("score", "severity"),
    [(0, "INFO"), (20, "LOW"), (40, "MEDIUM"), (60, "HIGH"), (80, "CRITICAL"), (100, "CRITICAL")],
)
def test_severity_is_derived_from_documented_score_bands(
    score: int, severity: str
) -> None:
    assert severity_for_score(score) == severity


def test_risk_score_has_an_auditable_factor_breakdown(database: Session) -> None:
    now = datetime.now(timezone.utc)
    database.add_all(
        [
            SecurityAlert(
                timestamp=now - timedelta(days=index + 1),
                severity="LOW",
                risk_score=25,
                alert_type="historical",
                source_ip="192.168.1.10",
                description="Historical alert",
                evidence={},
                status="RESOLVED",
            )
            for index in range(2)
        ]
    )
    database.commit()
    scan = AlertCandidate(
        timestamp=now,
        detection_name="possible_port_scan",
        source_ip="192.168.1.10",
        destination_ip=None,
        description="Possible port scan",
        evidence={"unique_destination_ports": 20, "port_threshold": 20},
    )
    connection = AlertCandidate(
        timestamp=now,
        detection_name="connection_spike",
        source_ip="192.168.1.10",
        destination_ip=None,
        description="Connection spike",
        evidence={"connections_in_window": 30, "minimum_connections": 30},
    )
    bandwidth = AlertCandidate(
        timestamp=now,
        detection_name="bandwidth_spike",
        source_ip="192.168.1.10",
        destination_ip="8.8.8.8",
        description="Bandwidth spike",
        evidence={"bytes": 50_000_000, "threshold_bytes": 50_000_000},
    )

    assessment = score_candidate(database, scan, [scan, connection, bandwidth])

    assert assessment.score == 75
    assert assessment.severity == "HIGH"
    assert assessment.breakdown == {
        "methodology_version": "1.1",
        "rule_base": 35,
        "rule_correlation": 12,
        "connection_frequency": 8,
        "unique_ports": 8,
        "bandwidth_volume": 8,
        "dns_query_rate": 0,
        "domain_length": 0,
        "dns_lookup_failures": 0,
        "traffic_direction": 0,
        "previous_alert_history": 4,
        "distinct_rules_for_source": 3,
        "previous_alert_count": 2,
        "total": 75,
    }


def test_port_scan_does_not_trigger_one_port_below_threshold(
    database: Session,
) -> None:
    now = datetime.now(timezone.utc)
    flows = [make_flow(destination_port=port, seen_at=now) for port in (80, 443)]
    database.add_all(flows)
    database.commit()

    assert PortScanRule(3, 30).evaluate(database, flows, now) == []


def test_port_scan_ignores_missing_ports_and_other_agents(database: Session) -> None:
    now = datetime.now(timezone.utc)
    current_agent = [
        make_flow(destination_port=80, seen_at=now),
        make_flow(destination_port=None, seen_at=now),
    ]
    for flow in current_agent:
        flow.agent_id = "agent-a"
    other_agent = make_flow(destination_port=443, seen_at=now)
    other_agent.agent_id = "agent-b"
    database.add_all([*current_agent, other_agent])
    database.commit()

    assert PortScanRule(2, 30).evaluate(database, current_agent, now) == []


def test_connection_spike_boundary_is_inclusive(database: Session) -> None:
    now = datetime.now(timezone.utc)
    recent = [
        make_flow(destination_port=10_000 + index, seen_at=now)
        for index in range(5)
    ]
    database.add_all(recent)
    database.commit()

    rule = ConnectionSpikeRule(
        window_seconds=60,
        baseline_seconds=300,
        multiplier=3,
        minimum_connections=5,
    )
    alerts = rule.evaluate(database, recent, now)

    assert len(alerts) == 1
    assert alerts[0].evidence["connections_in_window"] == 5


def test_connection_spike_does_not_trigger_below_minimum(database: Session) -> None:
    now = datetime.now(timezone.utc)
    recent = [make_flow(destination_port=20_000 + index, seen_at=now) for index in range(4)]
    database.add_all(recent)
    database.commit()

    assert ConnectionSpikeRule(60, 300, 3, 5).evaluate(database, recent, now) == []


def test_bandwidth_boundary_is_inclusive_and_large_values_are_safe(
    database: Session,
) -> None:
    threshold = 5 * 1024**4
    flow = make_flow(
        source_ip="192.168.1.10",
        destination_ip="2001:4860:4860::8888",
        size=threshold,
    )
    database.add(flow)
    database.commit()

    alerts = BandwidthSpikeRule(threshold, 300).evaluate(database, [flow])

    assert len(alerts) == 1
    assert alerts[0].evidence["bytes"] == threshold


def test_bandwidth_does_not_trigger_one_byte_below_threshold(
    database: Session,
) -> None:
    flow = make_flow(size=999)
    database.add(flow)
    database.commit()

    assert BandwidthSpikeRule(1_000, 300).evaluate(database, [flow]) == []
