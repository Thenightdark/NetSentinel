from datetime import datetime, timedelta, timezone

from collector.flows import FlowTracker
from collector.models import PacketMetadata


def packet(
    timestamp: datetime,
    size: int,
    source_ip: str = "192.0.2.10",
    source_port: int = 51000,
    destination_ip: str = "198.51.100.20",
    destination_port: int = 443,
    protocol: str = "TCP",
) -> PacketMetadata:
    return PacketMetadata(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        packet_size=size,
        tcp_flags="A" if protocol == "TCP" else None,
        network_interface="eth0",
    )


def test_packets_with_same_five_tuple_are_aggregated() -> None:
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    tracker = FlowTracker(inactivity_timeout_seconds=30)

    tracker.observe(packet(started, 60))
    tracker.observe(packet(started + timedelta(seconds=2), 100))
    tracker.observe(packet(started + timedelta(seconds=5), 40))

    flows = tracker.snapshot()
    assert len(flows) == 1
    assert flows[0].first_seen == started
    assert flows[0].last_seen == started + timedelta(seconds=5)
    assert flows[0].packets_sent == 3
    assert flows[0].bytes_sent == 200
    assert flows[0].source_ip == "192.0.2.10"
    assert flows[0].destination_ip == "198.51.100.20"
    assert flows[0].source_port == 51000
    assert flows[0].destination_port == 443
    assert flows[0].protocol == "TCP"


def test_reverse_direction_is_a_separate_flow() -> None:
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    tracker = FlowTracker(inactivity_timeout_seconds=30)
    tracker.observe(packet(now, 60))
    tracker.observe(
        packet(
            now,
            70,
            source_ip="198.51.100.20",
            source_port=443,
            destination_ip="192.0.2.10",
            destination_port=51000,
        )
    )

    assert tracker.active_flow_count == 2


def test_only_inactive_flows_are_finalized() -> None:
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    finalized_by_callback = []
    tracker = FlowTracker(
        inactivity_timeout_seconds=10,
        on_flow_finalized=finalized_by_callback.append,
    )
    tracker.observe(packet(started, 60, source_port=50001))
    tracker.observe(packet(started + timedelta(seconds=7), 80, source_port=50002))

    finalized = tracker.finalize_inactive(started + timedelta(seconds=11))

    assert len(finalized) == 1
    assert finalized[0].source_port == 50001
    assert finalized_by_callback == finalized
    assert tracker.active_flow_count == 1


def test_stop_flushes_remaining_flows() -> None:
    tracker = FlowTracker(inactivity_timeout_seconds=30)
    tracker.observe(packet(datetime.now(timezone.utc), 128))

    finalized = tracker.stop(finalize_remaining=True)

    assert len(finalized) == 1
    assert finalized[0].packets_sent == 1
    assert tracker.active_flow_count == 0

