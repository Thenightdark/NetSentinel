"""Flow aggregation tests for packet shapes that are easy to mishandle."""

from datetime import timedelta

from collector.flows import FlowTracker


def test_identical_observations_are_counted_without_retaining_packets(
    synthetic_packet,
) -> None:
    packet = synthetic_packet()
    tracker = FlowTracker(inactivity_timeout_seconds=30)

    tracker.observe(packet)
    tracker.observe(packet)

    flow = tracker.snapshot()[0]
    assert flow.packets_sent == 2
    assert flow.bytes_sent == packet.packet_size * 2
    assert not hasattr(flow, "packets")


def test_ipv4_and_ipv6_endpoints_never_share_a_flow(synthetic_packet) -> None:
    tracker = FlowTracker(inactivity_timeout_seconds=30)
    tracker.observe(synthetic_packet())
    tracker.observe(
        synthetic_packet(
            source_ip="fd00::10",
            destination_ip="2001:db8::20",
        )
    )

    assert tracker.active_flow_count == 2
    assert {flow.source_ip for flow in tracker.snapshot()} == {
        "192.168.10.10",
        "fd00::10",
    }


def test_portless_packets_aggregate_by_addresses_and_protocol(synthetic_packet) -> None:
    tracker = FlowTracker(inactivity_timeout_seconds=30)
    tracker.observe(
        synthetic_packet(
            protocol="ICMP", source_port=None, destination_port=None, tcp_flags=None
        )
    )
    tracker.observe(
        synthetic_packet(
            timestamp=synthetic_packet().timestamp + timedelta(seconds=1),
            protocol="ICMP",
            source_port=None,
            destination_port=None,
            tcp_flags=None,
            packet_size=256,
        )
    )

    flow = tracker.snapshot()[0]
    assert flow.source_port is None
    assert flow.destination_port is None
    assert flow.packets_sent == 2
    assert flow.bytes_sent == 384
    assert ":None" not in flow.summary()


def test_out_of_order_packet_updates_first_seen_without_rewinding_last_seen(
    synthetic_packet,
) -> None:
    tracker = FlowTracker(inactivity_timeout_seconds=30)
    newest = synthetic_packet(timestamp=synthetic_packet().timestamp + timedelta(seconds=5))
    oldest = synthetic_packet(timestamp=synthetic_packet().timestamp - timedelta(seconds=5))

    tracker.observe(newest)
    tracker.observe(oldest)

    flow = tracker.snapshot()[0]
    assert flow.first_seen == oldest.timestamp
    assert flow.last_seen == newest.timestamp


def test_timeout_boundary_is_inclusive(synthetic_packet) -> None:
    tracker = FlowTracker(inactivity_timeout_seconds=10)
    packet = synthetic_packet()
    tracker.observe(packet)

    assert tracker.finalize_inactive(packet.timestamp + timedelta(seconds=9, milliseconds=999)) == []
    assert len(tracker.finalize_inactive(packet.timestamp + timedelta(seconds=10))) == 1

