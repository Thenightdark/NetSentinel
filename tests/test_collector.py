from datetime import datetime, timezone

from scapy.all import Ether, IP, IPv6, Raw, TCP, UDP

import pytest

from collector import capture as capture_module
from collector.capture import CaptureUnavailable, PassivePacketCapture, normalize_packet
from collector.config import CollectorConfig
from collector.main import main
from collector.models import PacketMetadata
from collector.service import collect_interface_counters
from collector.stats import CaptureStats


def test_collector_returns_passive_interface_counters() -> None:
    snapshots = collect_interface_counters()

    assert isinstance(snapshots, list)
    for snapshot in snapshots:
        assert snapshot.bytes_sent >= 0
        assert snapshot.bytes_received >= 0
        assert snapshot.interface


def test_normalizes_ipv4_tcp_metadata_without_payload() -> None:
    packet = IP(src="192.0.2.1", dst="198.51.100.2") / TCP(
        sport=49152, dport=443, flags="SA"
    ) / Raw(b"content that must not be retained")
    packet.time = 1_700_000_000.0

    metadata = normalize_packet(packet, "Ethernet")

    assert metadata is not None
    assert metadata.source_ip == "192.0.2.1"
    assert metadata.destination_ip == "198.51.100.2"
    assert metadata.source_port == 49152
    assert metadata.destination_port == 443
    assert metadata.protocol == "TCP"
    assert metadata.tcp_flags == "SA"
    assert metadata.network_interface == "Ethernet"
    assert metadata.packet_size == len(packet)
    assert "content" not in metadata.to_dict()
    assert set(metadata.to_dict()) == {
        "timestamp", "source_ip", "destination_ip", "source_port",
        "destination_port", "protocol", "packet_size", "tcp_flags",
        "network_interface",
    }


def test_normalizes_ipv6_udp_metadata() -> None:
    packet = IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=53000, dport=53)

    metadata = normalize_packet(packet, "eth0")

    assert metadata is not None
    assert metadata.protocol == "UDP"
    assert metadata.source_port == 53000
    assert metadata.destination_port == 53
    assert metadata.tcp_flags is None


def test_ignores_non_ip_packet() -> None:
    assert normalize_packet(Ether(), "eth0") is None


def test_capture_stats_track_only_normalized_values() -> None:
    stats = CaptureStats()
    metadata = PacketMetadata(
        datetime.now(timezone.utc), "192.0.2.1", "198.51.100.2",
        12345, 443, "TCP", 60, "S", "eth0",
    )

    stats.record(metadata)
    stats.record_ignored()
    stats.record_malformed()

    assert stats.packets_seen == 1
    assert stats.bytes_seen == 60
    assert stats.protocols["TCP"] == 1
    assert "malformed=1" in stats.summary()


def test_demo_mode_runs_without_capture(capsys) -> None:
    assert main(["--demo"]) == 0
    output = capsys.readouterr().out
    assert "demo0" in output
    assert "TCP" in output


def test_malformed_packet_does_not_crash_capture() -> None:
    class MalformedPacket:
        def haslayer(self, _layer: object) -> bool:
            raise RuntimeError("invalid packet")

    stats = CaptureStats()
    collector = PassivePacketCapture(CollectorConfig(), lambda _: None, stats)

    collector._handle_packet(MalformedPacket())

    assert stats.malformed_packets == 1


def test_capture_errors_become_clear_unavailable_error(monkeypatch) -> None:
    def unavailable_sniff(**_kwargs: object) -> None:
        raise PermissionError("capture permission denied")

    monkeypatch.setattr(capture_module, "sniff", unavailable_sniff)
    collector = PassivePacketCapture(CollectorConfig(), lambda _: None)

    with pytest.raises(CaptureUnavailable, match="permission denied"):
        collector.run()
