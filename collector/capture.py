"""Passive packet capture and metadata normalization."""

from collections.abc import Callable
from datetime import datetime, timezone
import logging
import threading
from typing import Any

from scapy.all import ICMP, IP, IPv6, TCP, UDP, get_if_list, sniff

from .config import CollectorConfig
from .models import PacketMetadata
from .stats import CaptureStats

LOGGER = logging.getLogger(__name__)
PacketHandler = Callable[[PacketMetadata], None]


class CaptureUnavailable(RuntimeError):
    """Raised when the host cannot open a passive capture socket."""


def available_interfaces() -> list[str]:
    """Return interface identifiers recognized by Scapy."""
    return [str(interface) for interface in get_if_list()]


def normalize_packet(packet: Any, interface: str | None = None) -> PacketMetadata | None:
    """Convert an IPv4/IPv6 packet to metadata without retaining its payload."""
    try:
        if packet.haslayer(IP):
            network_layer = packet[IP]
            protocol_number = int(network_layer.proto)
        elif packet.haslayer(IPv6):
            network_layer = packet[IPv6]
            protocol_number = int(network_layer.nh)
        else:
            return None

        source_port: int | None = None
        destination_port: int | None = None
        tcp_flags: str | None = None

        if packet.haslayer(TCP):
            transport = packet[TCP]
            protocol = "TCP"
            source_port = int(transport.sport)
            destination_port = int(transport.dport)
            tcp_flags = str(transport.flags)
        elif packet.haslayer(UDP):
            transport = packet[UDP]
            protocol = "UDP"
            source_port = int(transport.sport)
            destination_port = int(transport.dport)
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = f"IP/{protocol_number}"

        captured_interface = interface or getattr(packet, "sniffed_on", None) or "unknown"
        timestamp_value = float(getattr(packet, "time", datetime.now(timezone.utc).timestamp()))

        return PacketMetadata(
            timestamp=datetime.fromtimestamp(timestamp_value, tz=timezone.utc),
            source_ip=str(network_layer.src),
            destination_ip=str(network_layer.dst),
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            packet_size=int(len(packet)),
            tcp_flags=tcp_flags,
            network_interface=str(captured_interface),
        )
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
        LOGGER.debug("Ignored malformed packet", exc_info=True)
        return None


class PassivePacketCapture:
    """Run a metadata-only Scapy capture on one selected interface."""

    def __init__(
        self,
        config: CollectorConfig,
        handler: PacketHandler,
        stats: CaptureStats | None = None,
    ) -> None:
        self.config = config
        self.handler = handler
        self.stats = stats or CaptureStats()
        self._stop_requested = threading.Event()

    def run(self) -> None:
        selected_interface = self.config.interface
        LOGGER.info("Starting passive capture on interface %s", selected_interface or "default")
        try:
            sniff(
                iface=selected_interface,
                prn=self._handle_packet,
                store=False,
                count=self.config.packet_limit,
                stop_filter=lambda _: self._stop_requested.is_set(),
            )
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            raise CaptureUnavailable(str(exc)) from exc

    def request_stop(self) -> None:
        self._stop_requested.set()

    def _handle_packet(self, packet: Any) -> None:
        try:
            metadata = normalize_packet(packet, self.config.interface)
            if metadata is None:
                self.stats.record_ignored()
                return
            self.stats.record(metadata)
            self.handler(metadata)
        except Exception:
            self.stats.record_malformed()
            LOGGER.warning("Malformed packet could not be processed", exc_info=True)

