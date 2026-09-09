"""Passive packet capture and metadata normalization."""

from collections.abc import Callable
from datetime import datetime, timezone
import logging
import threading
from typing import Any

from scapy.all import DNS, DNSQR, ICMP, IP, IPv6, TCP, UDP, get_if_list, sniff

from .config import CollectorConfig
from .models import DNSMetadata, PacketMetadata
from .stats import CaptureStats

LOGGER = logging.getLogger(__name__)
PacketHandler = Callable[[PacketMetadata], None]
DNSHandler = Callable[[DNSMetadata], None]

DNS_QUERY_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY",
}
DNS_RESPONSE_CODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED",
}


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


def normalize_dns_metadata(
    packet: Any, interface: str | None = None
) -> DNSMetadata | None:
    """Extract only first-question DNS metadata from an IPv4/IPv6 DNS message."""
    try:
        if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
            return None
        if packet.haslayer(IP):
            network_layer = packet[IP]
        elif packet.haslayer(IPv6):
            network_layer = packet[IPv6]
        else:
            return None

        dns = packet[DNS]
        question = packet[DNSQR]
        raw_name = question.qname
        if isinstance(raw_name, bytes):
            domain = raw_name.decode("ascii", errors="replace")
        else:
            domain = str(raw_name)
        domain = domain.rstrip(".").lower()
        if not domain or len(domain) > 253:
            return None

        is_response = bool(int(dns.qr))
        query_type_number = int(question.qtype)
        response_code = int(dns.rcode)
        captured_interface = interface or getattr(packet, "sniffed_on", None) or "unknown"
        timestamp_value = float(getattr(packet, "time", datetime.now(timezone.utc).timestamp()))
        return DNSMetadata(
            requesting_host=str(network_layer.dst if is_response else network_layer.src),
            queried_domain=domain,
            timestamp=datetime.fromtimestamp(timestamp_value, tz=timezone.utc),
            query_type=DNS_QUERY_TYPES.get(query_type_number, f"TYPE{query_type_number}"),
            response_status=(
                DNS_RESPONSE_CODES.get(response_code, f"RCODE{response_code}")
                if is_response
                else None
            ),
            is_response=is_response,
            network_interface=str(captured_interface),
        )
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, UnicodeError):
        LOGGER.debug("Ignored malformed DNS metadata", exc_info=True)
        return None


class PassivePacketCapture:
    """Run a metadata-only Scapy capture on one selected interface."""

    def __init__(
        self,
        config: CollectorConfig,
        handler: PacketHandler,
        stats: CaptureStats | None = None,
        dns_handler: DNSHandler | None = None,
    ) -> None:
        self.config = config
        self.handler = handler
        self.dns_handler = dns_handler
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
            if self.dns_handler is not None:
                dns_metadata = normalize_dns_metadata(packet, self.config.interface)
                if dns_metadata is not None:
                    self.dns_handler(dns_metadata)
        except Exception:
            self.stats.record_malformed()
            LOGGER.warning("Malformed packet could not be processed", exc_info=True)
