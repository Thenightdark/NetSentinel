"""Normalized collector data models. Packet payloads are intentionally absent."""

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class PacketMetadata:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    protocol: str
    packet_size: int
    tcp_flags: str | None
    network_interface: str
    process_id: int | None = None
    process_name: str | None = None
    executable_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        for optional_field in ("process_id", "process_name", "executable_name"):
            if result[optional_field] is None:
                result.pop(optional_field)
        result["timestamp"] = self.timestamp.isoformat()
        return result

    def summary(self) -> str:
        source = _endpoint(self.source_ip, self.source_port)
        destination = _endpoint(self.destination_ip, self.destination_port)
        flags = f" flags={self.tcp_flags}" if self.tcp_flags else ""
        process = (
            f" process={self.process_name or self.executable_name}({self.process_id})"
            if self.process_id is not None
            else ""
        )
        return (
            f"{self.timestamp.isoformat()} {self.network_interface} "
            f"{self.protocol} {source} -> {destination} "
            f"size={self.packet_size}B{flags}{process}"
        )


@dataclass(frozen=True, slots=True)
class DNSMetadata:
    """Narrow DNS query/response metadata; no answer data or packet body is retained."""

    requesting_host: str
    queried_domain: str
    timestamp: datetime
    query_type: str
    response_status: str | None
    is_response: bool
    network_interface: str

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["timestamp"] = self.timestamp.isoformat()
        return result

    def summary(self) -> str:
        status = f" status={self.response_status}" if self.response_status else ""
        direction = "response" if self.is_response else "query"
        return (
            f"{self.timestamp.isoformat()} {self.network_interface} DNS {direction} "
            f"client={self.requesting_host} {self.query_type} {self.queried_domain}{status}"
        )


def _endpoint(ip_address: str, port: int | None) -> str:
    if port is None:
        return ip_address
    separator = "]:" if ":" in ip_address else ":"
    prefix = "[" if ":" in ip_address else ""
    return f"{prefix}{ip_address}{separator}{port}"
