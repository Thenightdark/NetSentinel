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

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["timestamp"] = self.timestamp.isoformat()
        return result

    def summary(self) -> str:
        source = _endpoint(self.source_ip, self.source_port)
        destination = _endpoint(self.destination_ip, self.destination_port)
        flags = f" flags={self.tcp_flags}" if self.tcp_flags else ""
        return (
            f"{self.timestamp.isoformat()} {self.network_interface} "
            f"{self.protocol} {source} -> {destination} "
            f"size={self.packet_size}B{flags}"
        )


def _endpoint(ip_address: str, port: int | None) -> str:
    if port is None:
        return ip_address
    separator = "]:" if ":" in ip_address else ":"
    prefix = "[" if ":" in ip_address else ""
    return f"{prefix}{ip_address}{separator}{port}"

