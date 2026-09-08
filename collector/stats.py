"""In-memory collector statistics; no packet content is retained."""

from collections import Counter
from dataclasses import dataclass, field

from .models import PacketMetadata


@dataclass(slots=True)
class CaptureStats:
    packets_seen: int = 0
    bytes_seen: int = 0
    ignored_packets: int = 0
    malformed_packets: int = 0
    protocols: Counter[str] = field(default_factory=Counter)

    def record(self, metadata: PacketMetadata) -> None:
        self.packets_seen += 1
        self.bytes_seen += metadata.packet_size
        self.protocols[metadata.protocol] += 1

    def record_ignored(self) -> None:
        self.ignored_packets += 1

    def record_malformed(self) -> None:
        self.malformed_packets += 1

    def summary(self) -> str:
        protocol_summary = ", ".join(
            f"{protocol}={count}" for protocol, count in self.protocols.most_common()
        ) or "none"
        return (
            f"captured={self.packets_seen} bytes={self.bytes_seen} "
            f"ignored={self.ignored_packets} malformed={self.malformed_packets} "
            f"protocols=[{protocol_summary}]"
        )

