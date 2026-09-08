"""Legacy interface-counter helper retained for host-level telemetry."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone

import psutil


@dataclass(frozen=True)
class InterfaceSnapshot:
    interface: str
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    observed_at: str


def collect_interface_counters() -> list[InterfaceSnapshot]:
    """Read cumulative OS counters without opening or modifying network traffic."""
    observed_at = datetime.now(timezone.utc).isoformat()
    return [
        InterfaceSnapshot(
            interface=name,
            bytes_sent=counters.bytes_sent,
            bytes_received=counters.bytes_recv,
            packets_sent=counters.packets_sent,
            packets_received=counters.packets_recv,
            observed_at=observed_at,
        )
        for name, counters in psutil.net_io_counters(pernic=True).items()
    ]


if __name__ == "__main__":
    import json

    print(json.dumps([asdict(item) for item in collect_interface_counters()], indent=2))
