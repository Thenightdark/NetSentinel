from datetime import datetime, timezone

from backend.models import NetworkFlow

from .base import AlertCandidate


class UnusualDestinationPortRule:
    def __init__(self, ports: list[int]) -> None:
        self.ports = set(ports)

    def evaluate(
        self, flows: list[NetworkFlow], now: datetime | None = None
    ) -> list[AlertCandidate]:
        observed_at = now or datetime.now(timezone.utc)
        alerts: list[AlertCandidate] = []
        seen: set[tuple[str, str, int]] = set()
        for flow in flows:
            port = flow.destination_port
            if port is None or port not in self.ports:
                continue
            key = (flow.source_ip, flow.destination_ip, port)
            if key in seen:
                continue
            seen.add(key)
            alerts.append(
                AlertCandidate(
                    timestamp=observed_at,
                    severity="medium",
                    detection_name="unusual_destination_port",
                    source_ip=flow.source_ip,
                    destination_ip=flow.destination_ip,
                    description=(
                        f"Potentially suspicious connection activity: {flow.source_ip} "
                        f"contacted configured uncommon or high-risk destination port {port} "
                        f"on {flow.destination_ip}. The service may be authorized."
                    ),
                    evidence={
                        "destination_port": port,
                        "protocol": flow.protocol,
                        "bytes": flow.bytes,
                        "packet_count": flow.packet_count,
                    },
                )
            )
        return alerts
