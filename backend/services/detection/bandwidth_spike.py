from datetime import datetime, timezone

from backend.models import NetworkFlow
from backend.services.hosts import is_local_network_address

from .base import AlertCandidate


class BandwidthSpikeRule:
    def __init__(self, outbound_bytes: int, inbound_bytes: int) -> None:
        self.outbound_bytes = outbound_bytes
        self.inbound_bytes = inbound_bytes

    def evaluate(
        self, flows: list[NetworkFlow], now: datetime | None = None
    ) -> list[AlertCandidate]:
        observed_at = now or datetime.now(timezone.utc)
        alerts: list[AlertCandidate] = []
        for flow in flows:
            source_local = is_local_network_address(flow.source_ip)
            destination_local = is_local_network_address(flow.destination_ip)
            direction: str | None = None
            threshold = 0
            if source_local and not destination_local:
                direction, threshold = "outbound", self.outbound_bytes
            elif destination_local and not source_local:
                direction, threshold = "inbound", self.inbound_bytes
            if direction is None or flow.bytes < threshold:
                continue
            alerts.append(
                AlertCandidate(
                    timestamp=observed_at,
                    severity="medium",
                    detection_name="bandwidth_spike",
                    source_ip=flow.source_ip,
                    destination_ip=flow.destination_ip,
                    description=(
                        f"Unusual traffic pattern: a completed {direction} transfer between "
                        f"{flow.source_ip} and {flow.destination_ip} contained {flow.bytes} "
                        "bytes. Large transfers may be expected and should be reviewed in context."
                    ),
                    evidence={
                        "direction": direction,
                        "bytes": flow.bytes,
                        "threshold_bytes": threshold,
                        "protocol": flow.protocol,
                        "packet_count": flow.packet_count,
                    },
                )
            )
        return alerts
