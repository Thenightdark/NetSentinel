from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.models import NetworkFlow
from backend.services.hosts import is_local_network_address

from .base import AlertCandidate


class BandwidthSpikeRule:
    def __init__(self, threshold_bytes: int, window_seconds: float) -> None:
        self.threshold_bytes = threshold_bytes
        self.window_seconds = window_seconds

    def evaluate(
        self,
        database: Session,
        flows: list[NetworkFlow],
        now: datetime | None = None,
    ) -> list[AlertCandidate]:
        observed_at = now or datetime.now(timezone.utc)
        cutoff = observed_at - timedelta(seconds=self.window_seconds)
        agent_id = flows[0].agent_id
        candidates: set[tuple[str, str]] = set()
        for flow in flows:
            source_local = is_local_network_address(flow.source_ip)
            destination_local = is_local_network_address(flow.destination_ip)
            if source_local and not destination_local:
                candidates.add((flow.source_ip, "outbound"))
            elif destination_local and not source_local:
                candidates.add((flow.destination_ip, "inbound"))

        alerts: list[AlertCandidate] = []
        for host_ip, direction in candidates:
            endpoint_filter = (
                NetworkFlow.source_ip == host_ip
                if direction == "outbound"
                else NetworkFlow.destination_ip == host_ip
            )
            total_bytes = int(
                database.scalar(
                    select(func.sum(NetworkFlow.bytes)).where(
                        NetworkFlow.agent_id == agent_id,
                        endpoint_filter,
                        NetworkFlow.last_seen >= cutoff,
                    )
                )
                or 0
            )
            if total_bytes < self.threshold_bytes:
                continue
            alerts.append(
                AlertCandidate(
                    timestamp=observed_at,
                    detection_name="bandwidth_spike",
                    source_ip=host_ip,
                    destination_ip=None,
                    description=(
                        f"Unusual traffic pattern: {host_ip} transferred {total_bytes} bytes "
                        f"{direction} within {self.window_seconds:g} seconds. Large transfers "
                        "may be expected and should be reviewed in context."
                    ),
                    evidence={
                        "direction": direction,
                        "bytes": total_bytes,
                        "threshold_bytes": self.threshold_bytes,
                        "window_seconds": self.window_seconds,
                    },
                )
            )
        return alerts
