from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models import NetworkFlow

from .base import AlertCandidate


class PortScanRule:
    def __init__(self, unique_port_threshold: int, window_seconds: float) -> None:
        self.unique_port_threshold = unique_port_threshold
        self.window_seconds = window_seconds

    def evaluate(
        self, database: Session, flows: list[NetworkFlow], now: datetime | None = None
    ) -> list[AlertCandidate]:
        observed_at = now or datetime.now(timezone.utc)
        cutoff = observed_at - timedelta(seconds=self.window_seconds)
        alerts: list[AlertCandidate] = []
        for source_ip in {flow.source_ip for flow in flows}:
            rows = database.execute(
                select(NetworkFlow.destination_port, NetworkFlow.destination_ip).where(
                    NetworkFlow.source_ip == source_ip,
                    NetworkFlow.destination_port.is_not(None),
                    NetworkFlow.last_seen >= cutoff,
                )
            ).all()
            ports = sorted({int(port) for port, _ in rows if port is not None})
            if len(ports) < self.unique_port_threshold:
                continue
            destinations = sorted({destination for _, destination in rows})
            alerts.append(
                AlertCandidate(
                    timestamp=observed_at,
                    detection_name="possible_port_scan",
                    source_ip=source_ip,
                    destination_ip=destinations[0] if len(destinations) == 1 else None,
                    description=(
                        f"Possible port scan: {source_ip} contacted {len(ports)} distinct "
                        f"destination ports within {self.window_seconds:g} seconds. This may "
                        "be legitimate discovery traffic and should be reviewed in context."
                    ),
                    evidence={
                        "window_seconds": self.window_seconds,
                        "unique_destination_ports": len(ports),
                        "port_threshold": self.unique_port_threshold,
                        "destination_count": len(destinations),
                        "sample_ports": ports[:20],
                    },
                )
            )
        return alerts
