from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.models import NetworkFlow

from .base import AlertCandidate


class ConnectionSpikeRule:
    def __init__(
        self,
        window_seconds: float,
        baseline_seconds: float,
        multiplier: float,
        minimum_connections: int,
    ) -> None:
        self.window_seconds = window_seconds
        self.baseline_seconds = baseline_seconds
        self.multiplier = multiplier
        self.minimum_connections = minimum_connections

    def evaluate(
        self, database: Session, flows: list[NetworkFlow], now: datetime | None = None
    ) -> list[AlertCandidate]:
        observed_at = now or datetime.now(timezone.utc)
        recent_cutoff = observed_at - timedelta(seconds=self.window_seconds)
        baseline_cutoff = recent_cutoff - timedelta(seconds=self.baseline_seconds)
        windows_in_baseline = self.baseline_seconds / self.window_seconds
        agent_id = flows[0].agent_id
        alerts: list[AlertCandidate] = []
        for source_ip in {flow.source_ip for flow in flows}:
            recent_count = int(
                database.scalar(
                    select(func.count()).select_from(NetworkFlow).where(
                        NetworkFlow.source_ip == source_ip,
                        NetworkFlow.agent_id == agent_id,
                        NetworkFlow.last_seen >= recent_cutoff,
                    )
                )
                or 0
            )
            historical_count = int(
                database.scalar(
                    select(func.count()).select_from(NetworkFlow).where(
                        NetworkFlow.source_ip == source_ip,
                        NetworkFlow.agent_id == agent_id,
                        NetworkFlow.last_seen >= baseline_cutoff,
                        NetworkFlow.last_seen < recent_cutoff,
                    )
                )
                or 0
            )
            normal_per_window = historical_count / windows_in_baseline
            trigger_level = max(1.0, normal_per_window) * self.multiplier
            if recent_count < self.minimum_connections or recent_count < trigger_level:
                continue
            alerts.append(
                AlertCandidate(
                    timestamp=observed_at,
                    detection_name="connection_spike",
                    source_ip=source_ip,
                    destination_ip=None,
                    description=(
                        f"Unusual traffic pattern: {source_ip} created {recent_count} "
                        f"connections within {self.window_seconds:g} seconds, significantly "
                        "above its recent baseline."
                    ),
                    evidence={
                        "window_seconds": self.window_seconds,
                        "connections_in_window": recent_count,
                        "minimum_connections": self.minimum_connections,
                        "baseline_seconds": self.baseline_seconds,
                        "baseline_connections_per_window": round(normal_per_window, 2),
                        "multiplier": self.multiplier,
                    },
                )
            )
        return alerts
