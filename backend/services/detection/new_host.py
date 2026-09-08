from datetime import datetime, timezone

from .base import AlertCandidate


class NewHostRule:
    def evaluate(
        self, host_ips: set[str], now: datetime | None = None
    ) -> list[AlertCandidate]:
        observed_at = now or datetime.now(timezone.utc)
        return [
            AlertCandidate(
                timestamp=observed_at,
                severity="info",
                detection_name="new_host",
                source_ip=host_ip,
                destination_ip=None,
                description=(
                    f"New host observed: {host_ip} appeared in passive LAN traffic for the "
                    "first time. This is informational and does not imply malicious activity."
                ),
                evidence={"host_ip": host_ip, "discovery_method": "passive_flow_observation"},
            )
            for host_ip in sorted(host_ips)
        ]
