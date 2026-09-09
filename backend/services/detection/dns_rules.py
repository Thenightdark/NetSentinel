from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.models import DNSObservation

from .base import AlertCandidate


class HighDNSQueryRateRule:
    def __init__(self, query_threshold: int, window_seconds: float) -> None:
        self.query_threshold = query_threshold
        self.window_seconds = window_seconds

    def evaluate(
        self,
        database: Session,
        observations: list[DNSObservation],
        now: datetime | None = None,
    ) -> list[AlertCandidate]:
        observed_at = now or datetime.now(timezone.utc)
        cutoff = observed_at - timedelta(seconds=self.window_seconds)
        clients = {
            item.requesting_host for item in observations if not item.is_response
        }
        alerts: list[AlertCandidate] = []
        for client in clients:
            count = int(
                database.scalar(
                    select(func.count()).select_from(DNSObservation).where(
                        DNSObservation.requesting_host == client,
                        DNSObservation.is_response.is_(False),
                        DNSObservation.timestamp >= cutoff,
                    )
                )
                or 0
            )
            if count < self.query_threshold:
                continue
            alerts.append(
                AlertCandidate(
                    timestamp=observed_at,
                    detection_name="high_dns_query_rate",
                    source_ip=client,
                    destination_ip=None,
                    description=(
                        f"Unusual DNS traffic pattern: {client} made {count} queries within "
                        f"{self.window_seconds:g} seconds. High query volume can be legitimate "
                        "and should be reviewed in context."
                    ),
                    evidence={
                        "window_seconds": self.window_seconds,
                        "dns_queries_in_window": count,
                        "dns_query_threshold": self.query_threshold,
                    },
                )
            )
        return alerts


class LongDomainNameRule:
    def __init__(self, length_threshold: int) -> None:
        self.length_threshold = length_threshold

    def evaluate(
        self,
        observations: list[DNSObservation],
        now: datetime | None = None,
    ) -> list[AlertCandidate]:
        observed_at = now or datetime.now(timezone.utc)
        alerts: list[AlertCandidate] = []
        seen: set[tuple[str, str]] = set()
        for item in observations:
            key = (item.requesting_host, item.queried_domain)
            if item.is_response or key in seen or len(item.queried_domain) < self.length_threshold:
                continue
            seen.add(key)
            alerts.append(
                AlertCandidate(
                    timestamp=observed_at,
                    detection_name="unusually_long_domain",
                    source_ip=item.requesting_host,
                    destination_ip=None,
                    description=(
                        f"Unusual DNS signal: {item.requesting_host} requested a domain name "
                        f"with {len(item.queried_domain)} characters. Long names are not proof "
                        "of malicious activity."
                    ),
                    evidence={
                        "queried_domain": item.queried_domain,
                        "domain_length": len(item.queried_domain),
                        "long_domain_threshold": self.length_threshold,
                        "query_type": item.query_type,
                    },
                )
            )
        return alerts


class RepeatedFailedDNSLookupRule:
    def __init__(self, failure_threshold: int, window_seconds: float) -> None:
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds

    def evaluate(
        self,
        database: Session,
        observations: list[DNSObservation],
        now: datetime | None = None,
    ) -> list[AlertCandidate]:
        observed_at = now or datetime.now(timezone.utc)
        cutoff = observed_at - timedelta(seconds=self.window_seconds)
        keys = {
            (item.requesting_host, item.queried_domain)
            for item in observations
            if item.is_response and item.response_status not in (None, "NOERROR")
        }
        alerts: list[AlertCandidate] = []
        for client, domain in keys:
            count = int(
                database.scalar(
                    select(func.count()).select_from(DNSObservation).where(
                        DNSObservation.requesting_host == client,
                        DNSObservation.queried_domain == domain,
                        DNSObservation.is_response.is_(True),
                        DNSObservation.response_status.is_not(None),
                        func.upper(DNSObservation.response_status) != "NOERROR",
                        DNSObservation.timestamp >= cutoff,
                    )
                )
                or 0
            )
            if count < self.failure_threshold:
                continue
            alerts.append(
                AlertCandidate(
                    timestamp=observed_at,
                    detection_name="repeated_failed_dns_lookups",
                    source_ip=client,
                    destination_ip=None,
                    description=(
                        f"Potentially suspicious DNS activity: {client} received {count} "
                        f"failed lookups for {domain} within {self.window_seconds:g} seconds. "
                        "Configuration errors and unavailable domains can produce this signal."
                    ),
                    evidence={
                        "queried_domain": domain,
                        "window_seconds": self.window_seconds,
                        "failed_lookups": count,
                        "failure_threshold": self.failure_threshold,
                    },
                )
            )
        return alerts
