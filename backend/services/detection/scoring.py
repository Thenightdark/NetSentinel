from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.models import SecurityAlert

from .base import AlertCandidate

METHODOLOGY_VERSION = "1.1"
RULE_BASE_POINTS = {
    "new_host": 5,
    "unusual_destination_port": 20,
    "bandwidth_spike": 25,
    "connection_spike": 30,
    "possible_port_scan": 35,
    "high_dns_query_rate": 30,
    "unusually_long_domain": 20,
    "repeated_failed_dns_lookups": 25,
}


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: int
    severity: str
    breakdown: dict[str, int | str]


def severity_for_score(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"


def score_candidate(
    database: Session,
    candidate: AlertCandidate,
    correlated_candidates: list[AlertCandidate],
) -> RiskAssessment:
    """Score a finding using documented, bounded, auditable components."""
    base_points = RULE_BASE_POINTS[candidate.detection_name]
    distinct_rules = len({item.detection_name for item in correlated_candidates})
    correlation_points = min(18, max(0, distinct_rules - 1) * 6)

    connection_points = _largest_ratio_component(
        correlated_candidates,
        value_key="connections_in_window",
        threshold_key="minimum_connections",
        maximum_points=15,
    )
    unique_port_points = _largest_ratio_component(
        correlated_candidates,
        value_key="unique_destination_ports",
        threshold_key="port_threshold",
        maximum_points=15,
    )
    bandwidth_points = _largest_ratio_component(
        correlated_candidates,
        value_key="bytes",
        threshold_key="threshold_bytes",
        maximum_points=15,
    )
    dns_rate_points = _largest_ratio_component(
        correlated_candidates,
        value_key="dns_queries_in_window",
        threshold_key="dns_query_threshold",
        maximum_points=15,
    )
    domain_length_points = _largest_ratio_component(
        correlated_candidates,
        value_key="domain_length",
        threshold_key="long_domain_threshold",
        maximum_points=10,
    )
    dns_failure_points = _largest_ratio_component(
        correlated_candidates,
        value_key="failed_lookups",
        threshold_key="failure_threshold",
        maximum_points=15,
    )

    direction = str(candidate.evidence.get("direction", "not_applicable"))
    direction_points = 4 if direction == "inbound" else 2 if direction == "outbound" else 0
    previous_alerts = int(
        database.scalar(
            select(func.count()).select_from(SecurityAlert).where(
                SecurityAlert.source_ip == candidate.source_ip
            )
        )
        or 0
    )
    history_points = min(8, previous_alerts * 2)

    raw_score = sum(
        (
            base_points,
            correlation_points,
            connection_points,
            unique_port_points,
            bandwidth_points,
            dns_rate_points,
            domain_length_points,
            dns_failure_points,
            direction_points,
            history_points,
        )
    )
    score = min(100, raw_score)
    return RiskAssessment(
        score=score,
        severity=severity_for_score(score),
        breakdown={
            "methodology_version": METHODOLOGY_VERSION,
            "rule_base": base_points,
            "rule_correlation": correlation_points,
            "connection_frequency": connection_points,
            "unique_ports": unique_port_points,
            "bandwidth_volume": bandwidth_points,
            "dns_query_rate": dns_rate_points,
            "domain_length": domain_length_points,
            "dns_lookup_failures": dns_failure_points,
            "traffic_direction": direction_points,
            "previous_alert_history": history_points,
            "distinct_rules_for_source": distinct_rules,
            "previous_alert_count": previous_alerts,
            "total": score,
        },
    )


def _largest_ratio_component(
    candidates: list[AlertCandidate],
    *,
    value_key: str,
    threshold_key: str,
    maximum_points: int,
) -> int:
    """Award half the component at threshold and cap it at twice threshold."""
    largest = 0
    for candidate in candidates:
        value = candidate.evidence.get(value_key)
        threshold = candidate.evidence.get(threshold_key)
        if not isinstance(value, (int, float)) or not isinstance(threshold, (int, float)):
            continue
        if threshold <= 0:
            continue
        points = round(maximum_points * min(1.0, value / (2 * threshold)))
        largest = max(largest, points)
    return largest
