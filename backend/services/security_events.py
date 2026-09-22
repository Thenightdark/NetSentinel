"""Investigation context for defensive security events."""

from datetime import timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.config import get_settings
from backend.models import Host, NetworkFlow, SecurityAlert
from backend.schemas import SecurityEventDetail, SecurityEventHost
from backend.services.hosts import host_is_active


WHY_FLAGGED = {
    "possible_port_scan": "The source contacted more distinct destination ports than the configured threshold within a short observation window. Authorized discovery or administrative tools can produce the same pattern.",
    "connection_spike": "The connection count exceeded both the configured minimum and the host's recent baseline. Updates, browsers, or automation can also create bursts.",
    "unusual_destination_port": "The destination port is included in the configured uncommon or higher-risk port list. Port choice alone does not establish malicious intent.",
    "bandwidth_spike": "The transfer volume exceeded the configured inbound or outbound threshold. Large legitimate transfers should be considered during review.",
    "new_host": "A local-network address not previously recorded by this collector appeared in passive traffic metadata. This is an informational discovery signal.",
    "high_dns_query_rate": "The host generated more DNS requests than the configured rate threshold. Busy applications and resolvers can cause similar behavior.",
    "unusually_long_domain": "The queried domain length exceeded the configured threshold. Long domains can be legitimate and require surrounding context.",
    "repeated_failed_dns_lookups": "Unsuccessful DNS responses crossed the configured threshold. Stale configuration and unavailable services are possible explanations.",
}

RECOMMENDATIONS = {
    "possible_port_scan": [
        "Confirm whether the source belongs to an approved scanner, inventory tool, or administrator.",
        "Review the related destination ports and hosts for a consistent operational purpose.",
        "Compare the event with the source host's recent connection history before escalating.",
    ],
    "connection_spike": [
        "Compare the time window with scheduled jobs, software updates, or known traffic bursts.",
        "Review related flows for repeated destinations, ports, and process context when available.",
        "Check whether the connection rate returns to the host's normal baseline.",
    ],
    "unusual_destination_port": [
        "Verify whether the destination service and port are expected for this host.",
        "Review process information and neighboring flows for business context.",
        "Confirm destination ownership before deciding whether escalation is appropriate.",
    ],
    "bandwidth_spike": [
        "Determine whether backups, synchronization, downloads, or updates explain the transfer.",
        "Review direction, destination ownership, duration, and associated process metadata.",
        "Compare volume with earlier activity from the same host and collector.",
    ],
    "new_host": [
        "Compare the address and hostname with the authorized device inventory.",
        "Review its first observed flows to understand likely purpose and ownership.",
        "Continue passive observation; do not treat discovery alone as hostile activity.",
    ],
    "high_dns_query_rate": [
        "Identify the applications or services active on the requesting host at that time.",
        "Review top queried domains and determine whether the volume is expected.",
        "Compare the rate with the same host's normal DNS behavior.",
    ],
    "unusually_long_domain": [
        "Review the queried name and surrounding requests for a legitimate application pattern.",
        "Check whether the domain is associated with a known service used by the host.",
        "Look for repetition or additional signals before escalating.",
    ],
    "repeated_failed_dns_lookups": [
        "Check the requesting host for stale application or DNS configuration.",
        "Review whether failures repeat across one domain or many related names.",
        "Correlate with connection and process metadata before drawing conclusions.",
    ],
}

DEFAULT_RECOMMENDATIONS = [
    "Validate the source and destination against expected network activity.",
    "Review related flows, evidence, and process context before escalating.",
    "Document a benign explanation or continue monitoring for corroborating signals.",
]


def get_security_event_detail(
    database: Session, alert: SecurityAlert
) -> SecurityEventDetail:
    endpoint_filters = []
    for address in (alert.source_ip, alert.destination_ip):
        if address:
            endpoint_filters.extend(
                [NetworkFlow.source_ip == address, NetworkFlow.destination_ip == address]
            )

    related_flows = []
    if endpoint_filters:
        related_flows = list(
            database.scalars(
                select(NetworkFlow)
                .where(
                    NetworkFlow.agent_id == alert.agent_id,
                    NetworkFlow.last_seen >= alert.timestamp - timedelta(minutes=10),
                    NetworkFlow.first_seen <= alert.timestamp + timedelta(minutes=10),
                    or_(*endpoint_filters),
                )
                .order_by(NetworkFlow.last_seen.desc())
                .limit(20)
            )
        )

    host = None
    for address in (alert.source_ip, alert.destination_ip):
        if address:
            host = database.scalar(
                select(Host).where(
                    Host.agent_id == alert.agent_id, Host.ip_address == address
                )
            )
        if host is not None:
            break

    host_context = None
    if host is not None:
        timeout = get_settings().host_active_timeout_seconds
        host_context = SecurityEventHost(
            id=host.id,
            ip_address=host.ip_address,
            hostname=host.hostname,
            first_seen=host.first_seen,
            last_seen=host.last_seen,
            total_bytes=host.total_bytes,
            total_connections=host.total_connections,
            is_active=host_is_active(host, timeout),
        )

    return SecurityEventDetail(
        id=alert.id,
        agent_id=alert.agent_id,
        timestamp=alert.timestamp,
        severity=alert.severity,
        risk_score=alert.risk_score,
        alert_type=alert.alert_type,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        description=alert.description,
        evidence=alert.evidence,
        status=alert.status,
        why_flagged=WHY_FLAGGED.get(
            alert.alert_type,
            "Observed metadata matched a configured defensive rule. The signal requires contextual review and is not proof that an attack occurred.",
        ),
        related_flows=related_flows,
        host=host_context,
        recommended_investigation_steps=RECOMMENDATIONS.get(
            alert.alert_type, DEFAULT_RECOMMENDATIONS
        ),
    )
