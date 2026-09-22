from datetime import timedelta
import logging

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.config import Settings, get_settings
from backend.models import DNSObservation, NetworkFlow, SecurityAlert
from backend.services.detection_settings import get_detection_settings

from .bandwidth_spike import BandwidthSpikeRule
from .base import AlertCandidate
from .connection_spike import ConnectionSpikeRule
from .dns_rules import HighDNSQueryRateRule, LongDomainNameRule, RepeatedFailedDNSLookupRule
from .new_host import NewHostRule
from .port_scan import PortScanRule
from .scoring import RiskAssessment, score_candidate
from .unusual_port import UnusualDestinationPortRule

LOGGER = logging.getLogger(__name__)


class DetectionEngine:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.unusual_port = UnusualDestinationPortRule(
            self.settings.unusual_destination_ports
        )
        self.new_host = NewHostRule()
        self.high_dns_rate = HighDNSQueryRateRule(
            self.settings.dns_query_rate_threshold,
            self.settings.dns_query_rate_window_seconds,
        )
        self.long_domain = LongDomainNameRule(self.settings.dns_long_domain_length)
        self.failed_dns = RepeatedFailedDNSLookupRule(
            self.settings.dns_failure_threshold,
            self.settings.dns_failure_window_seconds,
        )

    def analyze(
        self,
        database: Session,
        flows: list[NetworkFlow],
        new_host_ips: set[str],
        agent_id: str | None = None,
    ) -> list[SecurityAlert]:
        if not self.settings.detection_enabled or not flows:
            return []

        configured = get_detection_settings(database)
        port_scan = PortScanRule(
            configured.port_scan_unique_ports,
            configured.port_scan_window_seconds,
        )
        connection_spike = ConnectionSpikeRule(
            configured.connection_spike_window_seconds,
            self.settings.connection_spike_baseline_seconds,
            self.settings.connection_spike_multiplier,
            configured.connection_spike_connections,
        )
        bandwidth_spike = BandwidthSpikeRule(
            configured.bandwidth_spike_megabytes * 1024 * 1024,
            configured.bandwidth_spike_window_seconds,
        )

        candidates = [
            *port_scan.evaluate(database, flows),
            *connection_spike.evaluate(database, flows),
            *self.unusual_port.evaluate(flows),
            *bandwidth_spike.evaluate(database, flows),
            *self.new_host.evaluate(new_host_ips),
        ]
        return self._persist_candidates(database, candidates, agent_id)

    def analyze_dns(
        self, database: Session, observations: list[DNSObservation], agent_id: str | None = None
    ) -> list[SecurityAlert]:
        if not self.settings.detection_enabled or not observations:
            return []
        candidates = [
            *self.high_dns_rate.evaluate(database, observations),
            *self.long_domain.evaluate(observations),
            *self.failed_dns.evaluate(database, observations),
        ]
        return self._persist_candidates(database, candidates, agent_id)

    def _persist_candidates(
        self, database: Session, candidates: list[AlertCandidate], agent_id: str | None = None
    ) -> list[SecurityAlert]:
        candidates_by_source = {
            source_ip: [item for item in candidates if item.source_ip == source_ip]
            for source_ip in {item.source_ip for item in candidates}
        }
        alerts = []
        for candidate in candidates:
            if self._is_in_cooldown(database, candidate, agent_id):
                continue
            assessment = score_candidate(
                database,
                candidate,
                candidates_by_source[candidate.source_ip],
                agent_id,
            )
            alerts.append(self._to_alert(candidate, assessment, agent_id))
        if alerts:
            from backend.services.statistics import record_alert_statistics

            database.add_all(alerts)
            record_alert_statistics(database, alerts)
            database.commit()
            LOGGER.info("Created %d defensive metadata alerts", len(alerts))
        return alerts

    def _is_in_cooldown(
        self, database: Session, candidate: AlertCandidate, agent_id: str | None
    ) -> bool:
        cooldown = self.settings.detection_alert_cooldown_seconds
        if cooldown <= 0 or candidate.detection_name == "new_host":
            return False
        destination_filter = (
            SecurityAlert.destination_ip.is_(None)
            if candidate.destination_ip is None
            else SecurityAlert.destination_ip == candidate.destination_ip
        )
        recent = database.scalar(
            select(func.count()).select_from(SecurityAlert).where(
                SecurityAlert.alert_type == candidate.detection_name,
                SecurityAlert.agent_id == agent_id,
                SecurityAlert.source_ip == candidate.source_ip,
                destination_filter,
                SecurityAlert.timestamp
                >= candidate.timestamp - timedelta(seconds=cooldown),
            )
        )
        return bool(recent)

    @staticmethod
    def _to_alert(
        candidate: AlertCandidate, assessment: RiskAssessment, agent_id: str | None
    ) -> SecurityAlert:
        evidence = {
            **candidate.evidence,
            "risk_score_breakdown": assessment.breakdown,
        }
        return SecurityAlert(
            agent_id=agent_id,
            timestamp=candidate.timestamp,
            severity=assessment.severity,
            risk_score=assessment.score,
            alert_type=candidate.detection_name,
            source_ip=candidate.source_ip,
            destination_ip=candidate.destination_ip,
            description=candidate.description,
            evidence=evidence,
            status="NEW",
        )


def run_detection(
    database: Session,
    flows: list[NetworkFlow],
    new_host_ips: set[str],
    agent_id: str | None = None,
) -> list[SecurityAlert]:
    return DetectionEngine().analyze(database, flows, new_host_ips, agent_id)


def run_dns_detection(
    database: Session, observations: list[DNSObservation], agent_id: str | None = None
) -> list[SecurityAlert]:
    return DetectionEngine().analyze_dns(database, observations, agent_id)
