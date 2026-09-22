from datetime import datetime, timezone
import json

import httpx

from backend.models import SecurityAlert
from backend.services.notifications import DiscordWebhookProvider, NotificationManager


def alert(
    severity: str = "HIGH",
    *,
    alert_type: str = "possible_port_scan",
    source_ip: str = "192.168.1.40",
    agent_id: str = "agent-a",
) -> SecurityAlert:
    return SecurityAlert(
        agent_id=agent_id,
        timestamp=datetime(2026, 9, 22, 12, 30, tzinfo=timezone.utc),
        severity=severity,
        risk_score=75,
        alert_type=alert_type,
        source_ip=source_ip,
        destination_ip=None,
        description="Possible port scan signal; review the observed flow pattern.",
        evidence={},
        status="NEW",
    )


def test_discord_provider_formats_required_alert_fields() -> None:
    requests: list[httpx.Request] = []
    provider = DiscordWebhookProvider(
        "https://discord.test/api/webhooks/example",
        transport=httpx.MockTransport(
            lambda request: requests.append(request) or httpx.Response(204)
        ),
    )
    try:
        delivered = NotificationManager([provider], rate_limit_seconds=300).notify_alerts(
            [alert("CRITICAL")]
        )
    finally:
        provider.close()

    payload = json.loads(requests[0].content)
    embed = payload["embeds"][0]
    assert delivered == 1
    assert embed["title"] == "Possible Port Scan"
    assert embed["description"].startswith("Possible port scan signal")
    assert {field["name"]: field["value"] for field in embed["fields"]} == {
        "Severity": "CRITICAL",
        "Source host": "192.168.1.40",
        "Time": "2026-09-22T12:30:00+00:00",
    }
    assert payload["allowed_mentions"] == {"parse": []}


def test_notifications_filter_severity_and_rate_limit_repeats() -> None:
    sent = []

    class RecordingProvider:
        name = "recording"

        def send(self, notification) -> None:
            sent.append(notification)

    current_time = [100.0]
    manager = NotificationManager(
        [RecordingProvider()],
        rate_limit_seconds=60,
        clock=lambda: current_time[0],
    )

    assert manager.notify_alerts([alert("INFO"), alert("MEDIUM")]) == 0
    assert manager.notify_alerts([alert("HIGH")]) == 1
    assert manager.notify_alerts([alert("HIGH")]) == 0
    assert manager.notify_alerts([alert("CRITICAL")]) == 1
    assert manager.notify_alerts([alert("CRITICAL")]) == 0
    current_time[0] += 61
    assert manager.notify_alerts([alert("CRITICAL")]) == 1
    assert [item.severity for item in sent] == ["HIGH", "CRITICAL", "CRITICAL"]


def test_provider_failure_does_not_escape_notification_dispatch() -> None:
    class FailingProvider:
        name = "failing"

        def send(self, notification) -> None:
            raise RuntimeError("temporary service failure")

    manager = NotificationManager([FailingProvider()], rate_limit_seconds=60)
    assert manager.notify_alerts([alert("HIGH")]) == 0
