"""Discord webhook notification provider."""

import httpx

from .base import AlertNotification


class DiscordWebhookProvider:
    name = "discord"
    _COLORS = {"HIGH": 0xF59E0B, "CRITICAL": 0xEF4444}

    def __init__(
        self,
        webhook_url: str,
        *,
        timeout_seconds: float = 5.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._webhook_url = webhook_url
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout_seconds), transport=transport
        )

    def send(self, notification: AlertNotification) -> None:
        response = self._client.post(
            self._webhook_url,
            json={
                "username": "NetSentinel",
                "allowed_mentions": {"parse": []},
                "embeds": [
                    {
                        "title": _display_name(notification.alert_name),
                        "description": notification.explanation[:500],
                        "color": self._COLORS.get(notification.severity, 0x64748B),
                        "fields": [
                            {
                                "name": "Severity",
                                "value": notification.severity,
                                "inline": True,
                            },
                            {
                                "name": "Source host",
                                "value": notification.source_host,
                                "inline": True,
                            },
                            {
                                "name": "Time",
                                "value": notification.occurred_at.isoformat(),
                                "inline": False,
                            },
                        ],
                        "footer": {"text": "Defensive metadata signal · review in context"},
                    }
                ],
            },
        )
        response.raise_for_status()

    def close(self) -> None:
        self._client.close()


def _display_name(value: str) -> str:
    return value.replace("_", " ").strip().title()
