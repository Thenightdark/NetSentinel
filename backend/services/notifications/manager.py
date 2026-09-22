"""Severity filtering, rate limiting, and provider dispatch."""

from collections.abc import Callable, Iterable
from functools import lru_cache
import logging
from threading import Lock
from time import monotonic

from backend.config import get_settings
from backend.models import SecurityAlert

from .base import AlertNotification, NotificationProvider
from .discord import DiscordWebhookProvider

LOGGER = logging.getLogger(__name__)
NOTIFIABLE_SEVERITIES = frozenset({"HIGH", "CRITICAL"})


class NotificationManager:
    def __init__(
        self,
        providers: Iterable[NotificationProvider],
        *,
        rate_limit_seconds: float = 300.0,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self.providers = tuple(providers)
        self.rate_limit_seconds = rate_limit_seconds
        self._clock = clock
        self._last_attempt: dict[tuple[str, str | None, str, str, str], float] = {}
        self._lock = Lock()

    def notify_alerts(self, alerts: Iterable[SecurityAlert]) -> int:
        delivered = 0
        for alert in alerts:
            severity = alert.severity.upper()
            if severity not in NOTIFIABLE_SEVERITIES:
                continue
            notification = AlertNotification(
                alert_name=alert.alert_type,
                severity=severity,
                source_host=alert.source_ip or "Unknown source",
                occurred_at=alert.timestamp,
                explanation=alert.description,
                agent_id=alert.agent_id,
            )
            for provider in self.providers:
                if not self._reserve(provider.name, notification):
                    LOGGER.info(
                        "Suppressed repeated %s notification for %s",
                        notification.alert_name,
                        notification.source_host,
                    )
                    continue
                try:
                    provider.send(notification)
                except Exception as exc:
                    LOGGER.warning(
                        "%s alert notification failed without affecting detection: %s",
                        provider.name,
                        exc,
                    )
                else:
                    delivered += 1
        return delivered

    def _reserve(self, provider_name: str, notification: AlertNotification) -> bool:
        key = (
            provider_name,
            notification.agent_id,
            notification.alert_name,
            notification.source_host,
            notification.severity,
        )
        now = self._clock()
        with self._lock:
            previous = self._last_attempt.get(key)
            if previous is not None and now - previous < self.rate_limit_seconds:
                return False
            self._last_attempt[key] = now
            self._prune(now)
            return True

    def _prune(self, now: float) -> None:
        expiry = max(self.rate_limit_seconds, 60.0) * 2
        stale = [key for key, seen_at in self._last_attempt.items() if now - seen_at > expiry]
        for key in stale:
            self._last_attempt.pop(key, None)

    def close(self) -> None:
        for provider in self.providers:
            close = getattr(provider, "close", None)
            if callable(close):
                close()


@lru_cache
def get_notification_manager() -> NotificationManager:
    settings = get_settings()
    providers: list[NotificationProvider] = []
    webhook_url = (
        settings.discord_webhook_url.get_secret_value().strip()
        if settings.discord_webhook_url is not None
        else ""
    )
    if webhook_url:
        providers.append(
            DiscordWebhookProvider(
                webhook_url,
                timeout_seconds=settings.notification_timeout_seconds,
            )
        )
    return NotificationManager(
        providers, rate_limit_seconds=settings.notification_rate_limit_seconds
    )
