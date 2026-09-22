"""Provider-neutral alert notification contracts."""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


@dataclass(frozen=True, slots=True)
class AlertNotification:
    alert_name: str
    severity: str
    source_host: str
    occurred_at: datetime
    explanation: str
    agent_id: str | None = None


class NotificationProvider(Protocol):
    """Interface implemented by Discord and future email/chat providers."""

    name: str

    def send(self, notification: AlertNotification) -> None:
        """Deliver one notification or raise when delivery fails."""
