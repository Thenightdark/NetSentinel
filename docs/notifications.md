# Alert notifications

NetSentinel can send newly created `HIGH` and `CRITICAL` defensive alerts to a Discord channel. Lower-severity signals remain available in the dashboard but do not generate outbound notifications.

## Discord setup

Create a webhook for the intended Discord channel, then store its URL only in the local `.env` file:

```env
NETSENTINEL_DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your-private-value
NETSENTINEL_NOTIFICATION_RATE_LIMIT_SECONDS=300
NETSENTINEL_NOTIFICATION_TIMEOUT_SECONDS=5
```

The checked-in `.env.example` intentionally contains no webhook URL. The populated `.env` file is ignored by Git. Treat a Discord webhook URL as a secret because anyone possessing it can post to that channel.

Each message contains the alert name, severity, source host, event time, and a short explanation. Discord mentions are disabled in webhook payloads.

## Rate limiting and failure behavior

The manager suppresses repeated notifications for the same provider, collector agent, detection name, source host, and severity during the configured window. The default is five minutes. A change from `HIGH` to `CRITICAL` is treated as a meaningful escalation and is not suppressed. This in-memory window is intentionally lightweight and resets when the backend restarts.

Notification delivery runs as a FastAPI background task after the alert has been stored. Timeouts and provider errors are logged and do not roll back alerts, reject collector ingestion, or stop packet capture.

## Adding providers

Providers implement the `NotificationProvider` interface and receive a provider-neutral `AlertNotification`. Email, Slack, Teams, or other adapters can therefore be added without changing detection rules or the Discord implementation. Register additional providers in `get_notification_manager()`.
