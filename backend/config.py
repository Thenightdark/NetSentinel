from functools import lru_cache
from typing import Annotated

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "NetSentinel API"
    database_url: str = (
        "postgresql+psycopg://netsentinel:change-this-local-development-password"
        "@localhost:5432/netsentinel"
    )
    allowed_origins: list[str] = ["http://localhost:3000"]
    ingest_api_key: SecretStr | None = Field(
        default=None, validation_alias="NETSENTINEL_API_KEY"
    )
    agent_enrollment_key: SecretStr | None = Field(
        default=None, validation_alias="NETSENTINEL_AGENT_ENROLLMENT_KEY"
    )
    agent_online_timeout_seconds: float = Field(
        default=90.0,
        gt=0,
        validation_alias="NETSENTINEL_AGENT_ONLINE_TIMEOUT_SECONDS",
    )
    auth_secret: SecretStr | None = Field(
        default=None, min_length=32, validation_alias="NETSENTINEL_AUTH_SECRET"
    )
    auth_session_minutes: int = Field(
        default=480,
        ge=5,
        le=43_200,
        validation_alias="NETSENTINEL_AUTH_SESSION_MINUTES",
    )
    auth_cookie_secure: bool = Field(
        default=False, validation_alias="NETSENTINEL_AUTH_COOKIE_SECURE"
    )
    initial_admin_username: str | None = Field(
        default=None, validation_alias="NETSENTINEL_ADMIN_USERNAME"
    )
    initial_admin_password: SecretStr | None = Field(
        default=None, validation_alias="NETSENTINEL_ADMIN_PASSWORD"
    )
    host_active_timeout_seconds: float = Field(
        default=300.0, validation_alias="NETSENTINEL_HOST_ACTIVE_TIMEOUT_SECONDS"
    )
    detection_enabled: bool = Field(
        default=True, validation_alias="NETSENTINEL_DETECTION_ENABLED"
    )
    connection_spike_baseline_seconds: float = Field(
        default=600.0,
        gt=0,
        validation_alias="NETSENTINEL_CONNECTION_SPIKE_BASELINE_SECONDS",
    )
    connection_spike_multiplier: float = Field(
        default=3.0,
        gt=1,
        validation_alias="NETSENTINEL_CONNECTION_SPIKE_MULTIPLIER",
    )
    unusual_destination_ports: list[Annotated[int, Field(ge=0, le=65_535)]] = Field(
        default_factory=lambda: [23, 445, 1433, 3389, 5900],
        validation_alias="NETSENTINEL_UNUSUAL_DESTINATION_PORTS",
    )
    detection_alert_cooldown_seconds: float = Field(
        default=300.0,
        ge=0,
        validation_alias="NETSENTINEL_DETECTION_ALERT_COOLDOWN_SECONDS",
    )
    dns_query_rate_window_seconds: float = Field(
        default=60.0,
        gt=0,
        validation_alias="NETSENTINEL_DNS_QUERY_RATE_WINDOW_SECONDS",
    )
    dns_query_rate_threshold: int = Field(
        default=100,
        ge=2,
        validation_alias="NETSENTINEL_DNS_QUERY_RATE_THRESHOLD",
    )
    dns_long_domain_length: int = Field(
        default=80,
        ge=20,
        le=253,
        validation_alias="NETSENTINEL_DNS_LONG_DOMAIN_LENGTH",
    )
    dns_failure_window_seconds: float = Field(
        default=300.0,
        gt=0,
        validation_alias="NETSENTINEL_DNS_FAILURE_WINDOW_SECONDS",
    )
    dns_failure_threshold: int = Field(
        default=10,
        ge=2,
        validation_alias="NETSENTINEL_DNS_FAILURE_THRESHOLD",
    )
    discord_webhook_url: SecretStr | None = Field(
        default=None, validation_alias="NETSENTINEL_DISCORD_WEBHOOK_URL"
    )
    notification_rate_limit_seconds: float = Field(
        default=300.0,
        ge=0,
        validation_alias="NETSENTINEL_NOTIFICATION_RATE_LIMIT_SECONDS",
    )
    notification_timeout_seconds: float = Field(
        default=5.0,
        gt=0,
        le=30,
        validation_alias="NETSENTINEL_NOTIFICATION_TIMEOUT_SECONDS",
    )

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
