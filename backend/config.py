from functools import lru_cache
from typing import Annotated

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "NetSentinel API"
    database_url: str = "sqlite:///./netsentinel.db"
    allowed_origins: list[str] = ["http://localhost:3000"]
    ingest_api_key: SecretStr | None = Field(
        default=None, validation_alias="NETSENTINEL_API_KEY"
    )
    host_active_timeout_seconds: float = Field(
        default=300.0, validation_alias="NETSENTINEL_HOST_ACTIVE_TIMEOUT_SECONDS"
    )
    detection_enabled: bool = Field(
        default=True, validation_alias="NETSENTINEL_DETECTION_ENABLED"
    )
    port_scan_window_seconds: float = Field(
        default=60.0, gt=0, validation_alias="NETSENTINEL_PORT_SCAN_WINDOW_SECONDS"
    )
    port_scan_unique_ports: int = Field(
        default=20, ge=2, validation_alias="NETSENTINEL_PORT_SCAN_UNIQUE_PORTS"
    )
    connection_spike_window_seconds: float = Field(
        default=60.0,
        gt=0,
        validation_alias="NETSENTINEL_CONNECTION_SPIKE_WINDOW_SECONDS",
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
    connection_spike_min_connections: int = Field(
        default=30,
        ge=2,
        validation_alias="NETSENTINEL_CONNECTION_SPIKE_MIN_CONNECTIONS",
    )
    unusual_destination_ports: list[Annotated[int, Field(ge=0, le=65_535)]] = Field(
        default_factory=lambda: [23, 445, 1433, 3389, 5900],
        validation_alias="NETSENTINEL_UNUSUAL_DESTINATION_PORTS",
    )
    bandwidth_outbound_bytes: int = Field(
        default=50_000_000,
        ge=1,
        validation_alias="NETSENTINEL_BANDWIDTH_OUTBOUND_BYTES",
    )
    bandwidth_inbound_bytes: int = Field(
        default=100_000_000,
        ge=1,
        validation_alias="NETSENTINEL_BANDWIDTH_INBOUND_BYTES",
    )
    detection_alert_cooldown_seconds: float = Field(
        default=300.0,
        ge=0,
        validation_alias="NETSENTINEL_DETECTION_ALERT_COOLDOWN_SECONDS",
    )

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
