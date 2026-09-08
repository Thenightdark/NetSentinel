"""Configuration for the passive NetSentinel collector."""

from dataclasses import dataclass
import os


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class CollectorConfig:
    """Runtime options with safe, local-only defaults."""

    interface: str | None = None
    demo_mode: bool = False
    fallback_to_demo: bool = True
    packet_limit: int = 0
    flow_inactivity_timeout_seconds: float = 60.0
    backend_url: str = "http://localhost:8000"
    api_key: str | None = None
    ingest_batch_size: int = 100
    ingest_flush_interval_seconds: float = 2.0
    ingest_timeout_seconds: float = 5.0
    ingest_max_retries: int = 3
    ingest_max_queue_size: int = 5_000
    log_level: str = "INFO"

    @classmethod
    def from_environment(cls) -> "CollectorConfig":
        return cls(
            interface=os.getenv("NETSENTINEL_INTERFACE") or None,
            demo_mode=_env_flag("NETSENTINEL_DEMO"),
            fallback_to_demo=not _env_flag("NETSENTINEL_DISABLE_DEMO_FALLBACK"),
            packet_limit=max(0, int(os.getenv("NETSENTINEL_PACKET_LIMIT", "0"))),
            flow_inactivity_timeout_seconds=max(
                0.1, float(os.getenv("NETSENTINEL_FLOW_TIMEOUT_SECONDS", "60"))
            ),
            backend_url=os.getenv("NETSENTINEL_BACKEND_URL", "http://localhost:8000"),
            api_key=os.getenv("NETSENTINEL_API_KEY") or None,
            ingest_batch_size=max(1, int(os.getenv("NETSENTINEL_INGEST_BATCH_SIZE", "100"))),
            ingest_flush_interval_seconds=max(
                0.1, float(os.getenv("NETSENTINEL_INGEST_FLUSH_SECONDS", "2"))
            ),
            ingest_timeout_seconds=max(
                0.1, float(os.getenv("NETSENTINEL_INGEST_TIMEOUT_SECONDS", "5"))
            ),
            ingest_max_retries=max(
                0, int(os.getenv("NETSENTINEL_INGEST_MAX_RETRIES", "3"))
            ),
            ingest_max_queue_size=max(
                1, int(os.getenv("NETSENTINEL_INGEST_MAX_QUEUE_SIZE", "5000"))
            ),
            log_level=os.getenv("NETSENTINEL_LOG_LEVEL", "INFO").upper(),
        )
