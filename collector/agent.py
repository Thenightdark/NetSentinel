"""Collector identity enrollment and lightweight backend heartbeats."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import logging
import os
from pathlib import Path
import platform
import socket
import threading
from uuid import uuid4

import httpx

LOGGER = logging.getLogger(__name__)
COLLECTOR_VERSION = "0.4.0"


@dataclass(frozen=True, slots=True)
class AgentCredentials:
    agent_id: str
    api_key: str


class AgentClient:
    """Enroll this installation once and keep its presence current."""

    def __init__(
        self,
        backend_url: str,
        enrollment_key: str | None,
        state_path: Path,
        *,
        heartbeat_interval_seconds: float = 30.0,
        timeout_seconds: float = 5.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.enrollment_key = enrollment_key
        self.state_path = state_path
        self.heartbeat_interval_seconds = heartbeat_interval_seconds
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._client = httpx.Client(
            base_url=backend_url.rstrip("/"),
            timeout=httpx.Timeout(timeout_seconds),
            transport=transport,
        )

    def ensure_registered(self) -> AgentCredentials:
        credentials = self._load_credentials()
        if credentials is not None:
            return credentials
        if not self.enrollment_key:
            raise RuntimeError("NETSENTINEL_AGENT_ENROLLMENT_KEY is not configured")

        agent_id = str(uuid4())
        response = self._client.post(
            "/api/agents/register",
            headers={"X-API-Key": self.enrollment_key},
            json={
                "agent_id": agent_id,
                "hostname": platform.node() or "unknown-host",
                "operating_system": _operating_system_name(),
                "ip_address": _safe_local_ip(),
                "version": COLLECTOR_VERSION,
            },
        )
        response.raise_for_status()
        data = response.json()
        credentials = AgentCredentials(agent_id=data["agent_id"], api_key=data["api_key"])
        self._save_credentials(credentials)
        LOGGER.info("Registered collector agent %s", credentials.agent_id)
        return credentials

    def start(self, credentials: AgentCredentials) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._heartbeat_worker,
            args=(credentials,),
            name="netsentinel-agent-heartbeat",
            daemon=True,
        )
        self._thread.start()

    def heartbeat(self, credentials: AgentCredentials) -> bool:
        try:
            response = self._client.post(
                "/api/agents/heartbeat",
                headers={
                    "X-Agent-ID": credentials.agent_id,
                    "X-API-Key": credentials.api_key,
                },
            )
            response.raise_for_status()
            return True
        except httpx.HTTPError as exc:
            LOGGER.warning("Collector heartbeat failed; capture will continue: %s", exc)
            return False

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=min(self.heartbeat_interval_seconds + 1.0, 10.0))
            self._thread = None
        self._client.close()

    def _heartbeat_worker(self, credentials: AgentCredentials) -> None:
        while not self._stop_event.is_set():
            self.heartbeat(credentials)
            self._stop_event.wait(self.heartbeat_interval_seconds)

    def _load_credentials(self) -> AgentCredentials | None:
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            return AgentCredentials(agent_id=data["agent_id"], api_key=data["api_key"])
        except FileNotFoundError:
            return None
        except (KeyError, TypeError, ValueError, OSError) as exc:
            raise RuntimeError(f"Invalid collector identity file: {self.state_path}") from exc

    def _save_credentials(self, credentials: AgentCredentials) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        temporary_path.write_text(json.dumps(asdict(credentials), indent=2), encoding="utf-8")
        if os.name != "nt":
            temporary_path.chmod(0o600)
        temporary_path.replace(self.state_path)


def _operating_system_name() -> str:
    return " ".join(item for item in (platform.system(), platform.release()) if item) or "Unknown"


def _safe_local_ip() -> str:
    """Use hostname resolution only; never probe or open a network connection."""
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"
