"""Bounded in-memory aggregation of packet metadata into directional flows."""

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import logging
import threading

from .models import PacketMetadata

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class FlowKey:
    source_ip: str
    source_port: int | None
    destination_ip: str
    destination_port: int | None
    protocol: str

    @classmethod
    def from_packet(cls, packet: PacketMetadata) -> "FlowKey":
        return cls(
            source_ip=packet.source_ip,
            source_port=packet.source_port,
            destination_ip=packet.destination_ip,
            destination_port=packet.destination_port,
            protocol=packet.protocol,
        )


@dataclass(slots=True)
class NetworkFlow:
    first_seen: datetime
    last_seen: datetime
    packets_sent: int
    bytes_sent: int
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    protocol: str

    @classmethod
    def from_packet(cls, packet: PacketMetadata) -> "NetworkFlow":
        return cls(
            first_seen=packet.timestamp,
            last_seen=packet.timestamp,
            packets_sent=1,
            bytes_sent=packet.packet_size,
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            source_port=packet.source_port,
            destination_port=packet.destination_port,
            protocol=packet.protocol,
        )

    def add_packet(self, packet: PacketMetadata) -> None:
        self.first_seen = min(self.first_seen, packet.timestamp)
        self.last_seen = max(self.last_seen, packet.timestamp)
        self.packets_sent += 1
        self.bytes_sent += packet.packet_size

    def summary(self) -> str:
        return (
            f"{self.protocol} {_endpoint(self.source_ip, self.source_port)} -> "
            f"{_endpoint(self.destination_ip, self.destination_port)} "
            f"packets={self.packets_sent} bytes={self.bytes_sent} "
            f"first={self.first_seen.isoformat()} last={self.last_seen.isoformat()}"
        )


FinalizedFlowHandler = Callable[[NetworkFlow], None]


class FlowTracker:
    """Aggregate active directional flows and expire inactive entries.

    Only one aggregate object per active five-tuple is retained. Individual
    packets are never stored by the tracker.
    """

    def __init__(
        self,
        inactivity_timeout_seconds: float = 60.0,
        on_flow_finalized: FinalizedFlowHandler | None = None,
        sweep_interval_seconds: float | None = None,
    ) -> None:
        if inactivity_timeout_seconds <= 0:
            raise ValueError("inactivity_timeout_seconds must be greater than zero")
        if sweep_interval_seconds is not None and sweep_interval_seconds <= 0:
            raise ValueError("sweep_interval_seconds must be greater than zero")

        self.inactivity_timeout = timedelta(seconds=inactivity_timeout_seconds)
        self.sweep_interval_seconds = sweep_interval_seconds or min(
            max(inactivity_timeout_seconds / 2, 0.1), 5.0
        )
        self.on_flow_finalized = on_flow_finalized
        self._active: dict[FlowKey, NetworkFlow] = {}
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def active_flow_count(self) -> int:
        with self._lock:
            return len(self._active)

    def observe(self, packet: PacketMetadata) -> None:
        key = FlowKey.from_packet(packet)
        with self._lock:
            flow = self._active.get(key)
            if flow is None:
                self._active[key] = NetworkFlow.from_packet(packet)
            else:
                flow.add_packet(packet)

    def snapshot(self) -> list[NetworkFlow]:
        """Return detached copies of current aggregates for diagnostics."""
        with self._lock:
            return [replace(flow) for flow in self._active.values()]

    def finalize_inactive(self, as_of: datetime | None = None) -> list[NetworkFlow]:
        reference_time = as_of or datetime.now(timezone.utc)
        finalized: list[NetworkFlow] = []
        with self._lock:
            inactive_keys = [
                key
                for key, flow in self._active.items()
                if reference_time - flow.last_seen >= self.inactivity_timeout
            ]
            for key in inactive_keys:
                finalized.append(self._active.pop(key))

        self._emit_finalized(finalized)
        return finalized

    def finalize_all(self) -> list[NetworkFlow]:
        with self._lock:
            finalized = list(self._active.values())
            self._active.clear()
        self._emit_finalized(finalized)
        return finalized

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._sweep_loop,
            name="netsentinel-flow-finalizer",
            daemon=True,
        )
        self._thread.start()

    def stop(self, finalize_remaining: bool = True) -> list[NetworkFlow]:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self.sweep_interval_seconds + 1.0)
            self._thread = None
        return self.finalize_all() if finalize_remaining else []

    def _sweep_loop(self) -> None:
        while not self._stop_event.wait(self.sweep_interval_seconds):
            try:
                self.finalize_inactive()
            except Exception:
                LOGGER.exception("Inactive flow finalization failed")

    def _emit_finalized(self, flows: list[NetworkFlow]) -> None:
        if self.on_flow_finalized is None:
            return
        for flow in flows:
            try:
                self.on_flow_finalized(flow)
            except Exception:
                LOGGER.exception("Finalized flow handler failed")


def _endpoint(ip_address: str, port: int | None) -> str:
    if port is None:
        return ip_address
    if ":" in ip_address:
        return f"[{ip_address}]:{port}"
    return f"{ip_address}:{port}"
