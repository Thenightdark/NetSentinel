"""Optional, best-effort correlation with local OS connection metadata."""

from dataclasses import dataclass, replace
import logging
from ntpath import basename
import socket
from time import monotonic

import psutil

from .models import PacketMetadata

LOGGER = logging.getLogger(__name__)
EndpointKey = tuple[str, int, str]


@dataclass(frozen=True, slots=True)
class ProcessMetadata:
    process_id: int
    process_name: str | None
    executable_name: str | None


class ProcessConnectionCorrelator:
    """Match packet endpoints to psutil's passive local connection snapshot.

    The cache keeps packet handling fast and deliberately stores only a PID and
    executable basename. Full executable paths and process memory are not read.
    """

    def __init__(self, enabled: bool = False, refresh_interval_seconds: float = 2.0) -> None:
        if refresh_interval_seconds <= 0:
            raise ValueError("refresh_interval_seconds must be greater than zero")
        self.enabled = enabled
        self.refresh_interval_seconds = refresh_interval_seconds
        self._connections: dict[EndpointKey, ProcessMetadata] = {}
        self._last_refresh = float("-inf")
        self._availability_warning_logged = False

    def enrich(self, packet: PacketMetadata) -> PacketMetadata:
        if not self.enabled or packet.source_port is None or packet.destination_port is None:
            return packet
        self._refresh_if_due()
        process = self._match(packet)
        if process is None:
            return packet
        return replace(
            packet,
            process_id=process.process_id,
            process_name=process.process_name,
            executable_name=process.executable_name,
        )

    def _refresh_if_due(self) -> None:
        now = monotonic()
        if now - self._last_refresh < self.refresh_interval_seconds:
            return
        self._last_refresh = now
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, NotImplementedError, OSError) as exc:
            log = LOGGER.debug if self._availability_warning_logged else LOGGER.warning
            log("Local process correlation unavailable: %s", exc)
            self._availability_warning_logged = True
            self._connections = {}
            return
        self._availability_warning_logged = False

        process_cache: dict[int, ProcessMetadata | None] = {}
        snapshot: dict[EndpointKey, ProcessMetadata] = {}
        for connection in connections:
            if connection.pid is None or not connection.laddr:
                continue
            protocol = _socket_protocol(connection.type)
            endpoint = _endpoint(connection.laddr)
            if protocol is None or endpoint is None:
                continue
            if connection.pid not in process_cache:
                process_cache[connection.pid] = _read_process(connection.pid)
            process = process_cache[connection.pid]
            if process is not None:
                snapshot[(endpoint[0], endpoint[1], protocol)] = process
        self._connections = snapshot

    def _match(self, packet: PacketMetadata) -> ProcessMetadata | None:
        protocol = packet.protocol.upper()
        source = (packet.source_ip.split("%", 1)[0], packet.source_port, protocol)
        destination = (
            packet.destination_ip.split("%", 1)[0],
            packet.destination_port,
            protocol,
        )
        return self._connections.get(source) or self._connections.get(destination)


def _read_process(process_id: int) -> ProcessMetadata | None:
    try:
        process = psutil.Process(process_id)
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return None
    try:
        process_name = process.name() or None
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
        process_name = None
    try:
        executable_path = process.exe() or None
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
        executable_path = None
    executable_name = basename(executable_path) if executable_path else None
    return ProcessMetadata(process_id, process_name, executable_name)


def _endpoint(address: object) -> tuple[str, int] | None:
    try:
        ip_address = str(address.ip)  # type: ignore[attr-defined]
        port = int(address.port)  # type: ignore[attr-defined]
    except AttributeError:
        try:
            ip_address, port = address[0], address[1]  # type: ignore[index]
        except (IndexError, TypeError, ValueError):
            return None
    return str(ip_address).split("%", 1)[0], int(port)


def _socket_protocol(socket_type: int) -> str | None:
    if socket_type == socket.SOCK_STREAM:
        return "TCP"
    if socket_type == socket.SOCK_DGRAM:
        return "UDP"
    return None
