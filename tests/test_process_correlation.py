from datetime import datetime, timezone
import socket
from types import SimpleNamespace

import psutil

from collector.models import PacketMetadata
from collector.processes import ProcessConnectionCorrelator


def packet() -> PacketMetadata:
    return PacketMetadata(
        timestamp=datetime.now(timezone.utc),
        source_ip="192.168.1.5",
        destination_ip="142.250.1.1",
        source_port=52321,
        destination_port=443,
        protocol="TCP",
        packet_size=128,
        tcp_flags="A",
        network_interface="Ethernet",
    )


def test_disabled_correlation_does_not_query_os(monkeypatch) -> None:
    monkeypatch.setattr(
        psutil,
        "net_connections",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("must not be called")),
    )

    original = packet()
    assert ProcessConnectionCorrelator(enabled=False).enrich(original) is original


def test_matches_local_endpoint_and_uses_executable_basename(monkeypatch) -> None:
    connection = SimpleNamespace(
        pid=42,
        laddr=SimpleNamespace(ip="192.168.1.5", port=52321),
        type=socket.SOCK_STREAM,
    )
    process = SimpleNamespace(
        name=lambda: "chrome.exe",
        exe=lambda: "C:\\Program Files\\Google\\Chrome\\chrome.exe",
    )
    monkeypatch.setattr(psutil, "net_connections", lambda **_kwargs: [connection])
    monkeypatch.setattr(psutil, "Process", lambda _pid: process)

    enriched = ProcessConnectionCorrelator(enabled=True).enrich(packet())

    assert enriched.process_id == 42
    assert enriched.process_name == "chrome.exe"
    assert enriched.executable_name == "chrome.exe"


def test_permission_failure_returns_original_metadata(monkeypatch) -> None:
    monkeypatch.setattr(
        psutil,
        "net_connections",
        lambda **_kwargs: (_ for _ in ()).throw(psutil.AccessDenied(pid=42)),
    )
    original = packet()

    enriched = ProcessConnectionCorrelator(enabled=True).enrich(original)

    assert enriched is original
    assert enriched.process_id is None


def test_executable_permission_failure_preserves_pid_and_process_name(monkeypatch) -> None:
    connection = SimpleNamespace(
        pid=42,
        laddr=("192.168.1.5", 52321),
        type=socket.SOCK_STREAM,
    )

    def denied_executable() -> str:
        raise psutil.AccessDenied(pid=42)

    process = SimpleNamespace(name=lambda: "browser", exe=denied_executable)
    monkeypatch.setattr(psutil, "net_connections", lambda **_kwargs: [connection])
    monkeypatch.setattr(psutil, "Process", lambda _pid: process)

    enriched = ProcessConnectionCorrelator(enabled=True).enrich(packet())

    assert enriched.process_id == 42
    assert enriched.process_name == "browser"
    assert enriched.executable_name is None
