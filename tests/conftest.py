"""Shared deterministic factories for synthetic network metadata.

The suite never needs live packet capture or real suspicious traffic.  Tests build
the smallest metadata objects required for the behavior under examination.
"""

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from backend.models import NetworkFlow
from collector.flows import NetworkFlow as CollectorFlow
from collector.models import PacketMetadata


SYNTHETIC_TIME = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def synthetic_packet() -> Callable[..., PacketMetadata]:
    def factory(**overrides: Any) -> PacketMetadata:
        values: dict[str, Any] = {
            "timestamp": SYNTHETIC_TIME,
            "source_ip": "192.168.10.10",
            "destination_ip": "198.51.100.20",
            "source_port": 51_000,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_size": 128,
            "tcp_flags": "A",
            "network_interface": "synthetic0",
        }
        values.update(overrides)
        return PacketMetadata(**values)

    return factory


@pytest.fixture
def synthetic_collector_flow() -> Callable[..., CollectorFlow]:
    def factory(**overrides: Any) -> CollectorFlow:
        values: dict[str, Any] = {
            "first_seen": SYNTHETIC_TIME - timedelta(seconds=1),
            "last_seen": SYNTHETIC_TIME,
            "packets_sent": 1,
            "bytes_sent": 128,
            "source_ip": "192.168.10.10",
            "destination_ip": "198.51.100.20",
            "source_port": 51_000,
            "destination_port": 443,
            "protocol": "TCP",
        }
        values.update(overrides)
        return CollectorFlow(**values)

    return factory


@pytest.fixture
def synthetic_database_flow() -> Callable[..., NetworkFlow]:
    def factory(**overrides: Any) -> NetworkFlow:
        values: dict[str, Any] = {
            "agent_id": "synthetic-agent",
            "source_ip": "192.168.10.10",
            "destination_ip": "198.51.100.20",
            "source_port": 51_000,
            "destination_port": 443,
            "protocol": "TCP",
            "bytes": 128,
            "packet_count": 1,
            "first_seen": SYNTHETIC_TIME - timedelta(seconds=1),
            "last_seen": SYNTHETIC_TIME,
        }
        values.update(overrides)
        return NetworkFlow(**values)

    return factory

