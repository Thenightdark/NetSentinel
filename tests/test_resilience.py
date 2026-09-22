"""Collector delivery and WebSocket failures must remain isolated."""

import asyncio
from datetime import datetime, timezone

import httpx

from backend.schemas import LiveSummary, LiveUpdate, NetworkFlowRead
from backend.websocket.manager import LiveConnectionManager
from collector.agent import AgentClient, AgentCredentials
from collector.ingest import FlowIngestionClient


def test_backend_outage_does_not_make_ingestion_client_unusable(
    synthetic_collector_flow,
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls <= 2:
            raise httpx.ConnectError("backend offline", request=request)
        return httpx.Response(202, json={"accepted": 1, "duplicate": False})

    client = FlowIngestionClient(
        "http://backend.test",
        "11111111-1111-4111-8111-111111111111",
        "test-key",
        max_retries=1,
        retry_backoff_seconds=0,
        transport=httpx.MockTransport(handler),
    )
    try:
        assert client.send_batch([synthetic_collector_flow()]) is False
        assert client.send_batch([synthetic_collector_flow()]) is True
    finally:
        client.stop()

    assert calls == 3


def test_collector_heartbeat_recovers_after_disconnect(tmp_path) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.ConnectError("connection reset", request=request)
        return httpx.Response(200, json={"status": "ONLINE"})

    client = AgentClient(
        "http://backend.test",
        None,
        tmp_path / "agent.json",
        transport=httpx.MockTransport(handler),
    )
    credentials = AgentCredentials("agent-id", "agent-key")
    try:
        assert client.heartbeat(credentials) is False
        assert client.heartbeat(credentials) is True
    finally:
        client.stop()


class _FakeWebSocket:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.messages: list[dict[str, object]] = []
        self.closed = False

    async def send_json(self, message: dict[str, object]) -> None:
        if self.fail:
            raise RuntimeError("browser disconnected")
        self.messages.append(message)

    async def close(self) -> None:
        self.closed = True


def _live_update(flow_id: int) -> LiveUpdate:
    now = datetime.now(timezone.utc)
    flow = NetworkFlowRead(
        id=flow_id,
        agent_id="agent",
        source_ip="192.168.1.10",
        destination_ip="198.51.100.20",
        source_port=51_000,
        destination_port=443,
        protocol="TCP",
        process_id=None,
        process_name=None,
        executable_name=None,
        bytes=128,
        packet_count=1,
        first_seen=now,
        last_seen=now,
    )
    return LiveUpdate(
        timestamp=now,
        summary=LiveSummary(
            throughput_bps=128,
            active_connections=1,
            total_flows=flow_id,
            total_bytes=128,
            total_packets=1,
            protocols=[],
        ),
        recent_flows=[flow],
        completed_flows=[flow],
    )


def test_websocket_disconnect_is_removed_without_affecting_other_clients() -> None:
    async def scenario() -> None:
        manager = LiveConnectionManager(throttle_seconds=0)
        connected = _FakeWebSocket()
        disconnected = _FakeWebSocket(fail=True)
        manager.connections.update({connected, disconnected})  # type: ignore[arg-type]

        manager.queue(_live_update(1))
        await manager._flush_task

        assert connected.messages[0]["type"] == "live.update"
        assert disconnected not in manager.connections
        assert connected in manager.connections
        await manager.close()

    asyncio.run(scenario())


def test_websocket_throttle_coalesces_completed_flows() -> None:
    async def scenario() -> None:
        manager = LiveConnectionManager(throttle_seconds=0.01)
        connected = _FakeWebSocket()
        manager.connections.add(connected)  # type: ignore[arg-type]

        manager.queue(_live_update(1))
        manager.queue(_live_update(2))
        await manager._flush_task

        assert len(connected.messages) == 1
        completed = connected.messages[0]["completed_flows"]
        assert {item["id"] for item in completed} == {1, 2}  # type: ignore[index]
        assert connected.messages[0]["summary"]["total_flows"] == 2  # type: ignore[index]
        await manager.close()

    asyncio.run(scenario())

