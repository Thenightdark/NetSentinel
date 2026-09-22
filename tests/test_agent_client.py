import json
from pathlib import Path

import httpx

from collector.agent import AgentClient


def test_agent_enrolls_once_and_reuses_saved_identity(tmp_path: Path) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        body = json.loads(request.content)
        return httpx.Response(201, json={"agent_id": body["agent_id"], "api_key": "unique-agent-key"})

    state_path = tmp_path / "agent.json"
    client = AgentClient("http://backend.test", "enrollment-key", state_path, transport=httpx.MockTransport(handler))
    first = client.ensure_registered()
    second = client.ensure_registered()
    client.stop()

    assert first == second
    assert len(requests) == 1
    assert requests[0].headers["X-API-Key"] == "enrollment-key"
    assert json.loads(state_path.read_text())["api_key"] == "unique-agent-key"


def test_agent_heartbeat_uses_unique_identity_and_tolerates_failure(tmp_path: Path) -> None:
    requests: list[httpx.Request] = []
    client = AgentClient(
        "http://backend.test",
        None,
        tmp_path / "agent.json",
        transport=httpx.MockTransport(lambda request: requests.append(request) or httpx.Response(503)),
    )
    credentials = type("Credentials", (), {"agent_id": "agent-id", "api_key": "agent-key"})()
    assert client.heartbeat(credentials) is False
    client.stop()
    assert requests[0].headers["X-Agent-ID"] == "agent-id"
    assert requests[0].headers["X-API-Key"] == "agent-key"
