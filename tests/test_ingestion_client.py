from datetime import datetime, timezone
import json
import threading

import httpx

from collector.flows import NetworkFlow
from collector.ingest import DNSIngestionClient, FlowIngestionClient
from collector.models import DNSMetadata


def flow(size: int = 512) -> NetworkFlow:
    now = datetime.now(timezone.utc)
    return NetworkFlow(
        first_seen=now,
        last_seen=now,
        packets_sent=4,
        bytes_sent=size,
        source_ip="192.0.2.10",
        destination_ip="198.51.100.20",
        source_port=51000,
        destination_port=443,
        protocol="TCP",
        process_id=42,
        process_name="chrome.exe",
        executable_name="chrome.exe",
    )


def test_temporary_failure_is_retried_with_same_idempotency_key() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        status = 503 if len(requests) == 1 else 202
        return httpx.Response(status, json={"accepted": 1, "duplicate": False})

    client = FlowIngestionClient(
        "http://backend.test",
        "11111111-1111-4111-8111-111111111111",
        "secret-key",
        max_retries=2,
        retry_backoff_seconds=0,
        transport=httpx.MockTransport(handler),
    )
    try:
        assert client.send_batch([flow()]) is True
    finally:
        client.stop()

    assert len(requests) == 2
    first_payload = json.loads(requests[0].content)
    second_payload = json.loads(requests[1].content)
    assert first_payload["batch_id"] == second_payload["batch_id"]
    assert first_payload["flows"][0]["bytes"] == 512
    assert first_payload["flows"][0]["process_id"] == 42
    assert first_payload["flows"][0]["process_name"] == "chrome.exe"
    assert requests[0].headers["X-API-Key"] == "secret-key"
    assert requests[0].headers["X-Agent-ID"] == "11111111-1111-4111-8111-111111111111"


def test_permanent_auth_failure_is_not_retried() -> None:
    attempts = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(401)

    client = FlowIngestionClient(
        "http://backend.test",
        "11111111-1111-4111-8111-111111111111",
        "wrong-key",
        max_retries=3,
        retry_backoff_seconds=0,
        transport=httpx.MockTransport(handler),
    )
    try:
        assert client.send_batch([flow()]) is False
    finally:
        client.stop()

    assert attempts == 1


def test_background_worker_batches_finalized_flows() -> None:
    delivered = threading.Event()
    batch_sizes: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        batch_sizes.append(len(json.loads(request.content)["flows"]))
        delivered.set()
        return httpx.Response(202, json={"accepted": 2, "duplicate": False})

    client = FlowIngestionClient(
        "http://backend.test",
        "11111111-1111-4111-8111-111111111111",
        "secret-key",
        batch_size=2,
        flush_interval_seconds=0.05,
        transport=httpx.MockTransport(handler),
    )
    client.start()
    client.enqueue(flow(100))
    client.enqueue(flow(200))
    assert delivered.wait(timeout=1)
    client.stop()

    assert batch_sizes == [2]


def test_full_queue_does_not_block_capture() -> None:
    client = FlowIngestionClient(
        "http://backend.test",
        "11111111-1111-4111-8111-111111111111",
        "secret-key",
        max_queue_size=1,
        transport=httpx.MockTransport(lambda _: httpx.Response(202)),
    )
    try:
        assert client.enqueue(flow()) is True
        assert client.enqueue(flow()) is False
    finally:
        client.stop()


def test_dns_metadata_uses_separate_authenticated_ingestion_contract() -> None:
    requests: list[httpx.Request] = []
    client = DNSIngestionClient(
        "http://backend.test",
        "11111111-1111-4111-8111-111111111111",
        "secret-key",
        transport=httpx.MockTransport(
            lambda request: requests.append(request) or httpx.Response(202)
        ),
    )
    observation = DNSMetadata(
        requesting_host="192.168.1.20",
        queried_domain="example.com",
        timestamp=datetime.now(timezone.utc),
        query_type="A",
        response_status=None,
        is_response=False,
        network_interface="Ethernet",
    )
    try:
        assert client.send_batch([observation]) is True
    finally:
        client.stop()

    payload = json.loads(requests[0].content)
    assert requests[0].url.path == "/api/ingest/dns"
    assert requests[0].headers["X-API-Key"] == "secret-key"
    assert payload["observations"] == [
        {
            "requesting_host": "192.168.1.20",
            "queried_domain": "example.com",
            "timestamp": observation.timestamp.isoformat(),
            "query_type": "A",
            "response_status": None,
            "is_response": False,
        }
    ]
