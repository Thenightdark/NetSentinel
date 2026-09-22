"""Reliable, non-blocking delivery of normalized metadata to the backend API."""

from collections.abc import Callable
from dataclasses import dataclass
import logging
from queue import Empty, Full, Queue
import threading
from time import monotonic
from typing import Generic, Literal, TypeVar
from uuid import UUID, uuid4

import httpx

from .flows import NetworkFlow
from .models import DNSMetadata

LOGGER = logging.getLogger(__name__)
DeliveryOutcome = Literal["success", "temporary_failure", "permanent_failure"]
ItemT = TypeVar("ItemT")


@dataclass(frozen=True, slots=True)
class PendingBatch(Generic[ItemT]):
    batch_id: UUID
    items: list[ItemT]


class BatchIngestionClient(Generic[ItemT]):
    """Queue and batch metadata without blocking passive packet capture."""

    TEMPORARY_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}

    def __init__(
        self,
        backend_url: str,
        agent_id: str,
        api_key: str,
        *,
        endpoint: str,
        payload_key: str,
        serializer: Callable[[ItemT], dict[str, object]],
        item_label: str,
        thread_name: str,
        batch_size: int = 100,
        flush_interval_seconds: float = 2.0,
        timeout_seconds: float = 5.0,
        max_retries: int = 3,
        retry_backoff_seconds: float = 0.5,
        max_queue_size: int = 5_000,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if batch_size <= 0 or max_queue_size <= 0:
            raise ValueError("batch and queue sizes must be greater than zero")
        if flush_interval_seconds <= 0 or timeout_seconds <= 0:
            raise ValueError("flush interval and timeout must be greater than zero")
        if max_retries < 0 or retry_backoff_seconds < 0:
            raise ValueError("retry settings cannot be negative")

        self.endpoint = endpoint
        self.payload_key = payload_key
        self.serializer = serializer
        self.item_label = item_label
        self.thread_name = thread_name
        self.batch_size = batch_size
        self.flush_interval_seconds = flush_interval_seconds
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.retry_backoff_seconds = retry_backoff_seconds
        self._queue: Queue[ItemT] = Queue(maxsize=max_queue_size)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._client = httpx.Client(
            base_url=backend_url.rstrip("/"),
            headers={"X-Agent-ID": agent_id, "X-API-Key": api_key},
            timeout=httpx.Timeout(timeout_seconds),
            transport=transport,
        )

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._worker,
            name=self.thread_name,
            daemon=True,
        )
        self._thread.start()

    def enqueue(self, item: ItemT) -> bool:
        try:
            self._queue.put_nowait(item)
            return True
        except Full:
            LOGGER.error(
                "%s delivery queue is full; dropping metadata to protect capture continuity",
                self.item_label,
            )
            return False

    def send_batch(self, items: list[ItemT], batch_id: UUID | None = None) -> bool:
        if not items:
            return True
        return self._deliver_batch(PendingBatch(batch_id or uuid4(), items)) == "success"

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            maximum_wait = (
                self.flush_interval_seconds
                + (self.timeout_seconds * (self.max_retries + 1))
                + sum(
                    self.retry_backoff_seconds * (2**attempt)
                    for attempt in range(self.max_retries)
                )
                + 1.0
            )
            self._thread.join(timeout=maximum_wait)
            if self._thread.is_alive():
                LOGGER.error("%s ingestion worker did not stop before its deadline", self.item_label)
                return
            self._thread = None
        self._client.close()

    def _worker(self) -> None:
        pending: PendingBatch[ItemT] | None = None
        while True:
            if pending is None:
                pending = self._next_batch()
                if pending is None:
                    if self._stop_event.is_set():
                        return
                    continue
            outcome = self._deliver_batch(pending)
            if outcome == "temporary_failure" and not self._stop_event.is_set():
                self._stop_event.wait(self.flush_interval_seconds)
                continue
            if outcome == "temporary_failure":
                LOGGER.error(
                    "Backend remained unavailable during shutdown; dropping %d queued %s items",
                    len(pending.items),
                    self.item_label,
                )
            for _ in pending.items:
                self._queue.task_done()
            pending = None

    def _next_batch(self) -> PendingBatch[ItemT] | None:
        try:
            first = self._queue.get(timeout=self.flush_interval_seconds)
        except Empty:
            return None
        items = [first]
        deadline = monotonic() + self.flush_interval_seconds
        while len(items) < self.batch_size:
            remaining = deadline - monotonic()
            if remaining <= 0:
                break
            try:
                items.append(self._queue.get(timeout=remaining))
            except Empty:
                break
        return PendingBatch(uuid4(), items)

    def _deliver_batch(self, pending: PendingBatch[ItemT]) -> DeliveryOutcome:
        payload = {
            "batch_id": str(pending.batch_id),
            self.payload_key: [self.serializer(item) for item in pending.items],
        }
        outcome: DeliveryOutcome = "temporary_failure"
        for attempt in range(self.max_retries + 1):
            try:
                response = self._client.post(self.endpoint, json=payload)
            except httpx.RequestError as exc:
                LOGGER.warning("%s ingestion request failed: %s", self.item_label, exc)
                outcome = "temporary_failure"
            else:
                if response.is_success:
                    LOGGER.info("Delivered %d %s items", len(pending.items), self.item_label)
                    return "success"
                if response.status_code not in self.TEMPORARY_STATUS_CODES:
                    LOGGER.error(
                        "%s ingestion rejected with HTTP %d; batch will not be retried",
                        self.item_label,
                        response.status_code,
                    )
                    return "permanent_failure"
                LOGGER.warning(
                    "Temporary %s ingestion failure: HTTP %d",
                    self.item_label,
                    response.status_code,
                )
                outcome = "temporary_failure"
            if attempt < self.max_retries:
                delay = self.retry_backoff_seconds * (2**attempt)
                if self._stop_event.wait(delay):
                    break
        return outcome


class FlowIngestionClient(BatchIngestionClient[NetworkFlow]):
    def __init__(self, backend_url: str, agent_id: str, api_key: str, **kwargs: object) -> None:
        super().__init__(
            backend_url,
            agent_id,
            api_key,
            endpoint="/api/ingest/flows",
            payload_key="flows",
            serializer=_serialize_flow,
            item_label="flow",
            thread_name="netsentinel-flow-ingestion",
            **kwargs,
        )


class DNSIngestionClient(BatchIngestionClient[DNSMetadata]):
    def __init__(self, backend_url: str, agent_id: str, api_key: str, **kwargs: object) -> None:
        super().__init__(
            backend_url,
            agent_id,
            api_key,
            endpoint="/api/ingest/dns",
            payload_key="observations",
            serializer=_serialize_dns,
            item_label="DNS metadata",
            thread_name="netsentinel-dns-ingestion",
            **kwargs,
        )


def _serialize_flow(flow: NetworkFlow) -> dict[str, object]:
    return {
        "source_ip": flow.source_ip,
        "destination_ip": flow.destination_ip,
        "source_port": flow.source_port,
        "destination_port": flow.destination_port,
        "protocol": flow.protocol,
        "bytes": flow.bytes_sent,
        "packet_count": flow.packets_sent,
        "first_seen": flow.first_seen.isoformat(),
        "last_seen": flow.last_seen.isoformat(),
        "process_id": flow.process_id,
        "process_name": flow.process_name,
        "executable_name": flow.executable_name,
    }


def _serialize_dns(observation: DNSMetadata) -> dict[str, object]:
    return {
        "requesting_host": observation.requesting_host,
        "queried_domain": observation.queried_domain,
        "timestamp": observation.timestamp.isoformat(),
        "query_type": observation.query_type,
        "response_status": observation.response_status,
        "is_response": observation.is_response,
    }
