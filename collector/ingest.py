"""Reliable, non-blocking delivery of finalized flows to the backend API."""

from dataclasses import dataclass
import logging
from queue import Empty, Full, Queue
import threading
from time import monotonic
from typing import Literal
from uuid import UUID, uuid4

import httpx

from .flows import NetworkFlow

LOGGER = logging.getLogger(__name__)
DeliveryOutcome = Literal["success", "temporary_failure", "permanent_failure"]


@dataclass(frozen=True, slots=True)
class PendingBatch:
    batch_id: UUID
    flows: list[NetworkFlow]


class FlowIngestionClient:
    """Queue and batch finalized flows without blocking packet capture."""

    TEMPORARY_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}

    def __init__(
        self,
        backend_url: str,
        api_key: str,
        *,
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

        self.batch_size = batch_size
        self.flush_interval_seconds = flush_interval_seconds
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.retry_backoff_seconds = retry_backoff_seconds
        self._queue: Queue[NetworkFlow] = Queue(maxsize=max_queue_size)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._client = httpx.Client(
            base_url=backend_url.rstrip("/"),
            headers={"X-API-Key": api_key},
            timeout=httpx.Timeout(timeout_seconds),
            transport=transport,
        )

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._worker,
            name="netsentinel-flow-ingestion",
            daemon=True,
        )
        self._thread.start()

    def enqueue(self, flow: NetworkFlow) -> bool:
        try:
            self._queue.put_nowait(flow)
            return True
        except Full:
            LOGGER.error(
                "Flow delivery queue is full; dropping finalized flow to protect capture continuity"
            )
            return False

    def send_batch(self, flows: list[NetworkFlow], batch_id: UUID | None = None) -> bool:
        """Synchronously send one batch; primarily useful for diagnostics and tests."""
        if not flows:
            return True
        pending = PendingBatch(batch_id or uuid4(), flows)
        return self._deliver_batch(pending) == "success"

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
                LOGGER.error("Flow ingestion worker did not stop before its deadline")
                return
            self._thread = None
        self._client.close()

    def _worker(self) -> None:
        pending: PendingBatch | None = None
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
                    "Backend remained unavailable during shutdown; dropping %d queued flows",
                    len(pending.flows),
                )
            for _ in pending.flows:
                self._queue.task_done()
            pending = None

    def _next_batch(self) -> PendingBatch | None:
        try:
            first = self._queue.get(timeout=self.flush_interval_seconds)
        except Empty:
            return None

        flows = [first]
        deadline = monotonic() + self.flush_interval_seconds
        while len(flows) < self.batch_size:
            remaining = deadline - monotonic()
            if remaining <= 0:
                break
            try:
                flows.append(self._queue.get(timeout=remaining))
            except Empty:
                break
        return PendingBatch(uuid4(), flows)

    def _deliver_batch(self, pending: PendingBatch) -> DeliveryOutcome:
        payload = {
            "batch_id": str(pending.batch_id),
            "flows": [_serialize_flow(flow) for flow in pending.flows],
        }
        for attempt in range(self.max_retries + 1):
            try:
                response = self._client.post("/api/ingest/flows", json=payload)
            except httpx.RequestError as exc:
                LOGGER.warning("Flow ingestion request failed: %s", exc)
                outcome: DeliveryOutcome = "temporary_failure"
            else:
                if response.is_success:
                    LOGGER.info("Delivered %d finalized flows", len(pending.flows))
                    return "success"
                if response.status_code not in self.TEMPORARY_STATUS_CODES:
                    LOGGER.error(
                        "Flow ingestion rejected with HTTP %d; batch will not be retried",
                        response.status_code,
                    )
                    return "permanent_failure"
                LOGGER.warning(
                    "Temporary flow ingestion failure: HTTP %d", response.status_code
                )
                outcome = "temporary_failure"

            if attempt < self.max_retries:
                delay = self.retry_backoff_seconds * (2**attempt)
                if self._stop_event.wait(delay):
                    break
        return outcome


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
    }

