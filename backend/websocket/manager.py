import asyncio
from contextlib import suppress

from fastapi import WebSocket

from backend.schemas import LiveUpdate


class LiveConnectionManager:
    """Fan out coalesced flow snapshots at a browser-safe rate."""

    def __init__(self, throttle_seconds: float = 0.5) -> None:
        self.throttle_seconds = throttle_seconds
        self.connections: set[WebSocket] = set()
        self._pending: LiveUpdate | None = None
        self._flush_task: asyncio.Task[None] | None = None

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.connections.discard(websocket)

    def queue(self, update: LiveUpdate) -> None:
        if not self.connections:
            return
        if self._pending is not None:
            known_ids = {flow.id for flow in update.completed_flows}
            update.completed_flows.extend(
                flow
                for flow in self._pending.completed_flows
                if flow.id not in known_ids
            )
            update.completed_flows = update.completed_flows[:25]
        self._pending = update
        if self._flush_task is None or self._flush_task.done():
            self._flush_task = asyncio.create_task(self._flush())

    async def _flush(self) -> None:
        await asyncio.sleep(self.throttle_seconds)
        update, self._pending = self._pending, None
        if update is None:
            return
        message = update.model_dump(mode="json")
        stale: list[WebSocket] = []
        for websocket in tuple(self.connections):
            try:
                await websocket.send_json(message)
            except Exception:
                stale.append(websocket)
        for websocket in stale:
            self.disconnect(websocket)

    async def close(self) -> None:
        if self._flush_task is not None and not self._flush_task.done():
            self._flush_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._flush_task
        for websocket in tuple(self.connections):
            with suppress(Exception):
                await websocket.close()
        self.connections.clear()
        self._pending = None


live_manager = LiveConnectionManager()
