from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.websocket.manager import live_manager

router = APIRouter()


@router.websocket("/ws/live")
async def live_stream(websocket: WebSocket) -> None:
    await live_manager.connect(websocket)
    await websocket.send_json(
        {
            "type": "connection.ready",
            "message": "NetSentinel live flow stream connected",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
    try:
        while True:
            message = await websocket.receive_text()
            if message == "ping":
                await websocket.send_json(
                    {
                        "type": "connection.heartbeat",
                        "message": "pong",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
    except WebSocketDisconnect:
        live_manager.disconnect(websocket)


@router.websocket("/ws/events")
async def legacy_event_stream(websocket: WebSocket) -> None:
    """Compatibility alias for dashboard clients configured before /ws/live."""
    await live_stream(websocket)
