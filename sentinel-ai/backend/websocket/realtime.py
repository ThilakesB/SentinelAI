"""
backend/websocket/realtime.py
==============================
WebSocket endpoint: WS /ws/realtime

Authenticated via JWT query param (?token=...) since WS doesn't support
Authorization headers in most browser clients.

Push events shape:
  {
    "type": "threat" | "process" | "network" | "response",
    "data": { ... }
  }

All connected clients receive every event. The monitoring collector pushes
events via set_ws_queue() at startup. This module owns the broadcast queue.
"""
from __future__ import annotations

import asyncio
import json
from typing import Set

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from starlette.websockets import WebSocketState

from backend.auth.service import decode_jwt

logger = structlog.get_logger(__name__)

router = APIRouter()

# Broadcast queue: monitoring collector pushes here, broadcaster reads here
_ws_broadcast_queue: asyncio.Queue = asyncio.Queue(maxsize=50_000)
_connected_clients: Set[WebSocket] = set()


@router.websocket("/ws/realtime")
async def realtime(websocket: WebSocket) -> None:
    """
    Authenticated WebSocket endpoint.
    Clients must pass ?token=<JWT> as a query parameter.
    """
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    payload = decode_jwt(token)
    if not payload:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    _connected_clients.add(websocket)
    logger.info("ws_client_connected", user=payload.get("email"), total=len(_connected_clients))

    try:
        # Send a welcome message
        await websocket.send_text(json.dumps({
            "type": "connected",
            "data": {"message": "SentinelAI real-time feed connected.", "user": payload.get("email")},
        }))

        # Keep the connection alive — client can send ping frames
        while True:
            try:
                # Wait for client message (ping/pong or disconnect)
                await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                # Send a keepalive ping
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.send_text(json.dumps({"type": "ping"}))

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("ws_error", error=str(exc))
    finally:
        _connected_clients.discard(websocket)
        logger.info("ws_client_disconnected", remaining=len(_connected_clients))


async def broadcast_loop() -> None:
    """
    Background task: drains the broadcast queue and pushes events to all connected clients.
    Started once during app lifespan via asyncio.create_task().
    """
    while True:
        try:
            event = await asyncio.wait_for(_ws_broadcast_queue.get(), timeout=1.0)
            if not _connected_clients:
                _ws_broadcast_queue.task_done()
                continue

            message = json.dumps(event, default=str)
            dead_clients = set()

            for client in _connected_clients.copy():
                try:
                    await client.send_text(message)
                except Exception:
                    dead_clients.add(client)

            _connected_clients -= dead_clients
            _ws_broadcast_queue.task_done()

        except asyncio.TimeoutError:
            continue
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.debug("broadcast_error", error=str(exc))


def setup_ws_queue() -> asyncio.Queue:
    """
    Called during app startup to wire the broadcast queue into the monitoring collector.
    Returns the queue reference.
    """
    from monitoring.collector import set_ws_queue
    set_ws_queue(_ws_broadcast_queue)
    asyncio.create_task(broadcast_loop(), name="ws_broadcaster")
    return _ws_broadcast_queue
