"""WebSocket Connection Manager for real-time security telemetry distribution (Step 10).

Maintains active client connections with strict Role-Based Access Control (RBAC):
- ADMIN users receive global security events, threats, and traffic telemetry.
- Standard USER accounts receive strictly their own scoped security events.
- Automatic disconnection cleanup, stale connection reaping, and heartbeat support.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import WebSocket, WebSocketDisconnect

from app.websocket.schemas import WebSocketEventType, WebSocketMessage, sanitize_payload

logger = logging.getLogger("zero_trust.websocket")


class ConnectionRecord:
    """Represents an active, authenticated WebSocket client session."""

    def __init__(self, websocket: WebSocket, user_id: int, username: str, role: str):
        self.websocket = websocket
        self.user_id = user_id
        self.username = username
        self.role = role.upper()
        self.connected_at = datetime.now(timezone.utc)


class ConnectionManager:
    """Thread-safe WebSocket connection registry and event broadcaster."""

    def __init__(self):
        self._connections: List[ConnectionRecord] = []
        self._lock = asyncio.Lock()

    @property
    def active_count(self) -> int:
        """Returns the number of active connected clients."""
        return len(self._connections)

    async def connect(
        self,
        websocket: WebSocket,
        user_id: int,
        username: str,
        role: str,
    ) -> ConnectionRecord:
        """Accepts the WebSocket connection and registers the authenticated client session."""
        await websocket.accept()
        record = ConnectionRecord(
            websocket=websocket,
            user_id=user_id,
            username=username,
            role=role,
        )
        async with self._lock:
            # Prevent duplicate registration of the same websocket instance
            self._connections = [c for c in self._connections if c.websocket != websocket]
            self._connections.append(record)

        logger.info(
            "[WS CONNECT] Client connected: user_id=%s, username='%s', role=%s (Total active: %d)",
            user_id,
            username,
            role,
            len(self._connections),
        )

        # Send immediate initial handshake acknowledgment
        ack_message = WebSocketMessage(
            type=WebSocketEventType.SYSTEM_STATUS.value,
            data={
                "status": "connected",
                "role": role,
                "user_id": user_id,
                "message": "Zero-Trust Real-time Telemetry Stream active.",
            },
        ).model_dump()
        await self.send_personal(ack_message, websocket)
        return record

    async def disconnect(self, websocket: WebSocket) -> None:
        """Removes a WebSocket client from the active registry."""
        async with self._lock:
            initial_count = len(self._connections)
            self._connections = [c for c in self._connections if c.websocket != websocket]
            removed = initial_count - len(self._connections)

        if removed > 0:
            logger.info("[WS DISCONNECT] Client session closed. (Remaining active: %d)", len(self._connections))

    async def send_personal(self, message: Dict[str, Any], websocket: WebSocket) -> bool:
        """Safely sends a message to a specific WebSocket client."""
        try:
            payload_str = json.dumps(message)
            await websocket.send_text(payload_str)
            return True
        except Exception as exc:
            logger.debug("[WS SEND FAILED] Could not send to client: %s", exc)
            await self.disconnect(websocket)
            return False

    async def broadcast(
        self,
        event_type: str,
        data: Dict[str, Any],
        user_id: Optional[int] = None,
    ) -> int:
        """Broadcasts a standardized event to authorized WebSocket clients.

        RBAC Enforcement:
        - ADMIN clients always receive all events (global SOC visibility).
        - USER clients receive events ONLY if event user_id matches client user_id.
        - Clients with stale or disconnected sockets are safely cleaned up.
        """
        sanitized_data = sanitize_payload(data)
        message = WebSocketMessage(
            type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            data=sanitized_data,
        ).model_dump()

        message_str = json.dumps(message)
        stale_sockets: List[WebSocket] = []
        sent_count = 0

        # Snapshot current connection list under read lock
        async with self._lock:
            current_connections = list(self._connections)

        for record in current_connections:
            # RBAC check: ADMIN sees everything; USER only sees their own events
            is_admin = record.role == "ADMIN"
            is_target_user = user_id is not None and record.user_id == user_id

            if is_admin or is_target_user:
                try:
                    await record.websocket.send_text(message_str)
                    sent_count += 1
                except (WebSocketDisconnect, RuntimeError, Exception) as exc:
                    logger.debug("[WS BROADCAST] Dropping dead connection: %s", exc)
                    stale_sockets.append(record.websocket)

        # Purge any dropped/stale connections
        if stale_sockets:
            async with self._lock:
                self._connections = [
                    c for c in self._connections if c.websocket not in stale_sockets
                ]

        return sent_count

    async def handle_client_message(self, websocket: WebSocket, text: str) -> None:
        """Handles inbound client messages (such as heartbeat PINGs)."""
        try:
            data = json.loads(text)
            msg_type = data.get("type", "").upper()
            if msg_type == WebSocketEventType.PING.value:
                pong = WebSocketMessage(
                    type=WebSocketEventType.PONG.value,
                    data={"echo": data.get("data", {})},
                ).model_dump()
                await self.send_personal(pong, websocket)
        except Exception:
            # Silently ignore non-JSON or malformed client frames
            pass


# Global singleton connection manager instance
connection_manager = ConnectionManager()
