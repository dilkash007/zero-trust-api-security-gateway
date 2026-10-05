"""FastAPI WebSocket endpoint for authenticated real-time security events (Step 10)."""

import logging
from typing import Optional
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status
from jose import JWTError

from app.auth.jwt import decode_access_token
from app.database.connection import SessionLocal
from app.database.models import User
from app.websocket.manager import connection_manager

logger = logging.getLogger("zero_trust.websocket.routes")

websocket_router = APIRouter(tags=["WebSocket (Step 10)"])


@websocket_router.websocket("/ws/security")
async def websocket_security_stream(
    websocket: WebSocket,
    token: Optional[str] = Query(None, description="JWT bearer token for WebSocket authentication"),
):
    """Authenticated WebSocket stream delivering real-time SOC security events.

    Authentication:
    - Validates JWT signature, expiration, and user account status.
    - Rejects unauthenticated or forged connection attempts immediately with code 1008 (Policy Violation).

    RBAC:
    - ADMIN users receive global organization-wide telemetry.
    - USER accounts receive strictly their own events.
    """
    if not token:
        logger.warning("[WS AUTH REJECTED] Missing JWT token on /ws/security connection attempt.")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Verify JWT and extract claims
    db = SessionLocal()
    try:
        payload = decode_access_token(token)
        user_id_raw = payload.get("sub")
        if not user_id_raw:
            logger.warning("[WS AUTH REJECTED] Token payload missing 'sub' claim.")
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        user_id = int(user_id_raw)
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_active:
            logger.warning("[WS AUTH REJECTED] User id %s not found or inactive.", user_id)
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        # Snapshot verified credentials
        verified_user_id = user.id
        verified_username = getattr(user, "username", getattr(user, "email", str(user.id)))
        verified_role = user.role.value if hasattr(user.role, "value") else str(user.role)
    except (JWTError, ValueError) as exc:
        logger.warning("[WS AUTH REJECTED] Invalid or expired JWT token: %s", exc)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    finally:
        db.close()

    # Register authenticated client
    record = await connection_manager.connect(
        websocket=websocket,
        user_id=verified_user_id,
        username=verified_username,
        role=verified_role,
    )

    try:
        while True:
            # Receive client messages (e.g. heartbeat PINGs)
            data_text = await websocket.receive_text()
            await connection_manager.handle_client_message(websocket, data_text)
    except WebSocketDisconnect:
        logger.debug("[WS DISCONNECT] Client gracefully disconnected: user_id=%s", verified_user_id)
    except Exception as exc:
        logger.debug("[WS EXCEPTION] Socket read loop ended: %s", exc)
    finally:
        await connection_manager.disconnect(websocket)
