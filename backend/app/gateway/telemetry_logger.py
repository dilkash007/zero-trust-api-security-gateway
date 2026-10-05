"""Telemetry logger module for storing API request logs and security events in PostgreSQL."""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional
import uuid

from app.database.connection import SessionLocal
from app.database.models import (
    ApiRequestLog,
    EventSeverity,
    SecurityEvent,
    SecurityEventType,
)

logger = logging.getLogger("zero_trust.telemetry")


def persist_telemetry(
    request_id: str,
    method: str,
    endpoint: str,
    client_ip: str,
    user_agent: str,
    status_code: int,
    response_time_ms: float,
    request_size: int = 0,
    response_size: int = 0,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    role: Optional[str] = None,
    is_authenticated: bool = False,
    is_sensitive: bool = False,
    security_event_type: Optional[str] = None,
    security_event_severity: Optional[str] = None,
    security_event_message: Optional[str] = None,
    security_event_metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Safely persists an API request log and associated security event to PostgreSQL.

    Catches database exceptions to prevent telemetry failures from interrupting the client response.
    Never persists credentials, JWTs, or Authorization headers.
    """
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)

        # 1. Create API Request Log record
        log_entry = ApiRequestLog(
            request_id=request_id,
            user_id=user_id,
            username=username,
            role=role,
            client_ip=client_ip,
            user_agent=user_agent,
            method=method,
            endpoint=endpoint,
            timestamp=now,
            status_code=status_code,
            response_time_ms=response_time_ms,
            request_size=request_size,
            response_size=response_size,
            is_authenticated=is_authenticated,
            is_sensitive=is_sensitive,
        )
        db.add(log_entry)

        # 2. Optionally create Security Event record
        if security_event_type:
            event_id = str(uuid.uuid4())
            sec_event = SecurityEvent(
                event_id=event_id,
                request_id=request_id,
                user_id=user_id,
                event_type=security_event_type,
                severity=security_event_severity or EventSeverity.INFO.value,
                message=security_event_message or security_event_type,
                endpoint=endpoint,
                timestamp=now,
                event_metadata=security_event_metadata or {},
            )
            db.add(sec_event)

        db.commit()
    except Exception as exc:
        db.rollback()
        logger.error(
            "Failed to persist security telemetry for request %s on %s: %s",
            request_id,
            endpoint,
            type(exc).__name__,
        )
    finally:
        db.close()
