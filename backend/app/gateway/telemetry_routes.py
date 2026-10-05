"""Endpoints for retrieving persistent API request logs and security events (Admin only)."""

from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import ApiRequestLog, SecurityEvent
from app.gateway.dependencies import require_admin_only
from app.gateway.request_context import RequestContext

telemetry_router = APIRouter(prefix="/api", tags=["Security Telemetry & Events"])


@telemetry_router.get(
    "/requests",
    status_code=status.HTTP_200_OK,
    summary="Retrieve persistent API request logs (ADMIN only)",
)
def get_api_requests(
    limit: int = Query(50, ge=1, le=100, description="Max records to return (capped at 100)"),
    status_code: Optional[int] = Query(None, description="Filter by HTTP status code"),
    endpoint: Optional[str] = Query(None, description="Filter by requested endpoint path"),
    user_id: Optional[int] = Query(None, description="Filter by user ID"),
    is_sensitive: Optional[bool] = Query(None, description="Filter by sensitivity flag"),
    context: RequestContext = Depends(require_admin_only),
    db: Session = Depends(get_db),
):
    """Returns historical API request telemetry stored in PostgreSQL."""
    query = db.query(ApiRequestLog)

    if status_code is not None:
        query = query.filter(ApiRequestLog.status_code == status_code)
    if endpoint is not None:
        query = query.filter(ApiRequestLog.endpoint == endpoint)
    if user_id is not None:
        query = query.filter(ApiRequestLog.user_id == user_id)
    if is_sensitive is not None:
        query = query.filter(ApiRequestLog.is_sensitive == is_sensitive)

    logs = query.order_by(desc(ApiRequestLog.id)).limit(limit).all()

    formatted_data = [
        {
            "request_id": log.request_id,
            "user_id": log.user_id,
            "username": log.username,
            "role": log.role,
            "client_ip": log.client_ip,
            "method": log.method,
            "endpoint": log.endpoint,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "status_code": log.status_code,
            "response_time_ms": log.response_time_ms,
            "request_size": log.request_size or 0,
            "response_size": log.response_size or 0,
            "is_authenticated": log.is_authenticated,
            "is_sensitive": log.is_sensitive,
        }
        for log in logs
    ]

    return {
        "success": True,
        "data": formatted_data,
    }


@telemetry_router.get(
    "/security/events",
    status_code=status.HTTP_200_OK,
    summary="Retrieve persistent security events (ADMIN only)",
)
def get_security_events(
    limit: int = Query(50, ge=1, le=100, description="Max records to return (capped at 100)"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    context: RequestContext = Depends(require_admin_only),
    db: Session = Depends(get_db),
):
    """Returns persistent security audit events (auth failures, privilege violations, sensitive access)."""
    query = db.query(SecurityEvent)

    if event_type is not None:
        query = query.filter(SecurityEvent.event_type == event_type)
    if severity is not None:
        query = query.filter(SecurityEvent.severity == severity)

    events = query.order_by(desc(SecurityEvent.id)).limit(limit).all()

    formatted_data = [
        {
            "event_id": ev.event_id,
            "request_id": ev.request_id,
            "user_id": ev.user_id,
            "event_type": ev.event_type,
            "severity": ev.severity,
            "message": ev.message,
            "endpoint": ev.endpoint,
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            "metadata": ev.event_metadata or {},
        }
        for ev in events
    ]

    return {
        "success": True,
        "data": formatted_data,
    }
