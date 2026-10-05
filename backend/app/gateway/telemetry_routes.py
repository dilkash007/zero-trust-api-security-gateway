"""Endpoints for retrieving persistent API request logs and security events (Admin only)."""

import time
from typing import Optional
from fastapi import APIRouter, Depends, Query, status

from sqlalchemy import desc, or_
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
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    status_code: Optional[int] = Query(None, description="Filter by HTTP status code"),
    endpoint: Optional[str] = Query(None, description="Filter by requested endpoint path"),
    method: Optional[str] = Query(None, description="Filter by HTTP method"),
    risk_level: Optional[str] = Query(None, description="Filter by risk tier (LOW, MEDIUM, HIGH, CRITICAL)"),
    policy: Optional[str] = Query(None, description="Filter by policy decision (ALLOW, MONITOR, RATE_LIMIT, BLOCK)"),
    user_id: Optional[int] = Query(None, description="Filter by user ID"),
    is_sensitive: Optional[bool] = Query(None, description="Filter by sensitivity flag"),
    search: Optional[str] = Query(None, description="Search across request_id, endpoint, username, client_ip"),
    context: RequestContext = Depends(require_admin_only),
    db: Session = Depends(get_db),
):
    """Returns historical API request telemetry stored in PostgreSQL."""
    query = db.query(ApiRequestLog)

    if status_code is not None:
        query = query.filter(ApiRequestLog.status_code == status_code)
    if endpoint is not None:
        query = query.filter(ApiRequestLog.endpoint == endpoint)
    if method is not None:
        query = query.filter(ApiRequestLog.method == method.strip().upper())
    if risk_level is not None:
        query = query.filter(ApiRequestLog.risk_level == risk_level.strip().upper())
    if policy is not None:
        query = query.filter(ApiRequestLog.policy_decision == policy.strip().upper())
    if user_id is not None:
        query = query.filter(ApiRequestLog.user_id == user_id)
    if is_sensitive is not None:
        query = query.filter(ApiRequestLog.is_sensitive == is_sensitive)

    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                ApiRequestLog.request_id.ilike(search_term),
                ApiRequestLog.endpoint.ilike(search_term),
                ApiRequestLog.username.ilike(search_term),
                ApiRequestLog.client_ip.ilike(search_term),
            )
        )

    total_count = query.count()
    logs = query.order_by(desc(ApiRequestLog.id)).offset(offset).limit(limit).all()

    formatted_data = [
        {
            "request_id": log.request_id,
            "user_id": log.user_id,
            "username": log.username,
            "role": log.role,
            "client_ip": log.client_ip,
            "user_agent": log.user_agent,
            "method": log.method,
            "endpoint": log.endpoint,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "status_code": log.status_code,
            "response_time_ms": log.response_time_ms,
            "request_size": log.request_size or 0,
            "response_size": log.response_size or 0,
            "is_authenticated": log.is_authenticated,
            "is_sensitive": log.is_sensitive,
            "risk_score": log.risk_score,
            "risk_level": log.risk_level,
            "policy_decision": log.policy_decision,
            "risk_reasons": log.risk_reasons or [],
        }
        for log in logs
    ]

    return {
        "success": True,
        "total": total_count,
        "offset": offset,
        "limit": limit,
        "data": formatted_data,
    }


@telemetry_router.get(
    "/requests/{request_id}",
    status_code=status.HTTP_200_OK,
    summary="Retrieve full request details and correlated security events by Request ID",
)
def get_request_by_id(
    request_id: str,
    context: RequestContext = Depends(require_admin_only),
    db: Session = Depends(get_db),
):
    """Returns detailed audit record and all associated security events for a specific request ID."""
    log = db.query(ApiRequestLog).filter(ApiRequestLog.request_id == request_id).first()
    if not log:
        return {
            "success": False,
            "error": "Request ID not found",
        }

    # Correlated security events
    events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.request_id == request_id)
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    )

    correlated_events = [
        {
            "event_id": ev.event_id,
            "event_type": ev.event_type,
            "severity": ev.severity,
            "message": ev.message,
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            "metadata": ev.event_metadata or {},
        }
        for ev in events
    ]

    return {
        "success": True,
        "data": {
            "request_id": log.request_id,
            "user_id": log.user_id,
            "username": log.username,
            "role": log.role,
            "client_ip": log.client_ip,
            "user_agent": log.user_agent,
            "method": log.method,
            "endpoint": log.endpoint,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "status_code": log.status_code,
            "response_time_ms": log.response_time_ms,
            "request_size": log.request_size or 0,
            "response_size": log.response_size or 0,
            "is_authenticated": log.is_authenticated,
            "is_sensitive": log.is_sensitive,
            "risk_score": log.risk_score,
            "risk_level": log.risk_level,
            "policy_decision": log.policy_decision,
            "risk_reasons": log.risk_reasons or [],
            "correlated_events": correlated_events,
        },
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


@telemetry_router.post(
    "/security/block-ip",
    status_code=status.HTTP_200_OK,
    summary="Add an IP address to the active perimeter blocklist (ADMIN only)",
)
def block_ip_address(
    payload: dict,
    context: RequestContext = Depends(require_admin_only),
):
    """Instantly adds an IP to the gateway rate limiter block list."""
    from app.cache.redis_client import get_rate_limiter
    ip = payload.get("ip")
    duration = int(payload.get("duration", 86400))
    if not ip:
        return {"success": False, "error": "IP address is required"}

    rl = get_rate_limiter()
    rl.block_ip(ip, duration)
    return {
        "success": True,
        "message": f"IP {ip} blocked successfully for {duration} seconds",
        "ip": ip,
        "blocked_until_seconds": duration,
    }


@telemetry_router.post(
    "/security/unblock-ip",
    status_code=status.HTTP_200_OK,
    summary="Remove an IP from the perimeter blocklist (ADMIN only)",
)
def unblock_ip_address(
    payload: dict,
    context: RequestContext = Depends(require_admin_only),
):
    """Removes an IP from the rate limiter block list."""
    from app.cache.redis_client import get_rate_limiter
    ip = payload.get("ip")
    if not ip:
        return {"success": False, "error": "IP address is required"}

    rl = get_rate_limiter()
    rl.unblock_ip(ip)
    return {
        "success": True,
        "message": f"IP {ip} unblocked successfully",
        "ip": ip,
    }


@telemetry_router.get(
    "/security/blocked-ips",
    status_code=status.HTTP_200_OK,
    summary="List all currently blocked IPs (ADMIN only)",
)
def get_blocked_ips_list(
    context: RequestContext = Depends(require_admin_only),
):
    """Returns all active IPs currently in quarantine/blocklist."""
    from app.cache.redis_client import get_rate_limiter
    rl = get_rate_limiter()
    blocked = rl.get_blocked_ips()
    return {
        "success": True,
        "count": len(blocked),
        "blocked_ips": blocked,
    }


@telemetry_router.post(
    "/security/reset-limits",
    status_code=status.HTTP_200_OK,
    summary="Reset rate limiting and clear IP blocklists (ADMIN only)",
)
def reset_rate_limits(
    context: RequestContext = Depends(require_admin_only),
):
    """Clears in-memory sliding window counters and unblocks all quarantined IPs."""
    from app.cache.redis_client import get_rate_limiter
    rl = get_rate_limiter()
    rl.clear_all()
    return {
        "success": True,
        "message": "All rate-limit windows and blocked IPs have been successfully cleared.",
    }


@telemetry_router.get(
    "/telemetry/export",
    status_code=status.HTTP_200_OK,
    summary="Export recent API request logs and security events as JSON (ADMIN only)",
)
def export_telemetry(
    limit: int = Query(500, ge=1, le=2000),
    context: RequestContext = Depends(require_admin_only),
    db: Session = Depends(get_db),
):
    """Exports full audit logs for compliance backup or forensics analysis."""
    logs = db.query(ApiRequestLog).order_by(desc(ApiRequestLog.id)).limit(limit).all()
    events = db.query(SecurityEvent).order_by(desc(SecurityEvent.id)).limit(limit).all()

    return {
        "exported_at": str(time.time()),
        "total_requests": len(logs),
        "total_events": len(events),
        "requests": [
            {
                "request_id": l.request_id,
                "timestamp": l.timestamp.isoformat() if l.timestamp else None,
                "client_ip": l.client_ip,
                "user": l.username,
                "method": l.method,
                "endpoint": l.endpoint,
                "status_code": l.status_code,
                "response_time_ms": l.response_time_ms,
                "risk_score": l.risk_score,
                "risk_level": l.risk_level,
                "policy_decision": l.policy_decision,
                "risk_reasons": l.risk_reasons,
            }
            for l in logs
        ],
        "events": [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "event_type": e.event_type,
                "severity": e.severity,
                "message": e.message,
                "endpoint": e.endpoint,
                "metadata": e.event_metadata,
            }
            for e in events
        ],
    }

