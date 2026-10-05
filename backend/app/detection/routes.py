"""API routes for querying detected behavioral anomalies (Step 6)."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import SecurityEvent, SecurityEventType
from app.gateway.dependencies import require_admin_only
from app.gateway.request_context import RequestContext

detection_router = APIRouter(prefix="/api/anomalies", tags=["Anomaly Detection (Step 6)"])

RECOGNIZED_ANOMALY_TYPES = [
    SecurityEventType.API_ABUSE.value,
    SecurityEventType.CREDENTIAL_ATTACK.value,
    SecurityEventType.UNKNOWN_DEVICE.value,
    SecurityEventType.LOCATION_ANOMALY.value,
    SecurityEventType.PRIVILEGE_MISUSE.value,
    SecurityEventType.UNUSUAL_TIME.value,
]


@detection_router.get(
    "",
    status_code=status.HTTP_200_OK,
    summary="Query recent detected behavioral anomalies (ADMIN only)",
)
def get_anomalies(
    limit: int = Query(50, ge=1, le=100, description="Max records to return (1-100)"),
    type: Optional[str] = Query(None, description="Filter by anomaly type (e.g. API_ABUSE, PRIVILEGE_MISUSE)"),
    severity: Optional[str] = Query(None, description="Filter by severity (HIGH, MEDIUM, LOW)"),
    user_id: Optional[int] = Query(None, description="Filter by user identifier"),
    context: RequestContext = Depends(require_admin_only),
    db: Session = Depends(get_db),
):
    """Returns detected behavioral anomalies from security_events. ADMIN only.

    Supports optional filtering by anomaly type, severity, and user_id.
    Results are returned newest first.
    """
    query = db.query(SecurityEvent)

    # If specific type requested, filter by it; otherwise limit to recognized anomaly event types
    if type:
        query = query.filter(SecurityEvent.event_type == type.strip().upper())
    else:
        query = query.filter(SecurityEvent.event_type.in_(RECOGNIZED_ANOMALY_TYPES))

    if severity:
        query = query.filter(SecurityEvent.severity == severity.strip().upper())

    if user_id is not None:
        query = query.filter(SecurityEvent.user_id == user_id)

    events = query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()

    data = [
        {
            "event_id": e.event_id,
            "request_id": e.request_id,
            "user_id": e.user_id,
            "username": (e.user.name or e.user.email) if e.user else (f"User #{e.user_id}" if e.user_id else "Anonymous"),
            "type": e.event_type,
            "severity": e.severity,
            "reason": e.message,
            "endpoint": e.endpoint,
            "evidence": e.event_metadata or {},
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        }
        for e in events
    ]

    return {
        "success": True,
        "count": len(data),
        "data": data,
    }
