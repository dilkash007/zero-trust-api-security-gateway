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
    SecurityEventType.ML_ANOMALY_DETECTED.value,
]


@detection_router.get(
    "",
    status_code=status.HTTP_200_OK,
    summary="Query recent detected behavioral anomalies (ADMIN only)",
)
def get_anomalies(
    limit: int = Query(50, ge=1, le=100, description="Max records to return (1-100)"),
    type: Optional[str] = Query(None, description="Filter by anomaly type (e.g. API_ABUSE, PRIVILEGE_MISUSE, ML_ANOMALY)"),
    severity: Optional[str] = Query(None, description="Filter by severity (HIGH, MEDIUM, LOW, CRITICAL)"),
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
        normalized_type = type.strip().upper()
        if normalized_type == "ML_ANOMALY":
            normalized_type = SecurityEventType.ML_ANOMALY_DETECTED.value
        query = query.filter(SecurityEvent.event_type == normalized_type)
    else:
        query = query.filter(SecurityEvent.event_type.in_(RECOGNIZED_ANOMALY_TYPES))

    if severity:
        query = query.filter(SecurityEvent.severity == severity.strip().upper())

    if user_id is not None:
        query = query.filter(SecurityEvent.user_id == user_id)

    events = query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()

    from app.database.models import ApiRequestLog

    req_ids = [e.request_id for e in events if e.request_id]
    req_map = {}
    if req_ids:
        req_logs = db.query(ApiRequestLog).filter(ApiRequestLog.request_id.in_(req_ids)).all()
        for r in req_logs:
            req_map[r.request_id] = r

    data = []
    for e in events:
        req = req_map.get(e.request_id)
        r_score = req.risk_score if req and req.risk_score is not None else (
            92 if e.severity == "CRITICAL" else 75 if e.severity == "HIGH" else 45 if e.severity == "MEDIUM" else 18
        )
        decision = req.policy_decision if req and req.policy_decision else (
            "BLOCK" if e.severity in ("CRITICAL", "HIGH") else "MONITOR"
        )
        c_ip = req.client_ip if req else (e.event_metadata or {}).get("client_ip", "127.0.0.1")
        u_agent = req.user_agent if req else (e.event_metadata or {}).get("user_agent", "Unknown Device")
        reasons = req.risk_reasons if req and req.risk_reasons else []

        data.append({
            "event_id": e.event_id,
            "request_id": e.request_id,
            "user_id": e.user_id,
            "username": (e.user.name or e.user.email) if e.user else (f"User #{e.user_id}" if e.user_id else "Anonymous"),
            "type": e.event_type,
            "threat_type": e.event_type.replace("_", " ").title(),
            "severity": e.severity,
            "reason": e.message,
            "endpoint": e.endpoint,
            "evidence": e.event_metadata or {},
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "client_ip": c_ip,
            "user_agent": u_agent,
            "risk_score": r_score,
            "policy_decision": decision,
            "action": decision,
            "risk_reasons": reasons,
        })

    return {
        "success": True,
        "count": len(data),
        "data": data,
    }

