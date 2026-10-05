"""API endpoints for Risk Scoring & Policy Decision Engine (Step 7)."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import ApiRequestLog, SecurityEvent
from app.gateway.dependencies import require_admin_only, require_user_or_admin
from app.gateway.request_context import RequestContext
from app.risk.policy import get_configured_policies, get_full_policy_config, update_configured_policies

risk_router = APIRouter(prefix="/api", tags=["Risk Scoring & Policy Engine (Step 7)"])


@risk_router.get(
    "/risk/me",
    status_code=status.HTTP_200_OK,
    summary="Retrieve current user's latest risk assessment",
)
def get_my_risk(
    context: RequestContext = Depends(require_user_or_admin),
    db: Session = Depends(get_db),
):
    """Returns the authenticated principal's latest evaluated risk score and policy decision."""
    latest_log = (
        db.query(ApiRequestLog)
        .filter(ApiRequestLog.user_id == context.user_id, ApiRequestLog.risk_score.isnot(None))
        .order_by(ApiRequestLog.id.desc())
        .first()
    )

    if latest_log:
        return {
            "success": True,
            "data": {
                "risk_score": latest_log.risk_score,
                "risk_level": latest_log.risk_level or "LOW",
                "decision": latest_log.policy_decision or "ALLOW",
                "reasons": latest_log.risk_reasons or [],
                "endpoint": latest_log.endpoint,
                "timestamp": latest_log.timestamp.isoformat() if latest_log.timestamp else None,
            },
        }

    # Baseline default if user has no evaluated traffic yet
    return {
        "success": True,
        "data": {
            "risk_score": 0,
            "risk_level": "LOW",
            "decision": "ALLOW",
            "reasons": [],
            "endpoint": None,
            "timestamp": None,
        },
    }


@risk_router.get(
    "/risk",
    status_code=status.HTTP_200_OK,
    summary="Query historical risk assessments and policy decisions (ADMIN only)",
)
def get_risk_assessments(
    limit: int = Query(50, ge=1, le=100, description="Max records to return (1-100)"),
    risk_level: Optional[str] = Query(None, description="Filter by risk tier (CRITICAL, HIGH, MEDIUM, LOW)"),
    decision: Optional[str] = Query(None, description="Filter by policy decision (BLOCK, RATE_LIMIT, MONITOR, ALLOW)"),
    user_id: Optional[int] = Query(None, description="Filter by user identifier"),
    context: RequestContext = Depends(require_admin_only),
    db: Session = Depends(get_db),
):
    """Returns historical risk evaluations with explainability factors. ADMIN only."""
    query = db.query(ApiRequestLog).filter(ApiRequestLog.risk_score.isnot(None))

    if risk_level:
        query = query.filter(ApiRequestLog.risk_level == risk_level.strip().upper())

    if decision:
        query = query.filter(ApiRequestLog.policy_decision == decision.strip().upper())

    if user_id is not None:
        query = query.filter(ApiRequestLog.user_id == user_id)

    records = query.order_by(ApiRequestLog.id.desc()).limit(limit).all()

    data = [
        {
            "id": r.id,
            "request_id": r.request_id,
            "user_id": r.user_id,
            "username": r.username or (r.user.email if r.user else "Anonymous"),
            "endpoint": r.endpoint,
            "method": r.method,
            "status_code": r.status_code,
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "decision": r.policy_decision,
            "reasons": r.risk_reasons or [],
            "client_ip": r.client_ip,
            "user_agent": r.user_agent,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        }
        for r in records
    ]

    return {
        "success": True,
        "count": len(data),
        "data": data,
    }


@risk_router.get(
    "/policies",
    status_code=status.HTTP_200_OK,
    summary="Retrieve configured Zero-Trust risk policy rules (ADMIN only)",
)
def get_policies(
    context: RequestContext = Depends(require_admin_only),
):
    """Returns the active Zero-Trust policy mapping tiers and configuration. ADMIN only."""
    return {
        "success": True,
        "policies": get_configured_policies(),
        "config": get_full_policy_config(),
    }


@risk_router.post(
    "/policies",
    status_code=status.HTTP_200_OK,
    summary="Update Zero-Trust policy configuration (ADMIN only)",
)
@risk_router.put(
    "/policies",
    status_code=status.HTTP_200_OK,
    summary="Update Zero-Trust policy configuration (ADMIN only)",
)
def update_policies(
    payload: Dict[str, Any],
    context: RequestContext = Depends(require_admin_only),
):
    """Updates active policy tiers, thresholds, or module switches."""
    updated = update_configured_policies(payload)
    return {
        "success": True,
        "message": "Security policies updated successfully",
        "policies": updated.get("tiers", []),
        "config": updated,
    }

