"""High-level event broadcasting utilities for the Zero-Trust security engine (Step 10).

Ensures all events are broadcast asynchronously without failing or blocking
the primary HTTP request pipeline.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional

from app.websocket.manager import connection_manager
from app.websocket.schemas import WebSocketEventType

logger = logging.getLogger("zero_trust.websocket.events")


async def safe_broadcast(event_type: str, data: Dict[str, Any], user_id: Optional[int] = None) -> None:
    """Dispatches a broadcast safely, suppressing exceptions so the caller is never broken."""
    try:
        if connection_manager.active_count > 0:
            await connection_manager.broadcast(event_type=event_type, data=data, user_id=user_id)
    except Exception as exc:
        logger.warning("[WS SAFE_BROADCAST ERROR] Suppressed broadcast failure: %s", exc)


async def broadcast_request_completed(
    request_id: str,
    method: str,
    endpoint: str,
    status_code: int,
    response_time_ms: float,
    risk_score: Optional[int],
    risk_level: Optional[str],
    policy_decision: Optional[str],
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    reasons: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """Broadcasts a REQUEST_COMPLETED event to authorized clients."""
    payload = {
        "request_id": request_id,
        "method": method,
        "endpoint": endpoint,
        "status_code": status_code,
        "response_time_ms": response_time_ms,
        "risk_score": risk_score if risk_score is not None else 0,
        "risk_level": risk_level or "LOW",
        "policy_decision": policy_decision or "ALLOW",
        "user_id": user_id,
        "username": username or "anonymous",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "reasons": reasons or [],
    }
    await safe_broadcast(WebSocketEventType.REQUEST_COMPLETED.value, payload, user_id=user_id)


async def broadcast_security_event(
    event_id: str,
    request_id: str,
    event_type: str,
    severity: str,
    message: str,
    endpoint: str,
    user_id: Optional[int] = None,
    risk_score: Optional[int] = None,
    risk_level: Optional[str] = None,
    policy_decision: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Broadcasts a high-priority SECURITY_EVENT (threat/anomaly) to authorized clients."""
    payload = {
        "event_id": event_id,
        "request_id": request_id,
        "event_type": event_type,
        "severity": severity,
        "message": message,
        "endpoint": endpoint,
        "user_id": user_id,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "policy": policy_decision,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metadata": metadata or {},
    }
    await safe_broadcast(WebSocketEventType.SECURITY_EVENT.value, payload, user_id=user_id)


async def broadcast_ml_anomaly(
    request_id: str,
    user_id: Optional[int],
    endpoint: str,
    anomaly_score: int,
    raw_score: float,
    threshold: int = 70,
) -> None:
    """Broadcasts an ML_ANOMALY detection event."""
    payload = {
        "request_id": request_id,
        "user_id": user_id,
        "endpoint": endpoint,
        "anomaly_score": anomaly_score,
        "raw_score": raw_score,
        "threshold": threshold,
        "detection": "ANOMALOUS" if anomaly_score >= threshold else "NORMAL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    await safe_broadcast(WebSocketEventType.ML_ANOMALY.value, payload, user_id=user_id)


async def broadcast_llm_anomaly(
    request_id: str,
    user_id: Optional[int],
    endpoint: str,
    threat_type: str,
    anomaly_score: int,
    confidence: float,
    reasoning: str,
    recommended_action: str,
    model: str = "zero-trust-guard",
) -> None:
    """Broadcasts a real-time LLM_ANOMALY threat intelligence event."""
    payload = {
        "request_id": request_id,
        "user_id": user_id,
        "endpoint": endpoint,
        "threat_type": threat_type,
        "anomaly_score": anomaly_score,
        "confidence": confidence,
        "reasoning": reasoning,
        "recommended_action": recommended_action,
        "model": model,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    await safe_broadcast(WebSocketEventType.LLM_ANOMALY.value, payload, user_id=user_id)


async def broadcast_simulation_completed(
    scenario: str,
    requests_generated: int,
    threats_detected: int,
    highest_risk: int,
    risk_level: str,
    final_policy: str,
    user_id: Optional[int] = None,
) -> None:
    """Broadcasts attack simulator results upon batch execution completion."""
    payload = {
        "scenario": scenario,
        "requests_generated": requests_generated,
        "threats_detected": threats_detected,
        "highest_risk": highest_risk,
        "risk_level": risk_level,
        "final_policy": final_policy,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    await safe_broadcast(WebSocketEventType.SIMULATION_COMPLETED.value, payload, user_id=user_id)


async def broadcast_proxy_transaction(
    transaction_id: str,
    source: Dict[str, Any],
    shield: Dict[str, Any],
    destination: Dict[str, Any],
    user_id: Optional[int] = None,
) -> None:
    """Broadcasts a real-time hop-by-hop PROXY_TRANSACTION event (Origin -> Zero Trust Shield -> Destination)."""
    payload = {
        "transaction_id": transaction_id,
        "source": source,
        "shield": shield,
        "destination": destination,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    await safe_broadcast(WebSocketEventType.PROXY_TRANSACTION.value, payload, user_id=user_id)

