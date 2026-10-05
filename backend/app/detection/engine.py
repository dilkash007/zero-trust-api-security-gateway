"""Behavioral anomaly detection evaluation engine (Step 6).

Coordinates feature extraction, baseline comparison, rule execution, deduplication,
and audit persistence into PostgreSQL security_events.
"""

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid
from sqlalchemy.orm import Session

from app.behavior.baseline import fetch_historical_logs
from app.behavior.features import extract_feature_snapshot
from app.database.connection import SessionLocal
from app.database.models import BehaviorProfile, SecurityEvent
from app.detection.rules import (
    DetectionResult,
    rule_api_abuse,
    rule_failed_request_burst,
    rule_sensitive_endpoint_misuse,
    rule_unknown_device,
    rule_unknown_ip,
    rule_unusual_time,
)

logger = logging.getLogger("zero_trust.detection")


def is_duplicate_anomaly(
    db: Session,
    user_id: Optional[int],
    endpoint: str,
    anomaly_type: str,
    window_seconds: int = 60,
) -> bool:
    """Checks whether an identical anomaly event was persisted within window_seconds to prevent event spam."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    query = db.query(SecurityEvent).filter(
        SecurityEvent.event_type == anomaly_type,
        SecurityEvent.timestamp >= cutoff,
    )
    if user_id is not None:
        query = query.filter(SecurityEvent.user_id == user_id)
    else:
        query = query.filter(SecurityEvent.endpoint == endpoint)

    return query.first() is not None


def evaluate_request(
    request_context: Any,
    current_features: Optional[Dict[str, Any]] = None,
    behavior_profile: Optional[Any] = None,
    db: Optional[Session] = None,
    status_code: Optional[int] = None,
) -> Dict[str, Any]:
    """Evaluates a request against the Zero-Trust rule engine and stores detected anomalies in security_events.

    Args:
        request_context: RequestContext instance or dictionary containing request attributes.
        current_features: Optional pre-calculated behavioral features dictionary.
        behavior_profile: Optional pre-fetched BehaviorProfile model instance.
        db: Optional active SQLAlchemy session.
        status_code: Optional HTTP status code override if not present in request_context.

    Returns:
        Structured dictionary: {"detected": bool, "anomalies": List[Dict[str, Any]]}
    """
    owns_session = False
    if db is None:
        db = SessionLocal()
        owns_session = True

    try:
        # 1. Unpack request attributes safely from RequestContext object or dict
        if hasattr(request_context, "request_id"):
            req_id = request_context.request_id
            user_id = request_context.user_id
            role = request_context.role
            client_ip = request_context.client_ip
            user_agent = request_context.user_agent
            endpoint = request_context.endpoint
            is_sensitive = getattr(request_context, "is_sensitive_endpoint", False)
            eff_status_code = getattr(request_context, "status_code", status_code or 200)
        elif isinstance(request_context, dict):
            req_id = request_context.get("request_id", str(uuid.uuid4()))
            user_id = request_context.get("user_id")
            role = request_context.get("role")
            client_ip = request_context.get("client_ip", "127.0.0.1")
            user_agent = request_context.get("user_agent", "unknown")
            endpoint = request_context.get("endpoint", "/")
            is_sensitive = request_context.get("is_sensitive", False)
            eff_status_code = request_context.get("status_code", status_code or 200)
        else:
            req_id = str(uuid.uuid4())
            user_id = None
            role = None
            client_ip = "127.0.0.1"
            user_agent = "unknown"
            endpoint = "/"
            is_sensitive = False
            eff_status_code = status_code or 200

        # 2. Fetch or resolve user's BehaviorProfile if not provided
        profile = behavior_profile
        if profile is None and user_id is not None:
            profile = db.query(BehaviorProfile).filter(BehaviorProfile.user_id == user_id).first()

        # 3. Calculate or resolve feature snapshot if not provided
        features = current_features
        if features is None:
            if user_id is not None:
                logs = fetch_historical_logs(user_id, db)
                known_devs = profile.known_devices if profile else []
                known_ips = profile.known_ips if profile else []
                features = extract_feature_snapshot(
                    logs=logs,
                    known_devices=known_devs,
                    known_ips=known_ips,
                )
            else:
                features = {
                    "requests_per_minute": 0.0,
                    "unique_endpoints": 1,
                    "failed_requests": 1 if eff_status_code >= 400 else 0,
                    "sensitive_endpoint_access": 1 if is_sensitive else 0,
                    "unique_devices": 1,
                    "unique_ips": 1,
                    "device_change": False,
                    "location_change": False,
                    "average_response_time": 0.0,
                    "current_hour": datetime.now(timezone.utc).hour,
                }

        # 4. Execute all 6 independent detection rules
        current_hour = int(features.get("current_hour", datetime.now(timezone.utc).hour))
        rule_evaluations: List[Optional[DetectionResult]] = [
            rule_api_abuse(features, profile),
            rule_failed_request_burst(features, profile),
            rule_unknown_device(user_agent, profile),
            rule_unknown_ip(client_ip, profile),
            rule_sensitive_endpoint_misuse(eff_status_code, is_sensitive, role, endpoint),
            rule_unusual_time(current_hour, profile),
        ]

        # 5. Process detections and persist security events with deduplication
        anomalies: List[Dict[str, Any]] = []
        new_events_persisted = False

        for res in rule_evaluations:
            if res and res.detected and res.anomaly_type:
                anomaly_item = {
                    "type": res.anomaly_type,
                    "severity": res.severity,
                    "reason": res.reason,
                    "evidence": res.evidence,
                }
                anomalies.append(anomaly_item)

                # Check 60-second duplicate suppression
                if not is_duplicate_anomaly(db, user_id, endpoint, res.anomaly_type, window_seconds=60):
                    now_utc = datetime.now(timezone.utc)
                    event_id = str(uuid.uuid4())
                    sec_event = SecurityEvent(
                        event_id=event_id,
                        request_id=req_id,
                        user_id=user_id,
                        event_type=res.anomaly_type,
                        severity=res.severity or "INFO",
                        message=res.reason or res.anomaly_type,
                        endpoint=endpoint,
                        timestamp=now_utc,
                        event_metadata=res.evidence,
                    )
                    db.add(sec_event)
                    new_events_persisted = True
                    logger.warning(
                        "[ANOMALY DETECTED] type=%s severity=%s user_id=%s endpoint=%s reason='%s'",
                        res.anomaly_type,
                        res.severity,
                        user_id,
                        endpoint,
                        res.reason,
                    )
                else:
                    logger.debug(
                        "[ANOMALY DEDUPLICATED] Suppressed duplicate %s event for user_id=%s within 60s",
                        res.anomaly_type,
                        user_id,
                    )

        if new_events_persisted:
            db.commit()

        return {
            "detected": len(anomalies) > 0,
            "anomalies": anomalies,
            "features": features,
        }

    except Exception as exc:
        if owns_session:
            db.rollback()
        logger.error("Error during rule-based anomaly detection: %s", type(exc).__name__, exc_info=True)
        return {
            "detected": False,
            "anomalies": [],
            "error": str(exc),
        }
    finally:
        if owns_session:
            db.close()
