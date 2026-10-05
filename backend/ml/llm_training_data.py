"""Zero-Trust LLM Training Dataset Generator.

Extracts real historical request telemetry and security events from PostgreSQL,
synthesizes canonical cybersecurity threat patterns, and constructs a structured
training dataset and Modelfile exemplar messages for Ollama model training.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple
from sqlalchemy.orm import Session

from app.database.models import ApiRequestLog, SecurityEvent

logger = logging.getLogger("zero_trust.ml.llm_data")

DATASET_DIR = Path(__file__).resolve().parent / "dataset"
TRAIN_JSONL_PATH = DATASET_DIR / "zero_trust_train.jsonl"


def format_telemetry_prompt(
    method: str,
    endpoint: str,
    status_code: int,
    role: str = "ANONYMOUS",
    client_ip: str = "127.0.0.1",
    user_agent: str = "Mozilla/5.0",
    requests_per_min: float = 1.0,
    failed_requests: int = 0,
    is_sensitive: bool = False,
    device_change: bool = False,
    location_change: bool = False,
    payload_sample: str = "",
) -> str:
    """Constructs a standardized, high-density telemetry input prompt for the LLM."""
    parts = [
        f"Method: {method}",
        f"Endpoint: {endpoint}",
        f"Status: {status_code}",
        f"Role: {role or 'ANONYMOUS'}",
        f"ClientIP: {client_ip}",
        f"UserAgent: {user_agent[:40]}",
        f"ReqPerMin: {requests_per_min:.1f}",
        f"FailedReqs: {failed_requests}",
        f"SensitiveEndpoint: {is_sensitive}",
        f"DeviceChange: {device_change}",
        f"LocationChange: {location_change}",
    ]
    if payload_sample:
        parts.append(f"Payload: {payload_sample[:100]}")
    return " | ".join(parts)


def format_ground_truth(
    threat_detected: bool,
    threat_type: str,
    anomaly_score: int,
    confidence: float,
    reasoning: str,
    recommended_action: str,
) -> str:
    """Formats standardized JSON output matching the Zero-Trust decision schema."""
    output = {
        "threat_detected": threat_detected,
        "threat_type": threat_type,
        "anomaly_score": int(anomaly_score),
        "confidence": round(float(confidence), 2),
        "reasoning": reasoning,
        "recommended_action": recommended_action,
    }
    return json.dumps(output, ensure_ascii=False)


def get_canonical_threat_exemplars() -> List[Tuple[str, str]]:
    """Curated canonical cybersecurity threat exemplars embedded into Ollama Modelfile."""
    exemplars = [
        (
            format_telemetry_prompt(
                method="GET",
                endpoint="/api/orders",
                status_code=200,
                role="USER",
                client_ip="192.168.1.10",
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X)",
                requests_per_min=2.5,
                failed_requests=0,
                is_sensitive=False,
            ),
            format_ground_truth(
                threat_detected=False,
                threat_type="NORMAL",
                anomaly_score=5,
                confidence=0.98,
                reasoning="Standard authorized access to user orders adhering to baseline velocity.",
                recommended_action="ALLOW",
            ),
        ),
        (
            format_telemetry_prompt(
                method="GET",
                endpoint="/api/orders",
                status_code=200,
                role="USER",
                client_ip="198.51.100.4",
                user_agent="Go-http-client/1.1",
                requests_per_min=42.0,
                failed_requests=0,
                is_sensitive=False,
            ),
            format_ground_truth(
                threat_detected=True,
                threat_type="API_ABUSE",
                anomaly_score=85,
                confidence=0.96,
                reasoning="Severe velocity anomaly: Request rate (42.0 rpm) breaches baseline burst ceiling.",
                recommended_action="RATE_LIMIT",
            ),
        ),
        (
            format_telemetry_prompt(
                method="POST",
                endpoint="/api/auth/login",
                status_code=401,
                role="ANONYMOUS",
                client_ip="203.0.113.88",
                user_agent="python-requests/2.31.0",
                requests_per_min=18.0,
                failed_requests=12,
                is_sensitive=True,
            ),
            format_ground_truth(
                threat_detected=True,
                threat_type="CREDENTIAL_ATTACK",
                anomaly_score=92,
                confidence=0.98,
                reasoning="Rapid repeated authentication failures indicative of brute-force or credential stuffing.",
                recommended_action="BLOCK",
            ),
        ),
        (
            format_telemetry_prompt(
                method="GET",
                endpoint="/api/admin/users",
                status_code=403,
                role="USER",
                client_ip="192.168.1.10",
                user_agent="Mozilla/5.0 (Windows NT 10.0)",
                requests_per_min=3.0,
                failed_requests=1,
                is_sensitive=True,
            ),
            format_ground_truth(
                threat_detected=True,
                threat_type="PRIVILEGE_MISUSE",
                anomaly_score=90,
                confidence=0.97,
                reasoning="Standard USER identity probed restricted administrative endpoint without necessary permissions.",
                recommended_action="BLOCK",
            ),
        ),
        (
            format_telemetry_prompt(
                method="GET",
                endpoint="/api/payment",
                status_code=200,
                role="USER",
                client_ip="104.28.19.44",
                user_agent="ZeroTrustAuditor/1.0",
                requests_per_min=1.0,
                failed_requests=0,
                is_sensitive=True,
                device_change=True,
                location_change=True,
            ),
            format_ground_truth(
                threat_detected=True,
                threat_type="LOCATION_ANOMALY",
                anomaly_score=68,
                confidence=0.91,
                reasoning="Sensitive payment endpoint accessed from novel device and IP outside historical profile.",
                recommended_action="MONITOR",
            ),
        ),
        (
            format_telemetry_prompt(
                method="POST",
                endpoint="/api/orders",
                status_code=200,
                role="USER",
                client_ip="192.168.1.15",
                user_agent="curl/7.88.1",
                requests_per_min=1.0,
                failed_requests=0,
                is_sensitive=False,
                payload_sample="id=105' OR '1'='1' --",
            ),
            format_ground_truth(
                threat_detected=True,
                threat_type="SUSPICIOUS_PAYLOAD",
                anomaly_score=95,
                confidence=0.99,
                reasoning="SQL injection signature pattern detected in query/body parameter.",
                recommended_action="BLOCK",
            ),
        ),
    ]
    return exemplars


def generate_training_dataset(db: Session, limit: int = 1000) -> Dict[str, Any]:
    """Generates a complete JSONL training dataset combining PostgreSQL telemetry and attack vectors."""
    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    samples: List[Dict[str, Any]] = []

    # 1. Include canonical cybersecurity attack & benign patterns
    exemplars = get_canonical_threat_exemplars()
    for prompt_text, completion_text in exemplars:
        samples.append({
            "prompt": prompt_text,
            "completion": completion_text,
            "source": "canonical_baseline",
        })

    # 2. Extract real database telemetry from PostgreSQL
    try:
        # Fetch security events indexed by request_id for fast correlation
        sec_events = (
            db.query(SecurityEvent)
            .order_by(SecurityEvent.id.desc())
            .limit(limit)
            .all()
        )
        sec_event_map: Dict[str, SecurityEvent] = {}
        for ev in sec_events:
            if ev.request_id and ev.request_id not in sec_event_map:
                sec_event_map[ev.request_id] = ev

        logs = (
            db.query(ApiRequestLog)
            .order_by(ApiRequestLog.id.desc())
            .limit(limit)
            .all()
        )

        for log in logs:
            score = log.risk_score or 0
            rec_action = log.policy_decision or "ALLOW"
            correlated_sec = sec_event_map.get(log.request_id)

            if correlated_sec:
                is_anomaly = True
                threat_type = correlated_sec.event_type
                reason = correlated_sec.message or f"Identified {threat_type} security violation."
            elif score >= 60:
                is_anomaly = True
                threat_type = "ANOMALY_DETECTED"
                reason = "Elevated risk score observed in gateway telemetry."
            elif log.status_code >= 400:
                is_anomaly = log.status_code in (401, 403)
                threat_type = "AUTH_FAILURE" if log.status_code == 401 else "FORBIDDEN_PROBE"
                reason = f"HTTP {log.status_code} client error response."
            else:
                is_anomaly = False
                threat_type = "NORMAL"
                reason = "Normal legitimate API request passing through gateway."

            prompt = format_telemetry_prompt(
                method=log.method,
                endpoint=log.endpoint,
                status_code=log.status_code,
                role=log.role or "ANONYMOUS",
                client_ip=log.client_ip,
                user_agent=log.user_agent,
                is_sensitive=log.is_sensitive,
            )

            completion = format_ground_truth(
                threat_detected=is_anomaly,
                threat_type=threat_type,
                anomaly_score=score,
                confidence=0.92 if is_anomaly else 0.98,
                reasoning=reason,
                recommended_action=rec_action,
            )

            samples.append({
                "prompt": prompt,
                "completion": completion,
                "source": "postgresql_telemetry",
            })

    except Exception as exc:
        logger.warning("Could not read all PostgreSQL telemetry for LLM dataset: %s", exc)

    # 3. Write out JSONL dataset
    with open(TRAIN_JSONL_PATH, "w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    logger.info("Successfully generated %d LLM training samples at %s", len(samples), TRAIN_JSONL_PATH)

    return {
        "dataset_path": str(TRAIN_JSONL_PATH),
        "total_samples": len(samples),
        "canonical_exemplars": len(exemplars),
        "telemetry_samples": len(samples) - len(exemplars),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
