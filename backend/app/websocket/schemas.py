"""WebSocket event schemas and standardized payloads for real-time SOC updates (Step 10)."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class WebSocketEventType(str, Enum):
    """Standardized event types broadcast over WebSocket."""
    REQUEST_COMPLETED = "REQUEST_COMPLETED"
    SECURITY_EVENT = "SECURITY_EVENT"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    RISK_CALCULATED = "RISK_CALCULATED"
    POLICY_DECISION = "POLICY_DECISION"
    ML_ANOMALY = "ML_ANOMALY"
    LLM_ANOMALY = "LLM_ANOMALY"
    PROXY_TRANSACTION = "PROXY_TRANSACTION"
    SIMULATION_COMPLETED = "SIMULATION_COMPLETED"
    PING = "PING"
    PONG = "PONG"
    SYSTEM_STATUS = "SYSTEM_STATUS"


class WebSocketMessage(BaseModel):
    """Standardized envelope for all WebSocket messages."""
    type: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    data: Dict[str, Any] = Field(default_factory=dict)


def sanitize_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitizes outgoing event payload to ensure no sensitive credentials or tokens leak."""
    sensitive_keys = {
        "password",
        "hashed_password",
        "secret",
        "jwt",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "api_key",
        "database_url",
    }
    sanitized = {}
    for k, v in data.items():
        if k.lower() in sensitive_keys:
            continue
        if isinstance(v, dict):
            sanitized[k] = sanitize_payload(v)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_payload(item) if isinstance(item, dict) else item
                for item in v
            ]
        else:
            sanitized[k] = v
    return sanitized
