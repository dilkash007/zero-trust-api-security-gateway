"""Schemas for the Zero-Trust API Protector & Reverse Proxy Inspector."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TargetApiConfig(BaseModel):
    """Configuration for the upstream target API (e.g., Google Gemini or custom API)."""
    name: str = "Google Gemini 3.5 Flash Lite"
    target_url: str = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent"
    api_key: Optional[str] = None
    auth_type: str = "query_param"  # "query_param", "header", "bearer", "none"
    auth_header_name: str = "x-goog-api-key"
    auth_query_param: str = "key"
    timeout_seconds: float = 20.0
    enabled: bool = True


class TargetPreset(BaseModel):
    """Pre-configured popular upstream target templates."""
    id: str
    name: str
    description: str
    target_url: str
    auth_type: str
    auth_header_name: str
    auth_query_param: str
    sample_clean_payload: Dict[str, Any]
    sample_attack_payload: Dict[str, Any]


class ProxyDispatchRequest(BaseModel):
    """Request payload sent to the Gateway's interactive dispatch inspector."""
    target_url: Optional[str] = None
    api_key: Optional[str] = None
    method: str = "POST"
    path: Optional[str] = "/api/proxy/dispatch"
    headers: Optional[Dict[str, str]] = None
    body: Optional[Any] = None
    prompt: Optional[str] = None
    simulated_ip: Optional[str] = None
    simulated_user_agent: Optional[str] = None
    client_city: Optional[str] = None
    client_country: Optional[str] = None
    caller_identity: Optional[str] = None


class SourceTelemetry(BaseModel):
    """Origin telemetry detailing where the request came from."""
    client_ip: str
    real_caller_ip: str = "127.0.0.1"
    is_simulated: bool = False
    caller_identity: str = "Anonymous Consumer"
    client_device: str = "Client Device"
    network_type: str = "Public Internet"
    user_agent: str
    geo_location: Dict[str, str] = Field(default_factory=dict)
    method: str
    path: str
    full_ingress_url: str = "/api/proxy/dispatch"
    ingress_time: str
    request_size_bytes: int
    headers: Dict[str, str] = Field(default_factory=dict)
    payload_preview: Optional[str] = None


class ShieldTelemetry(BaseModel):
    """Zero-Trust inspection telemetry (Rule Engine + ML Anomaly + Ollama LLM + Policy)."""
    rule_checks: Dict[str, Any] = Field(default_factory=dict)
    anomalies: List[Dict[str, Any]] = Field(default_factory=list)
    ml_anomaly_score: int = 0
    ml_is_anomaly: bool = False
    llm_threat_detected: bool = False
    llm_threat_type: Optional[str] = None
    llm_anomaly_score: int = 0
    llm_confidence: float = 0.0
    llm_reasoning: Optional[str] = None
    llm_model: str = "zero-trust-guard"
    risk_score: int = 0
    risk_level: str = "LOW"
    policy_decision: str = "ALLOW"
    inspection_time_ms: float = 0.0


class DestinationTelemetry(BaseModel):
    """Upstream telemetry detailing where the request went (or was blocked)."""
    target_url: str
    target_name: str
    model_name: Optional[str] = None
    was_forwarded: bool = False
    upstream_status_code: Optional[int] = None
    upstream_latency_ms: Optional[float] = None
    response_size_bytes: Optional[int] = None
    ai_response_text: Optional[str] = None
    token_usage: Optional[Dict[str, int]] = None
    response_preview: Optional[Any] = None
    block_reason: Optional[str] = None
    error_message: Optional[str] = None


class ProxyTransactionResponse(BaseModel):
    """Complete hop-by-hop telemetry transaction result."""
    transaction_id: str
    status: str  # "FORWARDED", "BLOCKED", "ERROR"
    source: SourceTelemetry
    shield: ShieldTelemetry
    destination: DestinationTelemetry
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class CheckModelItem(BaseModel):
    model_id: str
    name: str
    status: str  # "ONLINE", "ERROR", "UNAVAILABLE"
    status_code: Optional[int] = None
    latency_ms: Optional[float] = None
    sample_reply: Optional[str] = None
    error: Optional[str] = None


class CheckModelsRequest(BaseModel):
    api_key: str
    models: Optional[List[str]] = None


class CheckModelsResponse(BaseModel):
    success: bool
    api_key_valid: bool
    results: List[CheckModelItem]
    checked_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

