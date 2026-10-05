"""Real-time Zero-Trust LLM Threat & Anomaly Detector.

Evaluates live API request telemetry, behavioral features, and payload data against
the custom trained 'zero-trust-guard' LLM running locally in Ollama.
"""

from datetime import datetime, timezone
import json
import logging
import time
from typing import Any, Dict, Optional
import httpx

from app.config import settings
from ml.llm_training_data import format_telemetry_prompt

logger = logging.getLogger("zero_trust.ml.llm_detector")

DECISION_THRESHOLD = 70


class LLMCircuitBreaker:
    """Circuit breaker preventing request delays if Ollama service is slow or unreachable."""

    def __init__(self, failure_threshold: int = 3, reset_timeout: float = 30.0):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.is_open = False

    def record_success(self):
        self.failure_count = 0
        self.is_open = False

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.is_open = True
            logger.warning(
                "Ollama LLM Circuit Breaker TRIPPED OPEN. Temporarily bypassing LLM detection for %ss.",
                self.reset_timeout,
            )

    def can_attempt(self) -> bool:
        if not self.is_open:
            return True
        if time.time() - self.last_failure_time > self.reset_timeout:
            self.is_open = False
            self.failure_count = 0
            logger.info("Ollama LLM Circuit Breaker entering Half-Open retry state.")
            return True
        return False


_circuit_breaker = LLMCircuitBreaker()


def predict_threat_with_llm(
    request_context: Any,
    features: Optional[Dict[str, Any]] = None,
    payload_sample: str = "",
    timeout: float = 2.5,
) -> Dict[str, Any]:
    """Evaluates an API request against the trained 'zero-trust-guard' model.

    Args:
        request_context: RequestContext instance or dict with request attributes.
        features: Optional live behavioral feature snapshot dict.
        payload_sample: Optional query parameter or payload snippet for deep inspection.
        timeout: Maximum seconds to wait for inference (default: 2.5s).

    Returns:
        Structured evaluation dictionary:
        {
          "available": bool,
          "is_anomaly": bool,
          "threat_type": str,
          "anomaly_score": int (0-100),
          "confidence": float,
          "reasoning": str,
          "recommended_action": str,
          "model": str,
          "latency_ms": float,
        }
    """
    if not getattr(settings, "LLM_DETECTION_ENABLED", True):
        return {
            "available": False,
            "is_anomaly": False,
            "threat_type": "NORMAL",
            "anomaly_score": 0,
            "confidence": 0.0,
            "reasoning": "LLM threat detection disabled in settings.",
            "recommended_action": "ALLOW",
            "model": "none",
            "latency_ms": 0.0,
        }

    if not _circuit_breaker.can_attempt():
        return {
            "available": False,
            "is_anomaly": False,
            "threat_type": "NORMAL",
            "anomaly_score": 0,
            "confidence": 0.0,
            "reasoning": "Ollama LLM circuit breaker open (offline/slow fallback).",
            "recommended_action": "ALLOW",
            "model": "none",
            "latency_ms": 0.0,
        }

    start_t = time.perf_counter()

    # 1. Unpack request attributes safely
    if hasattr(request_context, "method"):
        method = request_context.method
        endpoint = request_context.endpoint
        status_code = getattr(request_context, "status_code", 200)
        role = getattr(request_context, "role", "ANONYMOUS")
        client_ip = getattr(request_context, "client_ip", "127.0.0.1")
        user_agent = getattr(request_context, "user_agent", "unknown")
        is_sensitive = getattr(request_context, "is_sensitive_endpoint", False)
    elif isinstance(request_context, dict):
        method = request_context.get("method", "GET")
        endpoint = request_context.get("endpoint", "/")
        status_code = request_context.get("status_code", 200)
        role = request_context.get("role", "ANONYMOUS")
        client_ip = request_context.get("client_ip", "127.0.0.1")
        user_agent = request_context.get("user_agent", "unknown")
        is_sensitive = request_context.get("is_sensitive", False)
    else:
        method, endpoint, status_code = "GET", "/", 200
        role, client_ip, user_agent, is_sensitive = "ANONYMOUS", "127.0.0.1", "unknown", False

    feat = features or {}
    rpm = float(feat.get("requests_per_minute", 1.0))
    failed_reqs = int(feat.get("failed_requests", 1 if status_code >= 400 else 0))
    dev_change = bool(feat.get("device_change", False))
    loc_change = bool(feat.get("location_change", False))

    prompt = format_telemetry_prompt(
        method=method,
        endpoint=endpoint,
        status_code=status_code,
        role=role,
        client_ip=client_ip,
        user_agent=user_agent,
        requests_per_min=rpm,
        failed_requests=failed_reqs,
        is_sensitive=is_sensitive,
        device_change=dev_change,
        location_change=loc_change,
        payload_sample=payload_sample,
    )

    base_url = getattr(settings, "OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    model_name = getattr(settings, "OLLAMA_MODEL", "zero-trust-guard")

    payload = {
        "model": model_name,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.05,
            "num_predict": 128,
        },
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(f"{base_url}/api/generate", json=payload)
            if resp.status_code == 404:
                # If zero-trust-guard not found, fallback to base model
                fallback_model = getattr(settings, "OLLAMA_BASE_MODEL", "qwen2.5:0.5b")
                payload["model"] = fallback_model
                resp = client.post(f"{base_url}/api/generate", json=payload)

            if resp.status_code == 200:
                _circuit_breaker.record_success()
                data = resp.json()
                raw_response = data.get("response", "{}").strip()
                parsed = json.loads(raw_response)

                score = int(parsed.get("anomaly_score", 0))
                threat_type = str(parsed.get("threat_type", "NORMAL")).upper()
                rec_action = str(parsed.get("recommended_action", "ALLOW")).upper()
                confidence = float(parsed.get("confidence", 0.90))
                reasoning = str(parsed.get("reasoning", "No anomaly identified"))

                # Calibration: Align action with high risk anomaly scores
                if score >= 85:
                    if threat_type == "API_ABUSE":
                        rec_action = "RATE_LIMIT"
                    elif threat_type in ("CREDENTIAL_ATTACK", "PRIVILEGE_MISUSE", "SUSPICIOUS_PAYLOAD"):
                        rec_action = "BLOCK"
                    elif rec_action == "ALLOW":
                        rec_action = "MONITOR"
                elif score >= 60 and rec_action == "ALLOW":
                    rec_action = "MONITOR"

                if threat_type in ("NORMAL", "BENIGN"):
                    is_anomaly = score >= DECISION_THRESHOLD
                else:
                    is_anomaly = score >= 50 or rec_action in ("BLOCK", "RATE_LIMIT", "MONITOR")

                latency_ms = round((time.perf_counter() - start_t) * 1000.0, 2)

                return {
                    "available": True,
                    "is_anomaly": is_anomaly,
                    "threat_type": threat_type,
                    "anomaly_score": score,
                    "confidence": confidence,
                    "reasoning": reasoning,
                    "recommended_action": rec_action,
                    "model": payload["model"],
                    "latency_ms": latency_ms,
                }
            else:
                _circuit_breaker.record_failure()
                logger.warning("Ollama LLM responded with HTTP %d", resp.status_code)
    except Exception as exc:
        _circuit_breaker.record_failure()
        logger.debug("Ollama LLM threat prediction bypassed: %s", exc)

    latency_ms = round((time.perf_counter() - start_t) * 1000.0, 2)
    return {
        "available": False,
        "is_anomaly": False,
        "threat_type": "NORMAL",
        "anomaly_score": 0,
        "confidence": 0.0,
        "reasoning": "Ollama LLM unavailable, safe fallback applied.",
        "recommended_action": "ALLOW",
        "model": "fallback",
        "latency_ms": latency_ms,
    }
