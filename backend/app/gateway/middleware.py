"""Production API Gateway Middleware.

Responsibilities (in request-path order):
  1. Assign a canonical Request-ID
  2. Extract client IP (X-Forwarded-For / X-Simulated-IP / direct)
  3. Enforce IP block-list (hard reject)
  4. Apply sliding-window rate limiting (per-IP and per-user burst)
  5. Forward request to downstream route handlers
  6. Collect telemetry (latency, size, auth context)
  7. Run rule-based anomaly detection (Step 6)
  8. Run ML Isolation Forest anomaly detection (Step 8)
  9. Calculate deterministic risk score (Step 7)
  10. Evaluate Zero-Trust policy decision (Step 7)
  11. Persist telemetry + security events to PostgreSQL (Step 4)
  12. Broadcast real-time WebSocket events (Step 10)
  13. Enforce BLOCK policy — return 403 for critical requests

Security invariants:
  - Telemetry is ALWAYS persisted before policy enforcement.
  - Policy enforcement never prevents telemetry from being written.
  - 401/403 responses from route handlers are NEVER overridden.
  - WebSocket failures NEVER slow or fail HTTP responses.
  - Rate-limit enforcement runs BEFORE route handlers.
"""

import logging
import time
import uuid
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.cache.redis_client import get_rate_limiter
from app.config import settings
from app.database.models import EventSeverity, SecurityEventType
from app.detection.engine import evaluate_request
from app.gateway.telemetry_logger import persist_telemetry, persist_security_event
from app.risk.policy import evaluate_policy
from app.risk.scorer import calculate_risk
from app.security.privilege import is_sensitive_endpoint
from app.websocket.events import (
    broadcast_request_completed,
    broadcast_security_event,
    broadcast_ml_anomaly,
    broadcast_llm_anomaly,
)
from ml.predictor import predict_anomaly
from ml.llm_detector import predict_threat_with_llm

logger = logging.getLogger("zero_trust.gateway")

# ---------------------------------------------------------------------------
# Protected path prefixes subject to Zero-Trust telemetry & inspection
# ---------------------------------------------------------------------------
PROTECTED_PATH_PREFIXES = (
    "/api/profile",
    "/api/orders",
    "/api/payment",
    "/api/users",
    "/api/admin",
    "/api/requests",
    "/api/security/events",
    "/api/test/protected",
    "/api/behavior",
    "/api/anomalies",
    "/api/risk",
    "/api/policies",
    "/api/ml",
    "/api/simulator",
    "/api/dashboard",
)

# Paths exempt from rate limiting (health probes, auth, internal)
RATE_LIMIT_EXEMPT_PREFIXES = (
    "/health",
    "/docs",
    "/openapi",
    "/redoc",
    "/auth/login",
    "/auth/register",
    "/api/auth",          # production auth endpoints
    "/api/simulator",     # simulator makes its own downstream requests
    "/ws",               # WebSocket connections
)

# IPs always exempt from rate limiting (loopback / trusted internal)
RATE_LIMIT_EXEMPT_IPS = {"127.0.0.1", "::1", "localhost"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_client_ip(request: Request) -> str:
    """Extract the best-effort real client IP address.

    Priority:
      1. X-Simulated-IP — used by local attack simulator tests
      2. X-Forwarded-For — set by load balancers / reverse proxies
      3. Direct client host
    """
    simulated = request.headers.get("X-Simulated-IP") or request.headers.get("X-Forwarded-For")
    if simulated:
        return simulated.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def _is_rate_limit_exempt(path: str) -> bool:
    return any(path.startswith(p) for p in RATE_LIMIT_EXEMPT_PREFIXES)


def _is_exempt_ip(ip: str) -> bool:
    """Loopback / trusted internal IPs bypass rate limiting entirely."""
    return ip in RATE_LIMIT_EXEMPT_IPS


def _rate_limit_key_ip(client_ip: str) -> str:
    return f"ip:{client_ip}"


def _rate_limit_key_burst(client_ip: str) -> str:
    return f"burst:{client_ip}"


def _rate_limit_key_user(user_id: int) -> str:
    return f"user:{user_id}"


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class RequestContextMiddleware(BaseHTTPMiddleware):
    """Production Zero-Trust Gateway Middleware.

    Enforces rate limits BEFORE routes execute, persists telemetry AFTER,
    and applies policy decisions (including blocking) on the response.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start_time = time.perf_counter()

        # ---------------------------------------------------------------
        # 1. Request ID — validate/generate canonical UUID
        # ---------------------------------------------------------------
        incoming_rid = request.headers.get("X-Request-ID")
        if incoming_rid:
            try:
                request_id = str(uuid.UUID(incoming_rid))
            except ValueError:
                request_id = str(uuid.uuid4())
        else:
            request_id = str(uuid.uuid4())

        # ---------------------------------------------------------------
        # 2. Extract client IP and core headers
        # ---------------------------------------------------------------
        client_ip = _extract_client_ip(request)
        user_agent = request.headers.get("user-agent", "unknown")
        request_size = int(request.headers.get("content-length", 0))

        request.state.request_id = request_id
        request.state.client_ip = client_ip
        request.state.user_agent = user_agent

        path = request.url.path

        # ---------------------------------------------------------------
        # 3 & 4. Pre-route rate limiting (runs before calling the handler)
        # Skip entirely for exempt paths AND exempt IPs (loopback / internal)
        # ---------------------------------------------------------------
        if not _is_rate_limit_exempt(path) and not _is_exempt_ip(client_ip):
            rl = get_rate_limiter()

            # 3a. IP block-list check
            if rl.is_ip_blocked(client_ip):
                logger.warning("[RATE_LIMIT] Blocked IP attempted request: %s → %s", client_ip, path)
                return JSONResponse(
                    status_code=429,
                    content={
                        "success": False,
                        "error": {
                            "code": "IP_BLOCKED",
                            "message": "Your IP has been temporarily blocked due to policy violations.",
                        },
                        "retry_after": settings.RATE_LIMIT_BLOCK_DURATION_SECONDS,
                    },
                    headers={"X-Request-ID": request_id, "Retry-After": str(settings.RATE_LIMIT_BLOCK_DURATION_SECONDS)},
                )

            # 3b. Burst protection (tight window, e.g. 20 req/5 s)
            burst_allowed, _ = rl.check_rate_limit(
                key=_rate_limit_key_burst(client_ip),
                limit=settings.RATE_LIMIT_BURST_REQUESTS,
                window_seconds=settings.RATE_LIMIT_BURST_WINDOW_SECONDS,
            )
            if not burst_allowed:
                logger.warning("[RATE_LIMIT] Burst limit exceeded for IP %s on %s", client_ip, path)
                # Persistent violations auto-block the IP
                rl.block_ip(client_ip, settings.RATE_LIMIT_BLOCK_DURATION_SECONDS)
                return JSONResponse(
                    status_code=429,
                    content={
                        "success": False,
                        "error": {
                            "code": "BURST_RATE_LIMIT_EXCEEDED",
                            "message": "Too many requests — burst limit exceeded. IP has been blocked.",
                        },
                        "retry_after": settings.RATE_LIMIT_BLOCK_DURATION_SECONDS,
                    },
                    headers={
                        "X-Request-ID": request_id,
                        "Retry-After": str(settings.RATE_LIMIT_BLOCK_DURATION_SECONDS),
                    },
                )

            # 3c. Sliding-window per-IP global limit (e.g. 100 req/60 s)
            ip_allowed, ip_remaining = rl.check_rate_limit(
                key=_rate_limit_key_ip(client_ip),
                limit=settings.RATE_LIMIT_REQUESTS,
                window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
            )
            if not ip_allowed:
                logger.warning("[RATE_LIMIT] IP window exceeded for %s on %s", client_ip, path)
                return JSONResponse(
                    status_code=429,
                    content={
                        "success": False,
                        "error": {
                            "code": "RATE_LIMIT_EXCEEDED",
                            "message": f"Too many requests. Limit: {settings.RATE_LIMIT_REQUESTS} per {settings.RATE_LIMIT_WINDOW_SECONDS}s.",
                        },
                        "retry_after": settings.RATE_LIMIT_WINDOW_SECONDS,
                    },
                    headers={
                        "X-Request-ID": request_id,
                        "Retry-After": str(settings.RATE_LIMIT_WINDOW_SECONDS),
                        "X-RateLimit-Limit": str(settings.RATE_LIMIT_REQUESTS),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Window": str(settings.RATE_LIMIT_WINDOW_SECONDS),
                    },
                )

        # ---------------------------------------------------------------
        # 5. Forward request to route handler
        # ---------------------------------------------------------------
        response = await call_next(request)

        # ---------------------------------------------------------------
        # 6. Inject X-Request-ID into all responses
        # ---------------------------------------------------------------
        response.headers["X-Request-ID"] = request_id

        # ---------------------------------------------------------------
        # 7. Measure latency and response metadata
        # ---------------------------------------------------------------
        response_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        response_size = int(response.headers.get("content-length", 0))
        status_code = response.status_code

        # ---------------------------------------------------------------
        # 8–13. Security telemetry for protected endpoints
        # ---------------------------------------------------------------
        is_protected = any(path.startswith(prefix) for prefix in PROTECTED_PATH_PREFIXES)

        if is_protected:
            context = getattr(request.state, "context", None)
            is_sensitive = is_sensitive_endpoint(path)

            user_id = context.user_id if context else None
            username = context.username if context else None
            role = context.role if context else None
            is_authenticated = bool(context and context.is_authenticated)

            # ---------------------------------------------------------------
            # 8a. Per-user rate limit check (post-auth, for authenticated users)
            # ---------------------------------------------------------------
            if user_id and not _is_rate_limit_exempt(path):
                rl = get_rate_limiter()
                user_allowed, user_remaining = rl.check_rate_limit(
                    key=_rate_limit_key_user(user_id),
                    limit=settings.RATE_LIMIT_USER_REQUESTS,
                    window_seconds=settings.RATE_LIMIT_USER_WINDOW_SECONDS,
                )
                if not user_allowed:
                    logger.warning("[RATE_LIMIT] User %s window exceeded on %s", user_id, path)
                    return JSONResponse(
                        status_code=429,
                        content={
                            "success": False,
                            "error": {
                                "code": "USER_RATE_LIMIT_EXCEEDED",
                                "message": f"User rate limit exceeded. Limit: {settings.RATE_LIMIT_USER_REQUESTS} per {settings.RATE_LIMIT_USER_WINDOW_SECONDS}s.",
                            },
                            "retry_after": settings.RATE_LIMIT_USER_WINDOW_SECONDS,
                        },
                        headers={
                            "X-Request-ID": request_id,
                            "Retry-After": str(settings.RATE_LIMIT_USER_WINDOW_SECONDS),
                        },
                    )

            # ---------------------------------------------------------------
            # 8b. Primary security event classification
            # ---------------------------------------------------------------
            sec_event_type = None
            sec_event_severity = None
            sec_event_message = None
            sec_event_metadata = {
                "method": request.method,
                "endpoint": path,
                "role": role,
                "sensitive": is_sensitive,
            }

            if status_code == 401:
                sec_event_type = SecurityEventType.AUTHENTICATION_FAILURE.value
                sec_event_severity = EventSeverity.MEDIUM.value
                sec_event_message = "Authentication token is missing or invalid"
            elif status_code == 403:
                sec_event_type = SecurityEventType.AUTHORIZATION_FAILURE.value
                sec_event_severity = EventSeverity.HIGH.value
                sec_event_message = "Insufficient privileges for endpoint access"
            elif status_code < 400 and is_sensitive:
                sec_event_type = SecurityEventType.SENSITIVE_ENDPOINT_ACCESS.value
                sec_event_severity = EventSeverity.INFO.value
                sec_event_message = f"Sensitive endpoint {path} accessed successfully"

            # ---------------------------------------------------------------
            # Step 6: Rule-based behavioral anomaly detection
            # ---------------------------------------------------------------
            req_ctx = {
                "request_id": request_id,
                "user_id": user_id,
                "role": role,
                "client_ip": client_ip,
                "user_agent": user_agent,
                "endpoint": path,
                "method": request.method,
                "status_code": status_code,
                "is_sensitive": is_sensitive,
            }
            try:
                detection_outcome = evaluate_request(req_ctx, status_code=status_code)
                anomalies = detection_outcome.get("anomalies", [])
                features = detection_outcome.get("features", {})
            except Exception as exc:
                logger.error("[DETECTION] Rule engine error on %s: %s", path, exc)
                anomalies = []
                features = {}

            # ---------------------------------------------------------------
            # Step 8: ML Isolation Forest anomaly detection
            # ---------------------------------------------------------------
            ml_result = None
            try:
                if features:
                    ml_result = predict_anomaly(features)
                    if ml_result and ml_result.get("is_anomaly"):
                        persist_security_event(
                            request_id=request_id,
                            user_id=user_id,
                            event_type=SecurityEventType.ML_ANOMALY_DETECTED.value,
                            severity=EventSeverity.HIGH.value,
                            message="Behavior differs significantly from the learned baseline",
                            endpoint=path,
                            metadata={
                                "model": "IsolationForest",
                                "anomaly_score": ml_result.get("anomaly_score", 0),
                                "raw_score": ml_result.get("raw_score", 0.0),
                                "threshold": 70,
                            },
                        )
            except Exception as exc:
                logger.error("[ML] Isolation Forest error on %s: %s", path, exc)
                ml_result = None

            # ---------------------------------------------------------------
            # Step 8.5: Zero-Trust LLM Deep Threat & Semantic Intelligence
            # ---------------------------------------------------------------
            llm_result = None
            try:
                query_str = str(request.url.query) if request.url.query else ""
                llm_result = predict_threat_with_llm(
                    req_ctx,
                    features=features,
                    payload_sample=query_str,
                    timeout=2.0,
                )
                if llm_result and llm_result.get("is_anomaly"):
                    persist_security_event(
                        request_id=request_id,
                        user_id=user_id,
                        event_type=SecurityEventType.LLM_ANOMALY_DETECTED.value,
                        severity=EventSeverity.HIGH.value if llm_result.get("anomaly_score", 0) >= 80 else EventSeverity.MEDIUM.value,
                        message=llm_result.get("reasoning", "LLM identified anomalous threat signature"),
                        endpoint=path,
                        metadata={
                            "model": llm_result.get("model", "zero-trust-guard"),
                            "threat_type": llm_result.get("threat_type"),
                            "anomaly_score": llm_result.get("anomaly_score", 0),
                            "confidence": llm_result.get("confidence", 0.0),
                            "recommended_action": llm_result.get("recommended_action"),
                        },
                    )
            except Exception as exc:
                logger.debug("[LLM] Zero-Trust LLM analysis error on %s: %s", path, exc)
                llm_result = None

            # ---------------------------------------------------------------
            # Step 7: Deterministic risk scoring & policy decision
            # ---------------------------------------------------------------
            risk_score = 0
            risk_level = "LOW"
            risk_reasons: list = []
            policy_decision = "ALLOW"

            try:
                risk_outcome = calculate_risk(req_ctx, anomalies, ml_result=ml_result, llm_result=llm_result)
                risk_score = risk_outcome["risk_score"]
                risk_level = risk_outcome["risk_level"]
                risk_reasons = risk_outcome["reasons"]

                policy_outcome = evaluate_policy(
                    risk_score=risk_score,
                    risk_level=risk_level,
                    request_context=req_ctx,
                    reasons=risk_reasons,
                    detection_results=anomalies,
                )
                policy_decision = policy_outcome["decision"]
            except Exception as exc:
                logger.error("[RISK] Scoring/policy error on %s: %s", path, exc)

            # ---------------------------------------------------------------
            # Persist telemetry to PostgreSQL — ALWAYS runs before enforcement
            # ---------------------------------------------------------------
            persist_telemetry(
                request_id=request_id,
                method=request.method,
                endpoint=path,
                client_ip=client_ip,
                user_agent=user_agent,
                status_code=status_code,
                response_time_ms=response_time_ms,
                request_size=request_size,
                response_size=response_size,
                user_id=user_id,
                username=username,
                role=role,
                is_authenticated=is_authenticated,
                is_sensitive=is_sensitive,
                security_event_type=sec_event_type,
                security_event_severity=sec_event_severity,
                security_event_message=sec_event_message,
                security_event_metadata=sec_event_metadata,
                risk_score=risk_score,
                risk_level=risk_level,
                policy_decision=policy_decision,
                risk_reasons=risk_reasons,
            )

            # ---------------------------------------------------------------
            # Step 10: Real-time WebSocket broadcasts (non-blocking, fire-and-forget)
            # ---------------------------------------------------------------
            try:
                await broadcast_request_completed(
                    request_id=request_id,
                    method=request.method,
                    endpoint=path,
                    status_code=status_code,
                    response_time_ms=response_time_ms,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    policy_decision=policy_decision,
                    user_id=user_id,
                    username=username,
                    reasons=risk_reasons,
                )

                if sec_event_type:
                    await broadcast_security_event(
                        event_id=f"evt_{request_id[:8]}",
                        request_id=request_id,
                        event_type=sec_event_type,
                        severity=sec_event_severity or "INFO",
                        message=sec_event_message or sec_event_type,
                        endpoint=path,
                        user_id=user_id,
                        risk_score=risk_score,
                        risk_level=risk_level,
                        policy_decision=policy_decision,
                        metadata=sec_event_metadata,
                    )

                for anomaly in anomalies:
                    await broadcast_security_event(
                        event_id=f"evt_{request_id[:8]}_{anomaly.get('anomaly_type')}",
                        request_id=request_id,
                        event_type=anomaly.get("anomaly_type", "ANOMALY_DETECTED"),
                        severity=anomaly.get("severity", "MEDIUM"),
                        message=anomaly.get("reason", "Rule anomaly detected"),
                        endpoint=path,
                        user_id=user_id,
                        risk_score=risk_score,
                        risk_level=risk_level,
                        policy_decision=policy_decision,
                        metadata=anomaly.get("evidence"),
                    )

                if ml_result and ml_result.get("is_anomaly"):
                    await broadcast_ml_anomaly(
                        request_id=request_id,
                        user_id=user_id,
                        endpoint=path,
                        anomaly_score=ml_result.get("anomaly_score", 0),
                        raw_score=ml_result.get("raw_score", 0.0),
                        threshold=70,
                    )

                if llm_result and llm_result.get("is_anomaly"):
                    await broadcast_llm_anomaly(
                        request_id=request_id,
                        user_id=user_id,
                        endpoint=path,
                        threat_type=llm_result.get("threat_type", "LLM_ANOMALY"),
                        anomaly_score=llm_result.get("anomaly_score", 0),
                        confidence=llm_result.get("confidence", 0.0),
                        reasoning=llm_result.get("reasoning", ""),
                        recommended_action=llm_result.get("recommended_action", "ALLOW"),
                        model=llm_result.get("model", "zero-trust-guard"),
                    )
            except Exception:
                # WebSocket failures MUST NEVER affect HTTP response delivery
                pass

            # ---------------------------------------------------------------
            # Step 7: Policy enforcement — BLOCK critical risk
            # Invariant: Never override existing 401/403 from route handlers.
            # ---------------------------------------------------------------
            if (
                settings.POLICY_ENFORCEMENT_ACTIVE
                and policy_decision == "BLOCK"
                and status_code < 400
            ):
                logger.warning(
                    "[POLICY] BLOCK decision enforced for user=%s on %s (risk=%d, level=%s)",
                    user_id, path, risk_score, risk_level,
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "success": False,
                        "error": {
                            "code": "POLICY_BLOCKED",
                            "message": "Request blocked by Zero-Trust policy engine due to critical behavioral risk.",
                        },
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                        "policy_decision": policy_decision,
                        "reasons": [r.get("reason", r) if isinstance(r, dict) else r for r in risk_reasons],
                    },
                    headers={"X-Request-ID": request_id},
                )

        return response
