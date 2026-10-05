"""API Gateway Middleware handling Request ID generation, IP extraction, response timing, and persistent telemetry."""

import time
import uuid
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.database.models import EventSeverity, SecurityEventType
from app.gateway.telemetry_logger import persist_telemetry
from app.security.privilege import is_sensitive_endpoint

# Protected API path prefixes subject to Zero-Trust telemetry and inspection
PROTECTED_PATH_PREFIXES = (
    "/api/profile",
    "/api/orders",
    "/api/payment",
    "/api/users",
    "/api/admin",
    "/api/requests",
    "/api/security/events",
    "/api/test/protected",
)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Middleware that injects Request ID, measures latency, and writes security telemetry to PostgreSQL."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start_time = time.perf_counter()

        # 1. Request ID handling
        incoming_request_id = request.headers.get("X-Request-ID")
        if incoming_request_id:
            try:
                # Sanitize incoming UUID representation
                request_id = str(uuid.UUID(incoming_request_id))
            except ValueError:
                request_id = str(uuid.uuid4())
        else:
            request_id = str(uuid.uuid4())

        # 2. Capture client IP and User-Agent without blindly trusting spoofable headers
        client_ip = request.client.host if request.client else "127.0.0.1"
        user_agent = request.headers.get("user-agent", "unknown")
        request_size = int(request.headers.get("content-length", 0))

        request.state.request_id = request_id
        request.state.client_ip = client_ip
        request.state.user_agent = user_agent

        # 3. Process the downstream request
        response = await call_next(request)

        # 4. Inject X-Request-ID into response header
        response.headers["X-Request-ID"] = request_id

        # 5. Measure latency and response size
        response_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        response_size = int(response.headers.get("content-length", 0))

        # 6. Check if this is a protected API endpoint requiring persistent telemetry
        path = request.url.path
        is_protected = any(path.startswith(prefix) for prefix in PROTECTED_PATH_PREFIXES)

        if is_protected:
            context = getattr(request.state, "context", None)
            is_sensitive = is_sensitive_endpoint(path)
            status_code = response.status_code

            user_id = context.user_id if context else None
            username = context.username if context else None
            role = context.role if context else None
            is_authenticated = bool(context and context.is_authenticated)

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

            # Persist telemetry to PostgreSQL (non-blocking failure behavior)
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
            )

        return response
