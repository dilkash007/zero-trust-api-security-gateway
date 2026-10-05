"""API Gateway Middleware handling Request ID generation, IP extraction, and response headers."""

import uuid
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Middleware that injects a unique Request ID and captures client telemetry."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Check for existing X-Request-ID from trusted client, otherwise generate new UUID4
        incoming_request_id = request.headers.get("X-Request-ID")
        if incoming_request_id:
            try:
                # Sanitize: verify it is a valid UUID representation
                request_id = str(uuid.UUID(incoming_request_id))
            except ValueError:
                request_id = str(uuid.uuid4())
        else:
            request_id = str(uuid.uuid4())

        # Extract client IP without blindly trusting spoofable proxy headers
        client_ip = request.client.host if request.client else "127.0.0.1"

        # Extract User-Agent with fallback
        user_agent = request.headers.get("user-agent", "unknown")

        # Attach to request state for downstream dependencies
        request.state.request_id = request_id
        request.state.client_ip = client_ip
        request.state.user_agent = user_agent

        response = await call_next(request)

        # Inject X-Request-ID into response header
        response.headers["X-Request-ID"] = request_id

        return response
