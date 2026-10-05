"""Gateway dependencies for security context injection and role-based authorization."""

from datetime import datetime, timezone
import logging
from typing import List, Optional
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.auth.jwt import decode_access_token
from app.database.connection import get_db
from app.database.models import User, UserRole
from app.gateway.request_context import RequestContext
from app.security.privilege import is_sensitive_endpoint

logger = logging.getLogger("zero_trust.gateway")

security_bearer = HTTPBearer(auto_error=False)


class SecurityGatewayException(HTTPException):
    """Structured security exception following Zero-Trust gateway format."""

    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(
            status_code=status_code,
            detail={"code": code, "message": message},
        )
        self.code = code
        self.message = message


def get_gateway_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    db: Session = Depends(get_db),
) -> User:
    """Authenticates the Bearer JWT token and returns the active User principal.

    Raises:
        SecurityGatewayException 401: If token is missing, invalid, expired, or user not found.
        SecurityGatewayException 403: If user account is inactive.
    """
    if not credentials or not credentials.credentials:
        raise SecurityGatewayException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="UNAUTHORIZED",
            message="Authentication required",
        )

    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        user_id_raw = payload.get("sub")
        if user_id_raw is None:
            raise SecurityGatewayException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                code="UNAUTHORIZED",
                message="Authentication required",
            )
        user_id = int(user_id_raw)
    except (JWTError, ValueError):
        raise SecurityGatewayException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="UNAUTHORIZED",
            message="Authentication required",
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise SecurityGatewayException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="UNAUTHORIZED",
            message="Authentication required",
        )

    if not user.is_active:
        raise SecurityGatewayException(
            status_code=status.HTTP_403_FORBIDDEN,
            code="FORBIDDEN",
            message="User account is inactive",
        )

    return user


def build_request_context(request: Request, user: User) -> RequestContext:
    """Constructs a comprehensive RequestContext object from request telemetry and authenticated identity."""
    request_id = getattr(request.state, "request_id", "req-unknown")
    client_ip = getattr(request.state, "client_ip", "127.0.0.1")
    user_agent = getattr(request.state, "user_agent", "unknown")
    endpoint = request.url.path
    method = request.method
    timestamp = datetime.now(timezone.utc)
    is_sensitive = is_sensitive_endpoint(endpoint)

    return RequestContext(
        request_id=request_id,
        user_id=user.id,
        username=user.name,
        role=user.role,
        client_ip=client_ip,
        user_agent=user_agent,
        method=method,
        endpoint=endpoint,
        timestamp=timestamp,
        is_authenticated=True,
        is_sensitive_endpoint=is_sensitive,
    )


class RequireRoles:
    """Dependency callable enforcing role-based access control and attaching RequestContext."""

    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    def __call__(
        self,
        request: Request,
        user: User = Depends(get_gateway_user),
    ) -> RequestContext:
        context = build_request_context(request, user)
        # Store context in request.state for observability
        request.state.context = context

        if context.role not in self.allowed_roles:
            logger.warning(
                "Access Denied (403): User id=%s (role=%s) attempted to access %s (requires %s)",
                context.user_id,
                context.role,
                context.endpoint,
                self.allowed_roles,
            )
            raise SecurityGatewayException(
                status_code=status.HTTP_403_FORBIDDEN,
                code="FORBIDDEN",
                message="Insufficient privileges",
            )

        logger.info(
            "Access Granted (200): User id=%s (role=%s) -> %s [sensitive=%s, req_id=%s]",
            context.user_id,
            context.role,
            context.endpoint,
            context.is_sensitive_endpoint,
            context.request_id,
        )
        return context


def require_role(*roles: str):
    """Helper factory for declaring required roles on protected endpoints."""
    return RequireRoles(list(roles))


# Predefined convenience dependencies
require_user_or_admin = RequireRoles([UserRole.USER.value, UserRole.ADMIN.value])
require_admin_only = RequireRoles([UserRole.ADMIN.value])
