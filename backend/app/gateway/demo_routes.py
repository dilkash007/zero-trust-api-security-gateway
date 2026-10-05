"""Protected demo API endpoints demonstrating Zero-Trust Gateway interception and role enforcement."""

from fastapi import APIRouter, Depends, status
from app.gateway.dependencies import require_admin_only, require_user_or_admin
from app.gateway.request_context import RequestContext

demo_router = APIRouter(prefix="/api", tags=["Protected Demo APIs"])


def _format_security_context(ctx: RequestContext) -> dict:
    """Extracts safe diagnostic security context metadata without exposing credentials."""
    return {
        "request_id": ctx.request_id,
        "role": ctx.role,
        "endpoint": ctx.endpoint,
        "method": ctx.method,
        "sensitive": ctx.is_sensitive_endpoint,
        "client_ip": ctx.client_ip,
        "user_agent": ctx.user_agent,
    }


@demo_router.get(
    "/profile",
    status_code=status.HTTP_200_OK,
    summary="User profile endpoint (Normal sensitivity, USER or ADMIN)",
)
def get_profile(context: RequestContext = Depends(require_user_or_admin)):
    """User profile data protected by the Zero-Trust Gateway."""
    return {
        "success": True,
        "data": {
            "endpoint": "/api/profile",
            "message": "Profile data accessed",
            "user_id": context.user_id,
            "username": context.username,
        },
        "security_context": _format_security_context(context),
    }


@demo_router.get(
    "/orders",
    status_code=status.HTTP_200_OK,
    summary="Orders endpoint (Normal sensitivity, USER or ADMIN)",
)
def get_orders(context: RequestContext = Depends(require_user_or_admin)):
    """Customer order history protected by the Zero-Trust Gateway."""
    return {
        "success": True,
        "data": {
            "endpoint": "/api/orders",
            "message": "Orders data accessed",
            "user_id": context.user_id,
            "total_orders": 3,
        },
        "security_context": _format_security_context(context),
    }


@demo_router.get(
    "/payment",
    status_code=status.HTTP_200_OK,
    summary="Payment endpoint (SENSITIVE, USER or ADMIN)",
)
def get_payment(context: RequestContext = Depends(require_user_or_admin)):
    """Sensitive payment processing verification endpoint."""
    return {
        "success": True,
        "data": {
            "endpoint": "/api/payment",
            "message": "Protected payment endpoint accessed",
            "sensitive": True,
        },
        "security_context": _format_security_context(context),
    }


@demo_router.get(
    "/users",
    status_code=status.HTTP_200_OK,
    summary="Administrative users overview (SENSITIVE, ADMIN only)",
)
def get_users(context: RequestContext = Depends(require_admin_only)):
    """Administrative user management endpoint accessible only to ADMIN role."""
    return {
        "success": True,
        "data": {
            "endpoint": "/api/users",
            "message": "Administrative user data accessed",
        },
        "security_context": _format_security_context(context),
    }


@demo_router.get(
    "/admin/users",
    status_code=status.HTTP_200_OK,
    summary="Admin users list (SENSITIVE, ADMIN only)",
)
def get_admin_users(context: RequestContext = Depends(require_admin_only)):
    """Restricted administrative user listing endpoint."""
    return {
        "success": True,
        "data": {
            "endpoint": "/api/admin/users",
            "message": "Administrative user list accessed",
            "sensitive": True,
        },
        "security_context": _format_security_context(context),
    }


@demo_router.get(
    "/admin/transactions",
    status_code=status.HTTP_200_OK,
    summary="Admin transaction audit (SENSITIVE, ADMIN only)",
)
def get_admin_transactions(context: RequestContext = Depends(require_admin_only)):
    """Restricted administrative audit transaction records."""
    return {
        "success": True,
        "data": {
            "endpoint": "/api/admin/transactions",
            "message": "Administrative transaction logs accessed",
            "sensitive": True,
        },
        "security_context": _format_security_context(context),
    }
