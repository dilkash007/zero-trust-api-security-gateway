"""Security classification and privilege configuration module."""

from typing import Set

# Centralized registry of sensitive API endpoints
SENSITIVE_ENDPOINTS: Set[str] = {
    "/api/payment",
    "/api/users",
    "/api/admin/users",
    "/api/admin/transactions",
}


def is_sensitive_endpoint(path: str) -> bool:
    """Classifies whether an endpoint path is deemed sensitive.

    Used by the Zero-Trust Security Gateway to determine elevated scrutiny.
    """
    normalized = path.rstrip("/") if len(path) > 1 else path
    return normalized in SENSITIVE_ENDPOINTS


__all__ = ["SENSITIVE_ENDPOINTS", "is_sensitive_endpoint"]
