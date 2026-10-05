"""Security classification and authorization package."""
from app.security.privilege import SENSITIVE_ENDPOINTS, is_sensitive_endpoint

__all__ = ["SENSITIVE_ENDPOINTS", "is_sensitive_endpoint"]
