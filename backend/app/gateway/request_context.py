"""Gateway Request Context model for Zero-Trust API inspection."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class RequestContext(BaseModel):
    """Context captured for every inspected API request in the Zero-Trust Gateway."""

    request_id: str = Field(..., description="Unique UUID for this transaction")
    user_id: Optional[int] = Field(None, description="Authenticated User ID")
    username: Optional[str] = Field(None, description="Authenticated User identifier (email/name)")
    role: Optional[str] = Field(None, description="Identity role (USER or ADMIN)")
    client_ip: str = Field(..., description="Observed client IP address")
    user_agent: str = Field(default="unknown", description="Client device/browser User-Agent")
    method: str = Field(..., description="HTTP Method (GET, POST, etc.)")
    endpoint: str = Field(..., description="Requested API path")
    timestamp: datetime = Field(..., description="UTC timestamp of the request")
    is_authenticated: bool = Field(default=False, description="Whether request is authenticated")
    is_sensitive_endpoint: bool = Field(default=False, description="Whether endpoint requires elevated sensitivity")
