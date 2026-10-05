"""Database models for Zero-Trust API Security & Behavioral Anomaly Engine.

Step 4 introduces persistent request telemetry (api_request_logs)
and security events (security_events).
"""

from datetime import datetime, timezone
import enum
from typing import Any, Dict, Optional
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.connection import Base


class UserRole(str, enum.Enum):
    """Supported roles in the Zero-Trust system."""
    USER = "USER"
    ADMIN = "ADMIN"


class SecurityEventType(str, enum.Enum):
    """Recognized security event classifications for Step 4."""
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"
    AUTHORIZATION_FAILURE = "AUTHORIZATION_FAILURE"
    SENSITIVE_ENDPOINT_ACCESS = "SENSITIVE_ENDPOINT_ACCESS"
    REQUEST_COMPLETED = "REQUEST_COMPLETED"


class EventSeverity(str, enum.Enum):
    """Static severity levels for security events."""
    INFO = "INFO"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class User(Base):
    """User account entity for authentication and identity management."""
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default=UserRole.USER.value, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    request_logs: Mapped[list["ApiRequestLog"]] = relationship(
        "ApiRequestLog", back_populates="user", cascade="all, delete-orphan"
    )
    security_events: Mapped[list["SecurityEvent"]] = relationship(
        "SecurityEvent", back_populates="user", cascade="all, delete-orphan"
    )


class ApiRequestLog(Base):
    """Persistent audit log of inspected API requests passing through the gateway."""
    __tablename__ = "api_request_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    request_id: Mapped[str] = mapped_column(String(36), unique=True, index=True, nullable=False)
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    role: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    client_ip: Mapped[str] = mapped_column(String(50), nullable=False)
    user_agent: Mapped[str] = mapped_column(Text, nullable=False, default="unknown")
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    response_time_ms: Mapped[float] = mapped_column(Float, nullable=False)
    request_size: Mapped[Optional[int]] = mapped_column(Integer, default=0, nullable=True)
    response_size: Mapped[Optional[int]] = mapped_column(Integer, default=0, nullable=True)
    is_authenticated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_sensitive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationship to user
    user: Mapped[Optional["User"]] = relationship("User", back_populates="request_logs")


class SecurityEvent(Base):
    """Audit log of high-value security events (auth failures, privilege violations, sensitive access)."""
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(36), unique=True, index=True, nullable=False)
    request_id: Mapped[Optional[str]] = mapped_column(String(36), index=True, nullable=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    event_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    message: Mapped[str] = mapped_column(String(255), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )
    # Map attribute event_metadata to column 'metadata' to avoid SQLAlchemy Base.metadata collision
    event_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column("metadata", JSON, nullable=True)

    # Relationship to user
    user: Mapped[Optional["User"]] = relationship("User", back_populates="security_events")


__all__ = [
    "Base",
    "User",
    "UserRole",
    "ApiRequestLog",
    "SecurityEvent",
    "SecurityEventType",
    "EventSeverity",
]
