"""Database models for Zero-Trust API Security & Behavioral Anomaly Engine.

Step 5 introduces persistent behavior baseline profiles (behavior_profiles).
"""

from datetime import datetime, timezone
import enum
from typing import Any, Dict, List, Optional
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.connection import Base


class UserRole(str, enum.Enum):
    """Supported roles in the Zero-Trust system."""
    USER = "USER"
    ADMIN = "ADMIN"


class SecurityEventType(str, enum.Enum):
    """Recognized security event classifications for Step 4 & Step 6."""
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"
    AUTHORIZATION_FAILURE = "AUTHORIZATION_FAILURE"
    SENSITIVE_ENDPOINT_ACCESS = "SENSITIVE_ENDPOINT_ACCESS"
    REQUEST_COMPLETED = "REQUEST_COMPLETED"

    # Step 6 Rule-Based Anomaly Types
    API_ABUSE = "API_ABUSE"
    CREDENTIAL_ATTACK = "CREDENTIAL_ATTACK"
    UNKNOWN_DEVICE = "UNKNOWN_DEVICE"
    LOCATION_ANOMALY = "LOCATION_ANOMALY"
    PRIVILEGE_MISUSE = "PRIVILEGE_MISUSE"
    UNUSUAL_TIME = "UNUSUAL_TIME"


class EventSeverity(str, enum.Enum):
    """Static severity levels for security and anomaly events."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class BaselineStatus(str, enum.Enum):
    """Maturity classifications for user behavior baselines (Step 5)."""
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"  # 0-9 requests
    LEARNING = "LEARNING"                    # 10-49 requests
    ESTABLISHED = "ESTABLISHED"              # 50+ requests


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
    behavior_profile: Mapped[Optional["BehaviorProfile"]] = relationship(
        "BehaviorProfile", back_populates="user", uselist=False, cascade="all, delete-orphan"
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
    event_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column("metadata", JSON, nullable=True)

    # Relationship to user
    user: Mapped[Optional["User"]] = relationship("User", back_populates="security_events")


class BehaviorProfile(Base):
    """Behavioral baseline profile established for each identity based on historical telemetry."""
    __tablename__ = "behavior_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True, nullable=False
    )
    avg_requests_per_minute: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    avg_unique_endpoints: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    avg_failed_requests: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    avg_sensitive_access: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    normal_hours: Mapped[List[int]] = mapped_column(JSON, default=list, nullable=False)
    known_devices: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    known_ips: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    avg_response_time: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    avg_request_size: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    avg_response_size: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    baseline_status: Mapped[str] = mapped_column(
        String(30), default=BaselineStatus.INSUFFICIENT_DATA.value, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationship to user
    user: Mapped["User"] = relationship("User", back_populates="behavior_profile")


__all__ = [
    "Base",
    "User",
    "UserRole",
    "ApiRequestLog",
    "SecurityEvent",
    "SecurityEventType",
    "EventSeverity",
    "BehaviorProfile",
    "BaselineStatus",
]
