"""Domain models, enums, and schemas for Risk Scoring and Policy Decisions (Step 7)."""

from datetime import datetime
import enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RiskLevel(str, enum.Enum):
    """Categorical risk tiers based on calculated score."""
    LOW = "LOW"            # 0 - 30
    MEDIUM = "MEDIUM"      # 31 - 60
    HIGH = "HIGH"          # 61 - 80
    CRITICAL = "CRITICAL"  # 81 - 100


class PolicyDecision(str, enum.Enum):
    """Zero-Trust enforcement decisions derived from risk tier."""
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    RATE_LIMIT = "RATE_LIMIT"
    CHALLENGE = "CHALLENGE"  # Reserved for future MFA/challenge extension
    BLOCK = "BLOCK"


class RiskReason(BaseModel):
    """Human-readable explainability factor for an additive risk contribution."""
    signal: str = Field(..., description="Security anomaly or risk signal identifier")
    points: int = Field(..., description="Additive weight contributed to risk score")
    description: str = Field(..., description="Explainable description of the risk indicator")


class RiskAssessment(BaseModel):
    """Comprehensive risk scoring outcome for an evaluated request."""
    risk_score: int = Field(..., ge=0, le=100, description="Deterministic risk score clamped between 0 and 100")
    risk_level: str = Field(..., description="Risk tier: LOW, MEDIUM, HIGH, CRITICAL")
    reasons: List[RiskReason] = Field(default_factory=list, description="List of explainable contributing factors")


class PolicyEvaluation(BaseModel):
    """Enforcement policy outcome produced by the policy engine."""
    decision: str = Field(..., description="Actionable policy decision: ALLOW, MONITOR, RATE_LIMIT, BLOCK")
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: str = Field(...)
    reasons: List[RiskReason] = Field(default_factory=list)


class PolicyRuleConfig(BaseModel):
    """Configured risk tier to policy decision mapping."""
    risk_level: str
    min_score: int
    max_score: int
    decision: str
