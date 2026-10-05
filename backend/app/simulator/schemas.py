"""Pydantic schemas for the Zero-Trust local attack simulator (Step 8)."""

import enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ScenarioEnum(str, enum.Enum):
    """Supported local demonstration attack scenarios."""
    API_ABUSE = "API_ABUSE"
    CREDENTIAL_ATTACK = "CREDENTIAL_ATTACK"
    PRIVILEGE_MISUSE = "PRIVILEGE_MISUSE"
    UNKNOWN_DEVICE = "UNKNOWN_DEVICE"
    LOCATION_ANOMALY = "LOCATION_ANOMALY"
    COMBINED_ATTACK = "COMBINED_ATTACK"


class SimulationRequest(BaseModel):
    """Trigger payload for launching a local attack simulation scenario."""
    scenario: ScenarioEnum = Field(..., description="Target security simulation scenario")


class SimulationResponse(BaseModel):
    """Result report returned after executing real HTTP simulation traffic."""
    scenario: str = Field(..., description="Executed scenario name")
    status: str = Field(default="completed", description="Execution status")
    requests_generated: int = Field(..., description="Count of actual HTTP requests sent to local API")
    message: str = Field(..., description="Summary of simulation outcome")
    details: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic outcome and observed security posture")
