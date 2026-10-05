"""Policy decision engine mapping risk evaluations to Zero-Trust actions (Step 7).

Policy Mapping:
  - LOW (0-30):       ALLOW
  - MEDIUM (31-60):   MONITOR
  - HIGH (61-80):     RATE_LIMIT
  - CRITICAL (81-100): BLOCK (with safety validation on strong security signals)
"""

from typing import Any, Dict, List, Optional
from app.risk.models import PolicyDecision, RiskLevel

# Static baseline policy mapping rules (Read-only for Step 7)
POLICY_RULES = [
    {"risk_level": RiskLevel.LOW.value, "min_score": 0, "max_score": 30, "decision": PolicyDecision.ALLOW.value},
    {"risk_level": RiskLevel.MEDIUM.value, "min_score": 31, "max_score": 60, "decision": PolicyDecision.MONITOR.value},
    {"risk_level": RiskLevel.HIGH.value, "min_score": 61, "max_score": 80, "decision": PolicyDecision.RATE_LIMIT.value},
    {"risk_level": RiskLevel.CRITICAL.value, "min_score": 81, "max_score": 100, "decision": PolicyDecision.BLOCK.value},
]

# Signals considered strong security threats justifying automated blocking
STRONG_BLOCKING_SIGNALS = {"CREDENTIAL_ATTACK", "API_ABUSE", "PRIVILEGE_MISUSE"}


def evaluate_policy(
    risk_score: int,
    risk_level: str,
    request_context: Optional[Any] = None,
    reasons: Optional[List[Dict[str, Any]]] = None,
    detection_results: Optional[Any] = None,
) -> Dict[str, Any]:
    """Evaluates the Zero-Trust policy decision for an analyzed request.

    Args:
        risk_score: Calculated risk score (0 to 100).
        risk_level: Categorical risk tier ("LOW", "MEDIUM", "HIGH", "CRITICAL").
        request_context: Optional RequestContext or dictionary.
        reasons: Optional list of explainable risk reason dicts.
        detection_results: Optional detected anomaly list or dictionary.

    Returns:
        Dictionary containing:
          - decision: "ALLOW" | "MONITOR" | "RATE_LIMIT" | "BLOCK"
          - risk_score: int
          - risk_level: str
          - reasons: list
    """
    reasons_list = reasons or []

    # Map standard categorical tiers
    if risk_level == RiskLevel.LOW.value:
        decision = PolicyDecision.ALLOW.value
    elif risk_level == RiskLevel.MEDIUM.value:
        decision = PolicyDecision.MONITOR.value
    elif risk_level == RiskLevel.HIGH.value:
        decision = PolicyDecision.RATE_LIMIT.value
    elif risk_level == RiskLevel.CRITICAL.value:
        # Blocking Safety: Verify presence of at least one strong security signal
        active_signals = {r.get("signal") for r in reasons_list if isinstance(r, dict)}

        # If detection_results passed, extract signals as well
        if detection_results:
            anom_list = detection_results.get("anomalies", []) if isinstance(detection_results, dict) else detection_results
            for a in anom_list:
                s = a.get("type") if isinstance(a, dict) else getattr(a, "anomaly_type", None)
                if s:
                    active_signals.add(s)

        if active_signals & STRONG_BLOCKING_SIGNALS:
            decision = PolicyDecision.BLOCK.value
        else:
            # Fallback to RATE_LIMIT to avoid falsely blocking traffic without strong malicious signals
            decision = PolicyDecision.RATE_LIMIT.value
    else:
        decision = PolicyDecision.ALLOW.value

    return {
        "decision": decision,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons": reasons_list,
    }


# Dynamic policy configuration with defaults
POLICY_CONFIG = {
    "tiers": list(POLICY_RULES),
    "rate_limits": {
        "global_per_min": 100,
        "burst_per_5s": 20,
    },
    "modules": {
        "mfa_enforcement": True,
        "rate_limiting": True,
        "ip_geofence": True,
        "ml_anomaly_scoring": True,
        "automated_blocking": True,
        "credential_stuffing_defense": True,
    }
}


def get_configured_policies() -> List[Dict[str, Any]]:
    """Returns the active policy tier configuration."""
    return list(POLICY_CONFIG["tiers"])


def get_full_policy_config() -> Dict[str, Any]:
    """Returns the full policy configuration including rate limits and active modules."""
    return dict(POLICY_CONFIG)


def update_configured_policies(data: Dict[str, Any]) -> Dict[str, Any]:
    """Updates active policy tiers, thresholds, or module switches."""
    global POLICY_CONFIG
    if "tiers" in data and isinstance(data["tiers"], list):
        POLICY_CONFIG["tiers"] = data["tiers"]
    if "rate_limits" in data and isinstance(data["rate_limits"], dict):
        POLICY_CONFIG["rate_limits"].update(data["rate_limits"])
    if "modules" in data and isinstance(data["modules"], dict):
        POLICY_CONFIG["modules"].update(data["modules"])
    return dict(POLICY_CONFIG)

