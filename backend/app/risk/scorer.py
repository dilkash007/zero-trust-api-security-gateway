"""Deterministic additive risk scoring engine (Step 7).

Evaluates security signals from Step 4-6 into a normalized 0-100 risk score,
categorical risk tier, and human-explainable contributing reasons.
"""

from typing import Any, Dict, List, Optional, Set
from app.risk.models import RiskLevel

# Prescribed additive signal weights and canonical explainability descriptions
SIGNAL_METADATA = {
    "UNKNOWN_DEVICE": (18, "Request originated from an unrecognized device User-Agent."),
    "LOCATION_ANOMALY": (20, "Request originated from an IP address not previously observed for this user."),
    "API_ABUSE": (24, "Request frequency is significantly higher than the user's normal baseline."),
    "PRIVILEGE_MISUSE": (20, "Unauthorized attempt to access privileged sensitive endpoint."),
    "CREDENTIAL_ATTACK": (25, "Failed request volume exceeds normal baseline threshold."),
    "UNUSUAL_TIME": (8, "API accessed outside user's established normal operational hours."),
    "SENSITIVE_ENDPOINT": (10, "Request accessed an elevated sensitive API endpoint."),
    "ML_ANOMALY": (12, "Behavior differs significantly from the learned baseline"),
    "LLM_ANOMALY": (15, "AI LLM identified threat signature or payload anomaly"),
}



def get_risk_level(score: int) -> str:
    """Maps a clamped 0-100 score to its deterministic risk level.

    Ranges:
      0–30:   LOW
      31–60:  MEDIUM
      61–80:  HIGH
      81–100: CRITICAL
    """
    if score <= 30:
        return RiskLevel.LOW.value
    elif score <= 60:
        return RiskLevel.MEDIUM.value
    elif score <= 80:
        return RiskLevel.HIGH.value
    else:
        return RiskLevel.CRITICAL.value


# Alias for backward compatibility
_score_to_risk_level = get_risk_level


def calculate_risk(
    request_context: Any,
    detection_results: Any,
    behavior_features: Optional[Dict[str, Any]] = None,
    ml_result: Optional[Dict[str, Any]] = None,
    llm_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Calculates a deterministic risk assessment for a request.

    Args:
        request_context: RequestContext instance or dictionary.
        detection_results: List of detected anomaly dictionaries, DetectionResult objects,
                           or a detection engine result dict with key 'anomalies'.
        behavior_features: Optional live feature snapshot dictionary.

    Returns:
        Dictionary containing:
          - risk_score: int (0 to 100)
          - risk_level: str ("LOW", "MEDIUM", "HIGH", "CRITICAL")
          - reasons: list of explainable risk reason dicts
    """
    reasons: List[Dict[str, Any]] = []
    seen_signals: Set[str] = set()

    # 1. Normalize detection results into a clean list of anomaly type strings
    anomaly_list: List[Dict[str, Any]] = []
    if isinstance(detection_results, dict) and "anomalies" in detection_results:
        anomaly_list = detection_results["anomalies"]
    elif isinstance(detection_results, list):
        anomaly_list = detection_results

    for anom in anomaly_list:
        anom_type = None
        if isinstance(anom, dict):
            anom_type = anom.get("anomaly_type") or anom.get("type") or anom.get("signal")
        elif hasattr(anom, "anomaly_type"):
            anom_type = getattr(anom, "anomaly_type")
        elif hasattr(anom, "type"):
            anom_type = getattr(anom, "type")

        if anom_type and anom_type in SIGNAL_METADATA and anom_type not in seen_signals:
            points, default_desc = SIGNAL_METADATA[anom_type]
            # Use custom reason if available, else default canonical description
            custom_desc = anom.get("reason") if isinstance(anom, dict) else getattr(anom, "reason", None)
            reasons.append({
                "signal": anom_type,
                "points": points,
                "description": custom_desc or default_desc,
            })
            seen_signals.add(anom_type)

    # 2. Extract sensitive endpoint status from request context
    is_sensitive = False
    if hasattr(request_context, "is_sensitive_endpoint"):
        is_sensitive = bool(request_context.is_sensitive_endpoint)
    elif isinstance(request_context, dict):
        is_sensitive = bool(request_context.get("is_sensitive", False) or request_context.get("is_sensitive_endpoint", False))

    # 3. Double-counting protection:
    # PRIVILEGE_MISUSE (+20) already encapsulates sensitive endpoint violation.
    # Only add +10 if PRIVILEGE_MISUSE was NOT detected.
    if is_sensitive and "PRIVILEGE_MISUSE" not in seen_signals:
        points, desc = SIGNAL_METADATA["SENSITIVE_ENDPOINT"]
        reasons.append({
            "signal": "SENSITIVE_ENDPOINT",
            "points": points,
            "description": desc,
        })
        seen_signals.add("SENSITIVE_ENDPOINT")

    # 4. Step 8 ML Anomaly Detection signal (+12 points)
    if ml_result and ml_result.get("is_anomaly") and "ML_ANOMALY" not in seen_signals:
        points, desc = SIGNAL_METADATA["ML_ANOMALY"]
        reasons.append({
            "signal": "ML_ANOMALY",
            "points": points,
            "description": desc,
        })
        seen_signals.add("ML_ANOMALY")

    # 5. Zero-Trust LLM Threat Detection signal (+15 points)
    if llm_result and llm_result.get("is_anomaly") and "LLM_ANOMALY" not in seen_signals:
        points, desc = SIGNAL_METADATA["LLM_ANOMALY"]
        custom_desc = llm_result.get("reasoning") or desc
        reasons.append({
            "signal": "LLM_ANOMALY",
            "points": points,
            "description": custom_desc,
        })
        seen_signals.add("LLM_ANOMALY")

    # 6. Sum additive weights and clamp between 0 and 100
    total_points = sum(r["points"] for r in reasons)
    clamped_score = min(max(total_points, 0), 100)

    # 6. Resolve categorical risk tier
    risk_tier = get_risk_level(clamped_score)

    return {
        "risk_score": clamped_score,
        "risk_level": risk_tier,
        "reasons": reasons,
    }
