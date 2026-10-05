"""Rule definitions for Zero-Trust behavioral anomaly detection (Step 6).

Implements explainable, rule-based heuristics that compare live request context and features
against Step 5 user behavior profiles.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from app.database.models import BaselineStatus, EventSeverity, SecurityEventType


@dataclass
class DetectionResult:
    """Individual anomaly detection outcome."""
    detected: bool
    anomaly_type: Optional[str] = None
    severity: Optional[str] = None
    reason: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)


def rule_api_abuse(
    current_features: Dict[str, Any],
    profile: Optional[Any],
) -> Optional[DetectionResult]:
    """Rule 4: Detects abrupt request burst/frequency spikes compared to user's baseline.

    Condition: current_requests_per_minute > baseline_average * 5
    Severity: HIGH
    Safety:
      - INSUFFICIENT_DATA: Suppressed to prevent premature false positives.
      - LEARNING: Conservative threshold (requires 5x baseline AND >= 20 req/min).
      - ESTABLISHED: Normal 5x baseline threshold (with >= 10 req/min minimum floor).
    """
    if not profile:
        return None

    status = getattr(profile, "baseline_status", BaselineStatus.INSUFFICIENT_DATA)
    if status == BaselineStatus.INSUFFICIENT_DATA:
        return None

    current_rpm = float(current_features.get("requests_per_minute", 0.0))
    baseline_rpm = float(getattr(profile, "avg_requests_per_minute", 0.0) or 1.0)

    if status == BaselineStatus.LEARNING:
        threshold = max(baseline_rpm * 5.0, 20.0)
    else:  # ESTABLISHED
        threshold = max(baseline_rpm * 5.0, 10.0)

    if current_rpm > threshold:
        return DetectionResult(
            detected=True,
            anomaly_type=SecurityEventType.API_ABUSE.value,
            severity=EventSeverity.HIGH.value,
            reason="Request frequency is significantly higher than the user's normal behavior.",
            evidence={
                "current_requests_per_minute": round(current_rpm, 2),
                "baseline_requests_per_minute": round(baseline_rpm, 2),
                "threshold": round(threshold, 2),
                "threshold_multiplier": 5,
                "baseline_status": status,
            },
        )
    return None


def rule_failed_request_burst(
    current_features: Dict[str, Any],
    profile: Optional[Any],
) -> Optional[DetectionResult]:
    """Rule 5: Detects surges in failed requests (4xx/5xx) indicating potential brute-force or credential stuffing.

    Condition: current_failed_requests > baseline_failed_requests * 5 (fallback: >= 5 failed requests)
    Severity: HIGH
    Safety:
      - INSUFFICIENT_DATA: Only flags if absolute threshold (>= 5 failed requests) is reached.
      - LEARNING/ESTABLISHED: Flags if >= max(baseline * 5, 5).
    """
    current_failed = int(current_features.get("failed_requests", 0))
    if current_failed <= 0:
        return None

    status = (
        getattr(profile, "baseline_status", BaselineStatus.INSUFFICIENT_DATA)
        if profile
        else BaselineStatus.INSUFFICIENT_DATA
    )
    baseline_failed = float(getattr(profile, "avg_failed_requests", 0.0) or 0.0) if profile else 0.0

    if status == BaselineStatus.INSUFFICIENT_DATA:
        if current_failed >= 5:
            return DetectionResult(
                detected=True,
                anomaly_type=SecurityEventType.CREDENTIAL_ATTACK.value,
                severity=EventSeverity.HIGH.value,
                reason="High volume of failed requests detected without established baseline history.",
                evidence={
                    "current_failed_requests": current_failed,
                    "absolute_threshold": 5,
                    "baseline_status": BaselineStatus.INSUFFICIENT_DATA,
                },
            )
        return None

    # LEARNING or ESTABLISHED
    threshold = max(baseline_failed * 5.0, 5.0)
    if current_failed >= threshold:
        return DetectionResult(
            detected=True,
            anomaly_type=SecurityEventType.CREDENTIAL_ATTACK.value,
            severity=EventSeverity.HIGH.value,
            reason="Failed request volume exceeds normal baseline threshold.",
            evidence={
                "current_failed_requests": current_failed,
                "baseline_failed_requests": round(baseline_failed, 2),
                "threshold": round(threshold, 2),
                "baseline_status": status,
            },
        )
    return None


def rule_unknown_device(
    current_device: str,
    profile: Optional[Any],
) -> Optional[DetectionResult]:
    """Rule 6: Detects requests arriving from an unobserved User-Agent device string.

    Condition: current_device NOT IN known_devices
    Severity: MEDIUM
    Safety: Suppressed during INSUFFICIENT_DATA or if profile has no known devices.
    """
    if not profile or not current_device or current_device == "unknown":
        return None

    status = getattr(profile, "baseline_status", BaselineStatus.INSUFFICIENT_DATA)
    if status == BaselineStatus.INSUFFICIENT_DATA:
        return None

    known_devices = getattr(profile, "known_devices", []) or []
    if not known_devices:
        return None

    # Compare device string
    if current_device not in known_devices:
        return DetectionResult(
            detected=True,
            anomaly_type=SecurityEventType.UNKNOWN_DEVICE.value,
            severity=EventSeverity.MEDIUM.value,
            reason="Request originated from an unrecognized device User-Agent.",
            evidence={
                "current_device": current_device,
                "known_devices": known_devices[:10],
                "baseline_status": status,
            },
        )
    return None


def rule_unknown_ip(
    current_ip: str,
    profile: Optional[Any],
) -> Optional[DetectionResult]:
    """Rule 7: Detects requests arriving from an unrecognized client IP address.

    Condition: current_ip NOT IN known_ips
    Severity: MEDIUM
    Note: IP change signal only; does not claim physical geographic verification.
    Safety: Suppressed during INSUFFICIENT_DATA.
    """
    if not profile or not current_ip:
        return None

    status = getattr(profile, "baseline_status", BaselineStatus.INSUFFICIENT_DATA)
    if status == BaselineStatus.INSUFFICIENT_DATA:
        return None

    known_ips = getattr(profile, "known_ips", []) or []
    if not known_ips:
        return None

    if current_ip not in known_ips:
        return DetectionResult(
            detected=True,
            anomaly_type=SecurityEventType.LOCATION_ANOMALY.value,
            severity=EventSeverity.MEDIUM.value,
            reason="Request originated from an unrecognized client IP address.",
            evidence={
                "current_ip": current_ip,
                "known_ips": known_ips[:10],
                "baseline_status": status,
            },
        )
    return None


def rule_sensitive_endpoint_misuse(
    status_code: int,
    is_sensitive: bool,
    user_role: Optional[str],
    endpoint: str,
) -> Optional[DetectionResult]:
    """Rule 8: Detects attempts by unauthorized users to access sensitive or administrative endpoints.

    Condition: status_code == 403 or (user_role == USER and endpoint is sensitive/admin)
    Severity: HIGH
    Note: Strong deterministic security signal; applies even with INSUFFICIENT_DATA.
    """
    is_admin_endpoint = endpoint.startswith("/api/admin") or endpoint in ("/api/users", "/api/security/events")
    is_privilege_violation = (status_code == 403) and (is_sensitive or is_admin_endpoint)

    if is_privilege_violation:
        return DetectionResult(
            detected=True,
            anomaly_type=SecurityEventType.PRIVILEGE_MISUSE.value,
            severity=EventSeverity.HIGH.value,
            reason="Unauthorized attempt to access privileged sensitive endpoint.",
            evidence={
                "user_role": user_role or "ANONYMOUS",
                "endpoint": endpoint,
                "status_code": status_code,
                "is_sensitive": is_sensitive,
            },
        )
    return None


def rule_unusual_time(
    current_hour: int,
    profile: Optional[Any],
) -> Optional[DetectionResult]:
    """Rule 9: Detects requests made outside the user's established historical usage hours.

    Condition: current_hour NOT IN normal_hours
    Severity: LOW
    Safety: STRICTLY only applied when baseline_status == ESTABLISHED.
    """
    if not profile:
        return None

    status = getattr(profile, "baseline_status", BaselineStatus.INSUFFICIENT_DATA)
    if status != BaselineStatus.ESTABLISHED:
        return None

    normal_hours = getattr(profile, "normal_hours", []) or []
    if not normal_hours:
        return None

    if current_hour not in normal_hours:
        return DetectionResult(
            detected=True,
            anomaly_type=SecurityEventType.UNUSUAL_TIME.value,
            severity=EventSeverity.LOW.value,
            reason="API accessed outside user's established normal operational hours.",
            evidence={
                "current_hour": current_hour,
                "normal_hours": normal_hours,
                "baseline_status": BaselineStatus.ESTABLISHED,
            },
        )
    return None
