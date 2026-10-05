"""Behavioral feature extraction for Isolation Forest anomaly detection (Step 8).

Defines the exact, stable 10-feature vector order used across training and prediction.
Reuses existing Step 5 feature definitions to ensure consistency.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import numpy as np

# Canonical feature list in strict stable order
FEATURE_NAMES = [
    "requests_per_minute",
    "unique_endpoints",
    "failed_requests",
    "sensitive_endpoint_access",
    "device_change",
    "location_change",
    "current_hour",
    "request_size",
    "response_size",
    "session_age",
]


def extract_feature_vector(
    feature_dict: Dict[str, Any],
    session_age_minutes: float = 0.0,
) -> np.ndarray:
    """Converts a live or historical feature dictionary into a 1D NumPy float64 vector.

    Maintains identical ordering as FEATURE_NAMES.
    """
    rpm = float(feature_dict.get("requests_per_minute", 0.0) or 0.0)
    endpoints = float(feature_dict.get("unique_endpoints", 1) or 1.0)
    failed = float(feature_dict.get("failed_requests", 0) or 0.0)
    sensitive = float(feature_dict.get("sensitive_endpoint_access", 0) or 0.0)
    dev_change = 1.0 if bool(feature_dict.get("device_change", False)) else 0.0
    loc_change = 1.0 if bool(feature_dict.get("location_change", False)) else 0.0
    hour = float(feature_dict.get("current_hour", datetime.now(timezone.utc).hour) or 0.0)
    req_size = float(feature_dict.get("average_request_size", 0.0) or feature_dict.get("request_size", 0.0) or 0.0)
    resp_size = float(feature_dict.get("average_response_size", 0.0) or feature_dict.get("response_size", 0.0) or 0.0)
    session_age = float(feature_dict.get("session_age", session_age_minutes) or 0.0)

    values = [
        rpm,
        endpoints,
        failed,
        sensitive,
        dev_change,
        loc_change,
        hour,
        req_size,
        resp_size,
        session_age,
    ]
    return np.array(values, dtype=np.float64)


def build_training_matrix_from_logs(logs: List[Any]) -> np.ndarray:
    """Builds a 2D feature matrix (N, 10) from real historical PostgreSQL request logs.

    Groups logs chronologically by user and creates rolling behavioral snapshot windows
    reflecting real baseline operational distributions.
    """
    if not logs or len(logs) == 0:
        return np.empty((0, len(FEATURE_NAMES)), dtype=np.float64)

    # Sort all logs chronologically
    sorted_logs = sorted(logs, key=lambda l: l.timestamp or datetime.min)

    # Group logs by user_id
    user_logs: Dict[Optional[int], List[Any]] = {}
    for log in sorted_logs:
        uid = getattr(log, "user_id", None)
        user_logs.setdefault(uid, []).append(log)

    samples: List[np.ndarray] = []

    for uid, u_logs in user_logs.items():
        if len(u_logs) == 0:
            continue

        first_time = u_logs[0].timestamp or datetime.now(timezone.utc)
        known_devices = set()
        known_ips = set()

        # Generate a feature vector for rolling windows of real logs
        for idx in range(len(u_logs)):
            window = u_logs[max(0, idx - 15) : idx + 1]
            latest = window[-1]
            latest_time = latest.timestamp or datetime.now(timezone.utc)

            # Compute window metrics
            unique_endpoints = len({l.endpoint for l in window if l.endpoint})
            failed_count = sum(1 for l in window if (l.status_code or 200) >= 400)
            sensitive_count = sum(1 for l in window if getattr(l, "is_sensitive", False))

            # Requests per minute within window
            if len(window) > 1:
                duration_sec = max((window[-1].timestamp - window[0].timestamp).total_seconds(), 1.0)
                rpm = round(len(window) / (duration_sec / 60.0), 2)
            else:
                rpm = 1.0

            # Device and location changes
            dev_change = latest.user_agent not in known_devices if known_devices else False
            loc_change = latest.client_ip not in known_ips if known_ips else False

            if latest.user_agent:
                known_devices.add(latest.user_agent)
            if latest.client_ip:
                known_ips.add(latest.client_ip)

            session_age_min = max((latest_time - first_time).total_seconds() / 60.0, 0.0)

            feat_dict = {
                "requests_per_minute": rpm,
                "unique_endpoints": unique_endpoints,
                "failed_requests": failed_count,
                "sensitive_endpoint_access": sensitive_count,
                "device_change": dev_change,
                "location_change": loc_change,
                "current_hour": latest_time.hour,
                "average_request_size": latest.request_size or 0,
                "average_response_size": latest.response_size or 0,
                "session_age": round(session_age_min, 2),
            }
            samples.append(extract_feature_vector(feat_dict))

    if not samples:
        return np.empty((0, len(FEATURE_NAMES)), dtype=np.float64)

    return np.array(samples, dtype=np.float64)
