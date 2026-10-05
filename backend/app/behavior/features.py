"""Feature extraction engine calculating behavioral telemetry from historical API request logs."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from app.database.models import ApiRequestLog


def calculate_requests_per_minute(logs: List[ApiRequestLog]) -> float:
    """Calculates average requests per minute across the log sample."""
    if not logs:
        return 0.0
    if len(logs) == 1:
        return 1.0

    sorted_logs = sorted(logs, key=lambda l: l.timestamp)
    duration_seconds = (sorted_logs[-1].timestamp - sorted_logs[0].timestamp).total_seconds()
    duration_minutes = duration_seconds / 60.0

    # If all requests were made within the same minute, normalize to duration of 1 minute
    effective_minutes = max(duration_minutes, 1.0)
    return round(len(logs) / effective_minutes, 2)


def calculate_unique_endpoints(logs: List[ApiRequestLog]) -> int:
    """Returns the count of distinct endpoint paths accessed."""
    return len({l.endpoint for l in logs if l.endpoint})


def calculate_failed_requests(logs: List[ApiRequestLog]) -> int:
    """Counts requests resulting in client or server errors (HTTP status >= 400)."""
    return sum(1 for l in logs if l.status_code >= 400)


def calculate_sensitive_access(logs: List[ApiRequestLog]) -> int:
    """Counts accesses to sensitive endpoints."""
    return sum(1 for l in logs if l.is_sensitive)


def calculate_unique_devices(logs: List[ApiRequestLog]) -> int:
    """Returns count of distinct User-Agent device identifiers."""
    return len({l.user_agent for l in logs if l.user_agent})


def calculate_unique_locations(logs: List[ApiRequestLog]) -> int:
    """Returns count of distinct client IP addresses."""
    return len({l.client_ip for l in logs if l.client_ip})


def check_device_change(logs: List[ApiRequestLog], known_devices: Optional[List[str]] = None) -> bool:
    """Detects if the most recent request used a device different from earlier requests."""
    if not logs:
        return False

    sorted_logs = sorted(logs, key=lambda l: l.timestamp)
    latest_device = sorted_logs[-1].user_agent

    # If historical known devices are provided, check if the latest device is novel
    if known_devices and len(known_devices) > 0:
        return latest_device not in known_devices

    # Otherwise compare against the immediately preceding request
    if len(sorted_logs) >= 2:
        return sorted_logs[-1].user_agent != sorted_logs[-2].user_agent

    return False


def check_location_change(logs: List[ApiRequestLog], known_ips: Optional[List[str]] = None) -> bool:
    """Detects if the most recent request came from a different IP location."""
    if not logs:
        return False

    sorted_logs = sorted(logs, key=lambda l: l.timestamp)
    latest_ip = sorted_logs[-1].client_ip

    if known_ips and len(known_ips) > 0:
        return latest_ip not in known_ips

    if len(sorted_logs) >= 2:
        return sorted_logs[-1].client_ip != sorted_logs[-2].client_ip

    return False


def calculate_average_response_time(logs: List[ApiRequestLog]) -> float:
    """Calculates mean response time in milliseconds."""
    if not logs:
        return 0.0
    return round(sum(l.response_time_ms for l in logs) / len(logs), 2)


def calculate_average_request_size(logs: List[ApiRequestLog]) -> float:
    """Calculates mean request payload size in bytes."""
    if not logs:
        return 0.0
    return round(sum(l.request_size or 0 for l in logs) / len(logs), 2)


def calculate_average_response_size(logs: List[ApiRequestLog]) -> float:
    """Calculates mean response payload size in bytes."""
    if not logs:
        return 0.0
    return round(sum(l.response_size or 0 for l in logs) / len(logs), 2)


def calculate_normal_hours(logs: List[ApiRequestLog]) -> List[int]:
    """Identifies the list of hours (0-23 UTC) where the user has active traffic."""
    if not logs:
        return []
    return sorted(list({l.timestamp.hour for l in logs}))


def extract_feature_snapshot(
    logs: List[ApiRequestLog],
    known_devices: Optional[List[str]] = None,
    known_ips: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Computes a live behavioral feature snapshot from real request telemetry."""
    current_utc_hour = datetime.now(timezone.utc).hour

    return {
        "requests_per_minute": calculate_requests_per_minute(logs),
        "unique_endpoints": calculate_unique_endpoints(logs),
        "failed_requests": calculate_failed_requests(logs),
        "sensitive_endpoint_access": calculate_sensitive_access(logs),
        "unique_devices": calculate_unique_devices(logs),
        "unique_ips": calculate_unique_locations(logs),
        "device_change": check_device_change(logs, known_devices),
        "location_change": check_location_change(logs, known_ips),
        "average_response_time": calculate_average_response_time(logs),
        "average_request_size": calculate_average_request_size(logs),
        "average_response_size": calculate_average_response_size(logs),
        "current_hour": current_utc_hour,
    }
