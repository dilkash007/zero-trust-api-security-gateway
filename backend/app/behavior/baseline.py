"""Baseline computation service updating user behavioral profiles from historical request logs."""

from datetime import datetime, timedelta, timezone
import logging
from typing import List, Optional
from sqlalchemy.orm import Session

from app.behavior.features import (
    calculate_average_request_size,
    calculate_average_response_size,
    calculate_average_response_time,
    calculate_failed_requests,
    calculate_normal_hours,
    calculate_requests_per_minute,
    calculate_sensitive_access,
    calculate_unique_endpoints,
)
from app.database.models import (
    ApiRequestLog,
    BaselineStatus,
    BehaviorProfile,
    User,
)

logger = logging.getLogger("zero_trust.behavior")


def determine_baseline_status(sample_count: int) -> str:
    """Determines baseline maturity status based on historical sample count.

    - 0–9 requests: INSUFFICIENT_DATA
    - 10–49 requests: LEARNING
    - 50+ requests: ESTABLISHED
    """
    if sample_count >= 50:
        return BaselineStatus.ESTABLISHED.value
    if sample_count >= 10:
        return BaselineStatus.LEARNING.value
    return BaselineStatus.INSUFFICIENT_DATA.value


def fetch_historical_logs(user_id: int, db: Session, days: int = 7) -> List[ApiRequestLog]:
    """Retrieves user request logs from a rolling window (defaults to last 7 days).

    Falls back to all available historical records if within the initial 7 days of activity.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    logs = (
        db.query(ApiRequestLog)
        .filter(ApiRequestLog.user_id == user_id, ApiRequestLog.timestamp >= cutoff)
        .order_by(ApiRequestLog.timestamp.asc())
        .all()
    )

    if not logs:
        # Fall back to all available logs for this user
        logs = (
            db.query(ApiRequestLog)
            .filter(ApiRequestLog.user_id == user_id)
            .order_by(ApiRequestLog.timestamp.asc())
            .all()
        )

    return logs


def update_user_baseline(user_id: int, db: Session) -> BehaviorProfile:
    """Computes features from historical logs and creates/updates the user's BehaviorProfile."""
    logs = fetch_historical_logs(user_id, db)
    sample_count = len(logs)
    status_label = determine_baseline_status(sample_count)
    now = datetime.now(timezone.utc)

    avg_rpm = calculate_requests_per_minute(logs)
    avg_endpoints = float(calculate_unique_endpoints(logs))
    avg_failed = float(calculate_failed_requests(logs))
    avg_sensitive = float(calculate_sensitive_access(logs))
    normal_hours = calculate_normal_hours(logs)
    known_devices = sorted(list({l.user_agent for l in logs if l.user_agent}))
    known_ips = sorted(list({l.client_ip for l in logs if l.client_ip}))
    avg_rt = calculate_average_response_time(logs)
    avg_req_size = calculate_average_request_size(logs)
    avg_resp_size = calculate_average_response_size(logs)

    # Check for existing profile
    profile = db.query(BehaviorProfile).filter(BehaviorProfile.user_id == user_id).first()

    if profile is None:
        profile = BehaviorProfile(
            user_id=user_id,
            avg_requests_per_minute=avg_rpm,
            avg_unique_endpoints=avg_endpoints,
            avg_failed_requests=avg_failed,
            avg_sensitive_access=avg_sensitive,
            normal_hours=normal_hours,
            known_devices=known_devices,
            known_ips=known_ips,
            avg_response_time=avg_rt,
            avg_request_size=avg_req_size,
            avg_response_size=avg_resp_size,
            sample_count=sample_count,
            baseline_status=status_label,
            updated_at=now,
        )
        db.add(profile)
    else:
        profile.avg_requests_per_minute = avg_rpm
        profile.avg_unique_endpoints = avg_endpoints
        profile.avg_failed_requests = avg_failed
        profile.avg_sensitive_access = avg_sensitive
        profile.normal_hours = normal_hours
        profile.known_devices = known_devices
        profile.known_ips = known_ips
        profile.avg_response_time = avg_rt
        profile.avg_request_size = avg_req_size
        profile.avg_response_size = avg_resp_size
        profile.sample_count = sample_count
        profile.baseline_status = status_label
        profile.updated_at = now

    db.commit()
    db.refresh(profile)

    logger.info(
        "Updated behavior baseline for user id=%s: status=%s, samples=%s, avg_rpm=%s",
        user_id,
        status_label,
        sample_count,
        avg_rpm,
    )
    return profile


def rebuild_all_baselines(db: Session) -> int:
    """Iterates through all registered users and recalculates their behavioral baselines."""
    users = db.query(User).all()
    count = 0
    for u in users:
        update_user_baseline(u.id, db)
        count += 1
    return count
