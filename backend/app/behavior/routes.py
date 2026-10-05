"""Behavioral baseline and feature snapshot API routes."""

from typing import Any, Dict
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.behavior.baseline import (
    fetch_historical_logs,
    rebuild_all_baselines,
    update_user_baseline,
)
from app.behavior.features import extract_feature_snapshot
from app.database.connection import get_db
from app.database.models import BehaviorProfile, User
from app.gateway.dependencies import require_admin_only, require_user_or_admin
from app.gateway.request_context import RequestContext

behavior_router = APIRouter(prefix="/api/behavior", tags=["Behavior Baselines & Feature Engine"])


def _format_profile(profile: BehaviorProfile, username: str = None) -> Dict[str, Any]:
    """Serializes BehaviorProfile entity into safe API response format."""
    devices_count = (
        len(profile.known_devices)
        if isinstance(profile.known_devices, list)
        else (profile.known_devices or 0)
    )
    ips_count = (
        len(profile.known_ips)
        if isinstance(profile.known_ips, list)
        else (profile.known_ips or 0)
    )

    return {
        "user_id": profile.user_id,
        "username": username or (profile.user.email if profile.user else f"User #{profile.user_id}"),
        "avg_requests_per_minute": profile.avg_requests_per_minute,
        "avg_unique_endpoints": profile.avg_unique_endpoints,
        "avg_failed_requests": profile.avg_failed_requests,
        "avg_sensitive_access": profile.avg_sensitive_access,
        "normal_hours": profile.normal_hours or [],
        "known_devices": devices_count,
        "known_ips": ips_count,
        "avg_response_time": profile.avg_response_time,
        "avg_request_size": profile.avg_request_size,
        "avg_response_size": profile.avg_response_size,
        "sample_count": profile.sample_count,
        "baseline_status": profile.baseline_status,
        "updated_at": profile.updated_at.isoformat() if profile.updated_at else None,
    }


@behavior_router.get(
    "/profiles",
    status_code=status.HTTP_200_OK,
    summary="Retrieve all user behavioral baseline profiles (ADMIN only)",
)
def get_all_behavior_profiles(
    context: RequestContext = Depends(require_admin_only),
    db: Session = Depends(get_db),
):
    """Returns baseline behavior profiles for all identities."""
    profiles = db.query(BehaviorProfile).all()

    # If no profiles have been computed yet, automatically initialize them
    if not profiles:
        rebuild_all_baselines(db)
        profiles = db.query(BehaviorProfile).all()

    data = [_format_profile(p) for p in profiles]
    return {
        "success": True,
        "data": data,
    }


@behavior_router.get(
    "/me",
    status_code=status.HTTP_200_OK,
    summary="Retrieve the authenticated user's own behavior profile",
)
def get_my_behavior_profile(
    context: RequestContext = Depends(require_user_or_admin),
    db: Session = Depends(get_db),
):
    """Returns the calling user's individual behavior baseline profile."""
    profile = (
        db.query(BehaviorProfile).filter(BehaviorProfile.user_id == context.user_id).first()
    )

    if profile is None:
        profile = update_user_baseline(context.user_id, db)

    return {
        "success": True,
        "data": _format_profile(profile, username=context.username),
    }


@behavior_router.get(
    "/features",
    status_code=status.HTTP_200_OK,
    summary="Extract latest behavioral feature snapshot for the authenticated user",
)
def get_feature_snapshot(
    context: RequestContext = Depends(require_user_or_admin),
    db: Session = Depends(get_db),
):
    """Calculates a live feature snapshot from the user's historical request logs."""
    logs = fetch_historical_logs(context.user_id, db)

    # Retrieve existing known devices & IPs for delta detection
    profile = (
        db.query(BehaviorProfile).filter(BehaviorProfile.user_id == context.user_id).first()
    )
    known_devices = profile.known_devices if profile else []
    known_ips = profile.known_ips if profile else []

    snapshot = extract_feature_snapshot(
        logs=logs,
        known_devices=known_devices,
        known_ips=known_ips,
    )

    return {
        "success": True,
        "data": snapshot,
    }


@behavior_router.post(
    "/rebuild",
    status_code=status.HTTP_200_OK,
    summary="Rebuild behavior baselines for all users from historical telemetry (ADMIN only)",
)
def rebuild_baselines(
    context: RequestContext = Depends(require_admin_only),
    db: Session = Depends(get_db),
):
    """Recalculates behavioral baselines for all users across historical request logs."""
    updated_count = rebuild_all_baselines(db)
    return {
        "success": True,
        "message": "Behavior baselines rebuilt",
        "profiles_updated": updated_count,
    }
