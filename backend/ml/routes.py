"""API endpoints for Machine Learning Anomaly Detection (Step 8)."""

from typing import Any, Dict
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.behavior.features import extract_feature_snapshot
from app.database.connection import get_db
from app.database.models import ApiRequestLog, BehaviorProfile
from app.gateway.dependencies import require_admin_only, require_user_or_admin
from app.gateway.request_context import RequestContext
from ml.predictor import get_ml_status, predict_anomaly
from ml.trainer import train_model

ml_router = APIRouter(prefix="/api/ml", tags=["Machine Learning Anomaly Detection (Step 8)"])


@ml_router.post(
    "/train",
    status_code=status.HTTP_200_OK,
    summary="Train or retrain Isolation Forest behavioral anomaly model (ADMIN only)",
)
def train_ml_model(
    context: RequestContext = Depends(require_admin_only),
    db: Session = Depends(get_db),
):
    """Triggers model training using real PostgreSQL request telemetry."""
    result = train_model(db)
    return {
        "success": result.get("status") in ("trained", "learning"),
        "data": result,
    }


@ml_router.get(
    "/status",
    status_code=status.HTTP_200_OK,
    summary="Retrieve current ML model status, metadata, and hyperparameters (ADMIN only)",
)
def get_model_status(
    context: RequestContext = Depends(require_admin_only),
):
    """Returns the operational readiness, sample count, and metadata of the ML engine."""
    status_data = get_ml_status()
    return {
        "success": True,
        "data": status_data,
    }


@ml_router.get(
    "/me",
    status_code=status.HTTP_200_OK,
    summary="Retrieve current authenticated user's behavioral ML evaluation",
)
def get_my_ml_evaluation(
    context: RequestContext = Depends(require_user_or_admin),
    db: Session = Depends(get_db),
):
    """Returns the Isolation Forest anomaly evaluation for the caller's current behavior."""
    # Query user's recent request logs (most recent 50 logs)
    logs = (
        db.query(ApiRequestLog)
        .filter(ApiRequestLog.user_id == context.user_id)
        .order_by(ApiRequestLog.id.desc())
        .limit(50)
        .all()
    )

    profile = (
        db.query(BehaviorProfile)
        .filter(BehaviorProfile.user_id == context.user_id)
        .first()
    )
    known_devices = profile.known_devices if profile and profile.known_devices else None
    known_ips = profile.known_ips if profile and profile.known_ips else None

    # Compute behavioral feature vector
    feat_snapshot = extract_feature_snapshot(logs, known_devices, known_ips)

    # Evaluate ML prediction
    prediction = predict_anomaly(feat_snapshot)

    return {
        "success": True,
        "data": {
            "available": prediction.get("available", False),
            "is_anomaly": prediction.get("is_anomaly", False),
            "anomaly_score": prediction.get("anomaly_score", 0),
            "raw_score": prediction.get("raw_score", 0.0),
            "model": prediction.get("model", "IsolationForest"),
            "threshold": 70,
        },
    }


# ===========================================================================
# Zero-Trust LLM Anomaly & Threat Intelligence Endpoints
# ===========================================================================

@ml_router.post(
    "/llm/train",
    status_code=status.HTTP_200_OK,
    summary="Train/compile the custom Zero-Trust LLM ('zero-trust-guard') via Ollama (ADMIN only)",
)
def train_llm_model(
    context: RequestContext = Depends(require_admin_only),
    db: Session = Depends(get_db),
):
    """Compiles and registers 'zero-trust-guard' LLM using real PostgreSQL request telemetry."""
    from ml.llm_trainer import train_zero_trust_llm

    result = train_zero_trust_llm(db)
    return {
        "success": result.get("success", False),
        "data": result,
    }


@ml_router.get(
    "/llm/status",
    status_code=status.HTTP_200_OK,
    summary="Retrieve current Zero-Trust LLM model training and operational status (ADMIN only)",
)
def get_llm_status(
    context: RequestContext = Depends(require_admin_only),
):
    """Returns training metadata and status for the Zero-Trust LLM."""
    from ml.llm_trainer import get_llm_training_status

    status_data = get_llm_training_status()
    return {
        "success": True,
        "data": status_data,
    }


@ml_router.post(
    "/llm/evaluate",
    status_code=status.HTTP_200_OK,
    summary="Evaluate an arbitrary API telemetry request or payload against the Zero-Trust LLM",
)
def evaluate_request_llm(
    payload: Dict[str, Any],
    context: RequestContext = Depends(require_user_or_admin),
):
    """Performs real-time LLM threat evaluation on request attributes and payload."""
    from ml.llm_detector import predict_threat_with_llm

    prediction = predict_threat_with_llm(
        request_context=payload,
        features=payload.get("features"),
        payload_sample=str(payload.get("payload_sample", "")),
    )
    return {
        "success": True,
        "data": prediction,
    }

