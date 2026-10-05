"""ML training service for behavioral anomaly detection (Step 8).

Extracts real historical request telemetry from PostgreSQL, constructs feature matrices,
evaluates sample sufficiency (>= 50), trains scikit-learn Isolation Forest, and persists artifacts.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sqlalchemy.orm import Session

from app.database.models import ApiRequestLog
from ml.features import FEATURE_NAMES, build_training_matrix_from_logs
from ml.predictor import MODEL_PATH, SCALER_PATH, METADATA_PATH, reload_model

logger = logging.getLogger("zero_trust.ml.trainer")

MIN_TRAINING_SAMPLES = 50


def train_model(db: Session, min_samples: int = MIN_TRAINING_SAMPLES) -> Dict[str, Any]:
    """Trains an Isolation Forest model using real PostgreSQL request telemetry.

    Args:
        db: Active SQLAlchemy database session.
        min_samples: Minimum required behavioral samples (default: 50).

    Returns:
        Training outcome dictionary.
    """
    logger.info("Initiating ML training from PostgreSQL telemetry...")

    try:
        # 1. Fetch real historical request logs (most recent 2,000 logs)
        logs = (
            db.query(ApiRequestLog)
            .order_by(ApiRequestLog.id.asc())
            .limit(2000)
            .all()
        )

        # 2. Build feature matrix using established behavioral feature windows
        X = build_training_matrix_from_logs(logs)
        sample_count = int(X.shape[0])

        logger.info("Extracted %d behavioral feature vectors from %d request logs.", sample_count, len(logs))

        # 3. Check sample sufficiency
        if sample_count < min_samples:
            meta = {
                "model_type": "IsolationForest",
                "version": "1.0",
                "status": "LEARNING",
                "training_samples": sample_count,
                "required_samples": min_samples,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            with open(METADATA_PATH, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)

            return {
                "status": "learning",
                "training_samples": sample_count,
                "required_samples": min_samples,
                "message": f"Insufficient behavioral data ({sample_count}/{min_samples}). Baseline still learning.",
            }

        # 4. Fit StandardScaler
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # 5. Fit Isolation Forest with deterministic hyperparameters
        model = IsolationForest(
            n_estimators=150,
            contamination="auto",
            random_state=42,
            n_jobs=1,
        )
        model.fit(X_scaled)

        # 6. Persist artifacts using joblib
        joblib.dump(scaler, SCALER_PATH)
        joblib.dump(model, MODEL_PATH)

        trained_at_str = datetime.now(timezone.utc).isoformat()
        metadata = {
            "model_type": "IsolationForest",
            "version": "1.0",
            "trained_at": trained_at_str,
            "training_samples": sample_count,
            "features": FEATURE_NAMES,
            "status": "READY",
            "hyperparameters": {
                "n_estimators": 150,
                "contamination": "auto",
                "random_state": 42,
            },
        }

        with open(METADATA_PATH, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        # 7. Refresh in-memory model cache
        reload_model()

        logger.info("Successfully trained Isolation Forest on %d real samples.", sample_count)

        return {
            "status": "trained",
            "model_type": "IsolationForest",
            "training_samples": sample_count,
            "features": len(FEATURE_NAMES),
            "trained_at": trained_at_str,
        }

    except Exception as e:
        logger.error("Failed to train ML model: %s", e, exc_info=True)
        return {
            "status": "error",
            "message": "Model training failed due to internal error.",
        }
