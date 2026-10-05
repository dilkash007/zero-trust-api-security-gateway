"""ML inference service for real-time behavioral anomaly prediction (Step 8).

Loads the trained Isolation Forest model, performs feature scaling,
computes normalized 0-100 anomaly scores, and caches model state in memory.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import joblib
import numpy as np

from ml.features import FEATURE_NAMES, extract_feature_vector

logger = logging.getLogger("zero_trust.ml")

ML_DIR = Path(__file__).resolve().parent
MODEL_PATH = ML_DIR / "model.pkl"
SCALER_PATH = ML_DIR / "preprocessing.pkl"
METADATA_PATH = ML_DIR / "metadata.json"

ML_ANOMALY_THRESHOLD = 70  # Centralized decision threshold

# In-memory singleton cache
_model: Optional[Any] = None
_scaler: Optional[Any] = None
_metadata: Optional[Dict[str, Any]] = None
_is_loaded: bool = False


def load_model(force_reload: bool = False) -> Tuple[Optional[Any], Optional[Any], Optional[Dict[str, Any]]]:
    """Loads trained model, scaler, and metadata into memory with graceful failure safety."""
    global _model, _scaler, _metadata, _is_loaded

    if _is_loaded and not force_reload:
        return _model, _scaler, _metadata

    _model = None
    _scaler = None
    _metadata = None
    _is_loaded = True

    try:
        if MODEL_PATH.exists() and SCALER_PATH.exists():
            _model = joblib.load(MODEL_PATH)
            _scaler = joblib.load(SCALER_PATH)

            if METADATA_PATH.exists():
                with open(METADATA_PATH, "r", encoding="utf-8") as f:
                    _metadata = json.load(f)
            else:
                _metadata = {
                    "model_type": "IsolationForest",
                    "status": "READY",
                    "version": "1.0",
                    "features": FEATURE_NAMES,
                }
            logger.info("ML Isolation Forest model and scaler loaded successfully into memory.")
        else:
            logger.info("ML model not trained yet. Operating in rule-only fallback mode.")
    except Exception as e:
        logger.warning("Failed to load ML model from disk: %s. Operating in safe fallback mode.", e)
        _model = None
        _scaler = None
        _metadata = None

    return _model, _scaler, _metadata


def reload_model() -> Tuple[Optional[Any], Optional[Any], Optional[Dict[str, Any]]]:
    """Forces reloading model artifacts from disk into the in-memory cache."""
    return load_model(force_reload=True)


def get_model() -> Optional[Any]:
    """Returns the currently active in-memory IsolationForest model or None."""
    model, _, _ = load_model()
    return model


def get_ml_status() -> Dict[str, Any]:
    """Returns the operational status and metadata of the ML subsystem."""
    model, _, metadata = load_model()

    if model is not None and metadata is not None:
        return {
            "available": True,
            "status": metadata.get("status", "READY"),
            "model_type": metadata.get("model_type", "IsolationForest"),
            "training_samples": metadata.get("training_samples", 0),
            "trained_at": metadata.get("trained_at", "N/A"),
            "feature_count": len(metadata.get("features", FEATURE_NAMES)),
            "features": metadata.get("features", FEATURE_NAMES),
            "threshold": ML_ANOMALY_THRESHOLD,
        }

    # Check if metadata exists even if model is learning
    if METADATA_PATH.exists():
        try:
            with open(METADATA_PATH, "r", encoding="utf-8") as f:
                meta = json.load(f)
                return {
                    "available": False,
                    "status": meta.get("status", "NOT_TRAINED"),
                    "model_type": "IsolationForest",
                    "training_samples": meta.get("training_samples", 0),
                    "required_samples": meta.get("required_samples", 50),
                    "threshold": ML_ANOMALY_THRESHOLD,
                }
        except Exception:
            pass

    return {
        "available": False,
        "status": "NOT_TRAINED",
        "model_type": "IsolationForest",
        "training_samples": 0,
        "threshold": ML_ANOMALY_THRESHOLD,
    }


def predict_anomaly(features: Any) -> Dict[str, Any]:
    """Evaluates an observation against the trained Isolation Forest model.

    Args:
        features: Either a feature dict, 1D/2D NumPy array, or list of values.

    Returns:
        Dictionary containing:
          - available: bool
          - is_anomaly: bool
          - anomaly_score: int (0 to 100)
          - raw_score: float
          - model: str
    """
    model, scaler, _ = load_model()

    if model is None or scaler is None:
        return {
            "available": False,
            "is_anomaly": False,
            "anomaly_score": 0,
            "raw_score": 0.0,
            "model": "IsolationForest",
            "reason": "ML model not trained",
        }

    try:
        # Convert input to 2D numpy array (1, 10)
        if isinstance(features, dict):
            X = extract_feature_vector(features).reshape(1, -1)
        elif isinstance(features, (list, tuple)):
            X = np.array(features, dtype=np.float64).reshape(1, -1)
        elif isinstance(features, np.ndarray):
            X = features.reshape(1, -1) if features.ndim == 1 else features
        else:
            return {
                "available": False,
                "is_anomaly": False,
                "anomaly_score": 0,
                "raw_score": 0.0,
                "model": "IsolationForest",
                "reason": "Invalid feature format",
            }

        # Apply standardized preprocessing pipeline
        X_scaled = scaler.transform(X)

        # Raw decision function: higher is normal inlier, negative is anomalous outlier
        raw_score = float(model.decision_function(X_scaled)[0])

        # Calibrated deterministic normalization:
        # raw +0.25 -> ~20 (normal)
        # raw  0.00 -> ~50 (baseline edge)
        # raw -0.17 -> ~70 (decision threshold)
        # raw -0.35 -> ~92 (strong anomaly)
        calibrated_score = 50.0 - (raw_score * 120.0)
        anomaly_score = int(round(max(0.0, min(100.0, calibrated_score))))

        is_anomaly = anomaly_score >= ML_ANOMALY_THRESHOLD

        return {
            "available": True,
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "raw_score": round(raw_score, 4),
            "model": "IsolationForest",
        }
    except Exception as e:
        logger.error("ML prediction error: %s. Safe fallback applied.", e)
        return {
            "available": False,
            "is_anomaly": False,
            "anomaly_score": 0,
            "raw_score": 0.0,
            "model": "IsolationForest",
            "reason": f"Prediction error: {str(e)}",
        }
