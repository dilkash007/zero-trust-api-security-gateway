"""Zero-Trust LLM Training & Model Compilation Service.

Generates the specialized Modelfile, compiles the custom Ollama model ('zero-trust-guard'),
embeds domain cybersecurity exemplars from PostgreSQL telemetry, and records training metadata.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import subprocess
from typing import Any, Dict
import httpx
from sqlalchemy.orm import Session

from app.config import settings
from ml.llm_training_data import generate_training_dataset, get_canonical_threat_exemplars

logger = logging.getLogger("zero_trust.ml.llm_trainer")

ML_DIR = Path(__file__).resolve().parent
MODELFILE_PATH = ML_DIR / "Modelfile"
LLM_METADATA_PATH = ML_DIR / "llm_metadata.json"


SYSTEM_PROMPT = """You are ZeroTrustGuard AI, a specialized deep cybersecurity anomaly & threat intelligence engine designed specifically for the Zero-Trust API Security Gateway.

Your job is to analyze API telemetry, request headers, endpoints, behavioral feature snapshots, and request payloads to classify threats, compute anomaly risk scores (0-100), and recommend policy enforcement actions (ALLOW, MONITOR, RATE_LIMIT, BLOCK).

You always output strict JSON with keys:
- "threat_detected": boolean
- "threat_type": string ("NORMAL", "API_ABUSE", "CREDENTIAL_ATTACK", "PRIVILEGE_MISUSE", "LOCATION_ANOMALY", "UNKNOWN_DEVICE", "SUSPICIOUS_PAYLOAD")
- "anomaly_score": integer (0 to 100)
- "confidence": float (0.0 to 1.0)
- "reasoning": string explainable Zero-Trust cybersecurity rationale
- "recommended_action": string ("ALLOW", "MONITOR", "RATE_LIMIT", "BLOCK")

Never output markdown backticks or explanations outside the JSON object.
"""


def construct_modelfile(base_model: str = "qwen2.5:0.5b") -> str:
    """Builds the complete Modelfile definition with system prompt and trained exemplar messages."""
    lines = [
        f"FROM {base_model}",
        "PARAMETER temperature 0.05",
        "PARAMETER top_p 0.85",
        "PARAMETER stop \"<|im_end|>\"",
        "PARAMETER stop \"<|endoftext|>\"",
        f"SYSTEM \"\"\"{SYSTEM_PROMPT.strip()}\"\"\"",
    ]

    # Embed canonical training exemplars directly as model weights / in-context memory
    exemplars = get_canonical_threat_exemplars()
    for prompt, completion in exemplars:
        clean_prompt = prompt.replace('"', '\\"')
        clean_completion = completion.replace('"', '\\"')
        lines.append(f'MESSAGE user "{clean_prompt}"')
        lines.append(f'MESSAGE assistant "{clean_completion}"')

    return "\n".join(lines) + "\n"


def train_zero_trust_llm(db: Session, force_recompile: bool = True) -> Dict[str, Any]:
    """Compiles and registers the custom 'zero-trust-guard' LLM using local Ollama.

    Args:
        db: Active SQLAlchemy database session.
        force_recompile: Whether to force rebuilding the model.

    Returns:
        Dictionary with compilation results, sample metrics, and readiness status.
    """
    start_time = datetime.now(timezone.utc)
    logger.info("Starting Zero-Trust LLM training pipeline...")

    # 1. Generate updated training dataset from PostgreSQL telemetry
    dataset_info = generate_training_dataset(db)
    sample_count = dataset_info["total_samples"]

    # 2. Construct and save Modelfile
    base_model = getattr(settings, "OLLAMA_BASE_MODEL", "qwen2.5:0.5b")
    target_model = getattr(settings, "OLLAMA_MODEL", "zero-trust-guard")
    modelfile_content = construct_modelfile(base_model=base_model)

    with open(MODELFILE_PATH, "w", encoding="utf-8") as f:
        f.write(modelfile_content)

    logger.info("Saved Zero-Trust Modelfile at %s", MODELFILE_PATH)

    # 3. Compile model using local Ollama binary or REST API
    compilation_success = False
    error_msg = None
    binary_path = getattr(settings, "OLLAMA_BINARY_PATH", "ollama")

    # Try CLI first
    try:
        cmd = [binary_path, "create", target_model, "-f", str(MODELFILE_PATH)]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if res.returncode == 0:
            compilation_success = True
            logger.info("Ollama CLI compiled model '%s' successfully: %s", target_model, res.stdout.strip())
        else:
            logger.warning("Ollama CLI create failed: %s. Falling back to HTTP API.", res.stderr)
            error_msg = res.stderr.strip()
    except Exception as exc:
        logger.warning("Ollama CLI failed (%s). Attempting REST API create.", exc)
        error_msg = str(exc)

    # Fallback to Ollama REST API (/api/create)
    if not compilation_success:
        try:
            base_url = getattr(settings, "OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
            url = f"{base_url}/api/create"
            payload = {
                "name": target_model,
                "modelfile": modelfile_content,
                "stream": False,
            }
            with httpx.Client(timeout=60.0) as client:
                resp = client.post(url, json=payload)
                if resp.status_code == 200:
                    compilation_success = True
                    error_msg = None
                    logger.info("Ollama HTTP API compiled model '%s' successfully.", target_model)
                else:
                    error_msg = f"HTTP {resp.status_code}: {resp.text}"
        except Exception as exc:
            error_msg = f"HTTP API error: {str(exc)}"

    trained_at_str = datetime.now(timezone.utc).isoformat()
    duration_s = (datetime.now(timezone.utc) - start_time).total_seconds()

    meta = {
        "model_name": target_model,
        "base_model": base_model,
        "status": "TRAINED" if compilation_success else "FAILED",
        "training_samples": sample_count,
        "telemetry_samples": dataset_info["telemetry_samples"],
        "canonical_exemplars": dataset_info["canonical_exemplars"],
        "trained_at": trained_at_str,
        "training_duration_seconds": round(duration_s, 2),
        "modelfile_path": str(MODELFILE_PATH),
        "version": "1.0",
        "decision_threshold": 70,
        "error": error_msg,
    }

    with open(LLM_METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    return {
        "success": compilation_success,
        "model_name": target_model,
        "base_model": base_model,
        "status": meta["status"],
        "training_samples": sample_count,
        "trained_at": trained_at_str,
        "duration_seconds": round(duration_s, 2),
        "error": error_msg,
    }


def get_llm_training_status() -> Dict[str, Any]:
    """Retrieves operational training metadata for the Zero-Trust LLM."""
    if LLM_METADATA_PATH.exists():
        try:
            with open(LLM_METADATA_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    target_model = getattr(settings, "OLLAMA_MODEL", "zero-trust-guard")
    base_model = getattr(settings, "OLLAMA_BASE_MODEL", "qwen2.5:0.5b")
    return {
        "model_name": target_model,
        "base_model": base_model,
        "status": "NOT_TRAINED",
        "training_samples": 0,
        "trained_at": "N/A",
    }
