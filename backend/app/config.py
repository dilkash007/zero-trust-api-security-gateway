import json
from pathlib import Path
from typing import List, Optional, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Base directory pointing to backend folder
BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Central configuration management loaded via Pydantic Settings."""

    APP_NAME: str = "Zero-Trust API Security Engine"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # ---------------------------------------------------------------------------
    # Database
    # ---------------------------------------------------------------------------
    DATABASE_URL: str

    # ---------------------------------------------------------------------------
    # Redis (optional — graceful fallback to in-memory when not set)
    # ---------------------------------------------------------------------------
    REDIS_URL: Optional[str] = None

    # ---------------------------------------------------------------------------
    # CORS
    # ---------------------------------------------------------------------------
    CORS_ORIGINS: Union[List[str], str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ]

    # ---------------------------------------------------------------------------
    # Security & JWT
    # ---------------------------------------------------------------------------
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ---------------------------------------------------------------------------
    # Rate Limiting (production defaults — override via environment)
    # ---------------------------------------------------------------------------
    # Global sliding-window per IP
    RATE_LIMIT_REQUESTS: int = 100        # max requests
    RATE_LIMIT_WINDOW_SECONDS: int = 60   # per N seconds

    # Per-user authenticated window
    RATE_LIMIT_USER_REQUESTS: int = 200
    RATE_LIMIT_USER_WINDOW_SECONDS: int = 60

    # Burst protection: requests that arrive faster than this interval are flagged
    RATE_LIMIT_BURST_REQUESTS: int = 20
    RATE_LIMIT_BURST_WINDOW_SECONDS: int = 5

    # Auto-block duration after repeated rate-limit breaches
    RATE_LIMIT_BLOCK_DURATION_SECONDS: int = 3600  # 1 hour

    # ---------------------------------------------------------------------------
    # Policy Enforcement
    # ---------------------------------------------------------------------------
    # When True the gateway actively blocks BLOCK-policy requests (production)
    # When False the middleware records but does not block (shadow mode / test)
    POLICY_ENFORCEMENT_ACTIVE: bool = True

    # ---------------------------------------------------------------------------
    # Upstream Forwarding (future reverse-proxy mode)
    # ---------------------------------------------------------------------------
    UPSTREAM_BASE_URL: Optional[str] = None

    # ---------------------------------------------------------------------------
    # Local LLM / Ollama Threat Intelligence
    # ---------------------------------------------------------------------------
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "zero-trust-guard"
    OLLAMA_BASE_MODEL: str = "qwen2.5:0.5b"
    OLLAMA_BINARY_PATH: str = "/Users/brajeshkumarrai/Desktop/llm/bin/ollama"
    LLM_DETECTION_ENABLED: bool = True

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            clean_str = v.strip()
            if clean_str.startswith("[") and clean_str.endswith("]"):
                try:
                    parsed = json.loads(clean_str)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed]
                except Exception:
                    pass
            return [origin.strip() for origin in clean_str.split(",") if origin.strip()]
        return v

    model_config = SettingsConfigDict(
        env_file=(BASE_DIR / ".env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
