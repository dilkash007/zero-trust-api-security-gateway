"""FastAPI endpoints for Zero-Trust Reverse Proxy & Target API Protection."""

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.auth.dependencies import get_current_user_optional
from app.database.models import User
from app.proxy.schemas import (
    CheckModelsRequest,
    CheckModelsResponse,
    ProxyDispatchRequest,
    ProxyTransactionResponse,
    TargetApiConfig,
    TargetPreset,
)
from app.proxy.service import (
    check_all_gemini_models,
    dispatch_proxy_request,
    get_current_config,
    get_presets,
    get_recent_transactions,
    update_current_config,
)

logger = logging.getLogger("zero_trust.proxy.routes")

proxy_router = APIRouter(prefix="/api/proxy", tags=["API Protector & Reverse Proxy"])


@proxy_router.get(
    "/config",
    response_model=Dict[str, Any],
    summary="Get current target API configuration and available presets",
)
def get_proxy_configuration():
    """Returns the current target API config (e.g., Gemini endpoint) along with popular presets."""
    cfg = get_current_config()
    presets = get_presets()
    return {
        "success": True,
        "config": {
            "name": cfg.name,
            "target_url": cfg.target_url,
            "has_api_key": bool(cfg.api_key),
            "auth_type": cfg.auth_type,
            "auth_header_name": cfg.auth_header_name,
            "auth_query_param": cfg.auth_query_param,
            "timeout_seconds": cfg.timeout_seconds,
            "enabled": cfg.enabled,
        },
        "presets": [p.model_dump() for p in presets],
    }


@proxy_router.post(
    "/config",
    response_model=Dict[str, Any],
    summary="Update target API configuration",
)
def update_proxy_configuration(config: TargetApiConfig):
    """Sets the active target API destination, credentials, and timeout."""
    updated = update_current_config(config)
    return {
        "success": True,
        "message": f"Target API updated to '{updated.name}' ({updated.target_url})",
        "config": {
            "name": updated.name,
            "target_url": updated.target_url,
            "has_api_key": bool(updated.api_key),
            "auth_type": updated.auth_type,
            "timeout_seconds": updated.timeout_seconds,
        },
    }


@proxy_router.get(
    "/presets",
    response_model=List[Dict[str, Any]],
    summary="List preconfigured target API templates",
)
def list_target_presets():
    """Returns preset configs for Google Gemini (Flash, Pro, 2.0) and generic REST targets."""
    return [p.model_dump() for p in get_presets()]


@proxy_router.post(
    "/models/check",
    response_model=CheckModelsResponse,
    summary="Validate API key across multiple Gemini models and measure real latency",
)
async def check_gemini_models_endpoint(req: CheckModelsRequest):
    """Checks user's API key against Gemini models (1.5 Flash, 1.5 Pro, 2.0 Flash) and returns live statuses."""
    if not req.api_key or len(req.api_key.strip()) < 10:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A valid Google Gemini API key is required to check models.",
        )
    return await check_all_gemini_models(api_key=req.api_key.strip(), models=req.models)



@proxy_router.post(
    "/dispatch",
    response_model=ProxyTransactionResponse,
    summary="Dispatch request through Zero-Trust shield with hop-by-hop telemetry",
)
async def dispatch_request_through_gateway(
    request: Request,
    dispatch_req: ProxyDispatchRequest,
    x_simulated_ip: Optional[str] = Header(None),
    x_forwarded_for: Optional[str] = Header(None),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """Dispatches a payload through the Zero-Trust inspection pipeline to the target API.
    Captures:
      1. Source (Origin IP, headers, device, location)
      2. Zero-Trust Shield (Rules, ML Anomaly, Ollama LLM, Risk, Policy ALLOW/BLOCK)
      3. Destination (Upstream status, latency, response from Gemini or target)
    """
    real_ip = x_simulated_ip or (x_forwarded_for.split(",")[0].strip() if x_forwarded_for else (request.client.host if request.client else "127.0.0.1"))
    user_agent = request.headers.get("user-agent", "Mozilla/5.0 ZeroTrustProxy")

    user_id = current_user.id if current_user else None
    username = (getattr(current_user, "email", None) or getattr(current_user, "name", None)) if current_user else None

    result = await dispatch_proxy_request(
        dispatch_req=dispatch_req,
        real_client_ip=real_ip,
        real_user_agent=user_agent,
        user_id=user_id,
        username=username,
    )
    return result


@proxy_router.get(
    "/history",
    response_model=List[ProxyTransactionResponse],
    summary="Get recent proxy transactions with hop-by-hop details",
)
def get_transaction_history(limit: int = 50):
    """Returns the latest hop-by-hop transactions for live display in the UI."""
    return get_recent_transactions(limit=limit)


@proxy_router.post(
    "/gemini",
    summary="Direct reverse proxy endpoint for Google Gemini API",
)
async def direct_gemini_proxy(
    request: Request,
    x_goog_api_key: Optional[str] = Header(None),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """Transparent reverse-proxy endpoint for Gemini API.
    External applications or scripts can send Gemini generateContent requests here directly:
      POST http://localhost:8000/api/proxy/gemini
    The gateway validates against prompt injection, malicious signatures, and anomaly scores.
    If clean, forwards to Google Gemini and returns the genuine response.
    If malicious, returns HTTP 403 Forbidden with zero upstream calls.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}

    cfg = get_current_config()
    api_key = x_goog_api_key or request.query_params.get("key") or cfg.api_key

    client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (request.client.host if request.client else "127.0.0.1")
    user_agent = request.headers.get("user-agent", "External-Client/1.0")
    client_id = request.headers.get("x-client-id") or request.headers.get("x-consumer-name") or request.headers.get("x-app-name") or request.headers.get("x-api-client")
    city_hint = request.headers.get("x-client-city") or request.headers.get("cf-ipcity")
    country_hint = request.headers.get("x-client-country") or request.headers.get("cf-ipcountry")

    dispatch_req = ProxyDispatchRequest(
        target_url=cfg.target_url if "generativelanguage.googleapis.com" in cfg.target_url else "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent",
        api_key=api_key,
        method="POST",
        path="/api/proxy/gemini",
        body=body,
        simulated_user_agent=user_agent,
        client_city=city_hint,
        client_country=country_hint,
        caller_identity=client_id,
    )

    user_id = current_user.id if current_user else None
    username = (getattr(current_user, "email", None) or getattr(current_user, "name", None)) if current_user else None

    result = await dispatch_proxy_request(
        dispatch_req=dispatch_req,
        real_client_ip=client_ip,
        real_user_agent=user_agent,
        user_id=user_id,
        username=username,
    )

    if result.shield.policy_decision == "BLOCK":
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": {
                    "code": 403,
                    "message": "Blocked by Zero-Trust API Security Gateway Shield",
                    "status": "PERMISSION_DENIED",
                    "details": {
                        "risk_score": result.shield.risk_score,
                        "risk_level": result.shield.risk_level,
                        "reason": result.destination.block_reason,
                        "llm_threat": result.shield.llm_threat_type,
                    }
                }
            },
        )

    # Clean response: return destination payload
    if result.destination.upstream_status_code and result.destination.upstream_status_code >= 400:
        return JSONResponse(
            status_code=result.destination.upstream_status_code,
            content=result.destination.response_preview or {"error": result.destination.error_message},
        )

    return result.destination.response_preview or {"message": "Success"}
