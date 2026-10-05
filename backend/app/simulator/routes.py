"""API endpoints for local Attack Simulator (Step 8)."""

from fastapi import APIRouter, Depends, status

from app.gateway.dependencies import require_admin_only
from app.gateway.request_context import RequestContext
from app.simulator.attacks import execute_simulation
from app.simulator.schemas import SimulationRequest, SimulationResponse
from app.websocket.events import broadcast_simulation_completed

simulator_router = APIRouter(prefix="/api/simulator", tags=["Attack Simulator (Step 8)"])


@simulator_router.post(
    "/run",
    response_model=SimulationResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute a local attack simulation scenario (ADMIN only)",
)
async def run_attack_simulation(
    payload: SimulationRequest,
    context: RequestContext = Depends(require_admin_only),
):
    """Triggers real local HTTP requests through the Zero-Trust gateway to test threat detection."""
    result = await execute_simulation(payload.scenario)
    try:
        resulting_risk = (result.details or {}).get("resulting_risk", {})
        reasons = resulting_risk.get("reasons", [])
        threats_detected = len(reasons) if reasons else (1 if result.requests_generated > 0 else 0)
        highest_risk = resulting_risk.get("risk_score", 0)
        risk_level = resulting_risk.get("risk_level", "LOW")
        final_policy = resulting_risk.get("policy_decision", "ALLOW")

        await broadcast_simulation_completed(
            scenario=result.scenario,
            requests_generated=result.requests_generated,
            threats_detected=threats_detected,
            highest_risk=highest_risk,
            risk_level=risk_level,
            final_policy=final_policy,
            user_id=context.user_id,
        )
    except Exception as exc:
        pass
    return result
