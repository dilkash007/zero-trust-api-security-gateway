"""Safe local attack simulation engine (Step 8).

Generates real HTTP traffic against this application's local endpoints to test and demonstrate
the end-to-end Zero-Trust pipeline:
Request -> Logging -> Behavior Engine -> Rule Engine -> ML Engine -> Risk Scoring -> Policy Enforcement.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional
import httpx

from app.simulator.schemas import ScenarioEnum, SimulationResponse

logger = logging.getLogger("zero_trust.simulator")

BASE_URL = "http://127.0.0.1:8000"


async def get_test_user_token(client: httpx.AsyncClient) -> Optional[str]:
    """Authenticates standard test user via real HTTP login endpoint."""
    try:
        for pwd in ("testpass123", "StrongPassword123", "Password123!"):
            resp = await client.post(
                "/api/auth/login",
                json={"email": "demo@example.com", "password": pwd},
            )
            if resp.status_code == 200:
                return resp.json().get("access_token")
    except Exception as exc:
        logger.error("Simulator failed to acquire user token: %s", exc)
    return None


async def run_api_abuse_simulation(client: httpx.AsyncClient, token: str) -> Dict[str, Any]:
    """Generates an abrupt burst of 35 requests to trigger the API_ABUSE frequency rule."""
    headers = {"Authorization": f"Bearer {token}"}
    success_count = 0
    statuses = []

    for _ in range(35):
        resp = await client.get("/api/orders", headers=headers)
        statuses.append(resp.status_code)
        if resp.status_code == 200:
            success_count += 1
        await asyncio.sleep(0.01)

    return {
        "requests_generated": len(statuses),
        "target_endpoint": "/api/orders",
        "expected_detection": "API_ABUSE",
        "successful_requests": success_count,
        "sample_status_codes": statuses[:5],
    }


async def run_credential_attack_simulation(client: httpx.AsyncClient) -> Dict[str, Any]:
    """Generates failed login attempts using a non-existent test account."""
    failures = 0
    statuses = []

    for idx in range(12):
        resp = await client.post(
            "/api/auth/login",
            json={"email": f"simulator_test_{idx}@example.local", "password": "WrongPassword123!"},
        )
        statuses.append(resp.status_code)
        if resp.status_code == 401:
            failures += 1
        await asyncio.sleep(0.02)

    return {
        "requests_generated": len(statuses),
        "target_endpoint": "/api/auth/login",
        "expected_detection": "CREDENTIAL_ATTACK",
        "failed_attempts": failures,
        "sample_status_codes": statuses[:5],
    }


async def run_privilege_misuse_simulation(client: httpx.AsyncClient, token: str) -> Dict[str, Any]:
    """Attempts unauthorized access to ADMIN-only endpoints with standard USER identity."""
    headers = {"Authorization": f"Bearer {token}"}
    forbidden_count = 0
    targets = ["/api/admin/users", "/api/admin/transactions"]
    statuses = []

    for target in targets:
        resp = await client.get(target, headers=headers)
        statuses.append(resp.status_code)
        if resp.status_code == 403:
            forbidden_count += 1

    return {
        "requests_generated": len(targets),
        "target_endpoints": targets,
        "expected_detection": "PRIVILEGE_MISUSE",
        "forbidden_403_responses": forbidden_count,
    }


async def run_unknown_device_simulation(client: httpx.AsyncClient, token: str) -> Dict[str, Any]:
    """Sends authenticated request with an unrecognized device User-Agent."""
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "ZeroTrust-Simulator-Unknown-Device/1.0 (Hackathon Security Audit Tool)",
    }
    resp = await client.get("/api/orders", headers=headers)

    return {
        "requests_generated": 1,
        "target_endpoint": "/api/orders",
        "simulated_device": "ZeroTrust-Simulator-Unknown-Device/1.0",
        "expected_detection": "UNKNOWN_DEVICE",
        "status_code": resp.status_code,
    }


async def run_location_anomaly_simulation(client: httpx.AsyncClient, token: str) -> Dict[str, Any]:
    """Sends authenticated request with an unobserved client IP address."""
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Forwarded-For": "198.51.100.99",
    }
    resp = await client.get("/api/orders", headers=headers)

    return {
        "requests_generated": 1,
        "target_endpoint": "/api/orders",
        "simulated_ip": "198.51.100.99",
        "expected_detection": "LOCATION_ANOMALY",
        "status_code": resp.status_code,
    }


async def run_combined_attack_simulation(client: httpx.AsyncClient, token: str) -> Dict[str, Any]:
    """Executes a multi-vector attack combining unusual device, new IP, sensitive endpoint, and burst."""
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "ZeroTrust-Simulator-Combined-Attack/2.0",
        "X-Forwarded-For": "203.0.113.88",
    }
    statuses = []

    for _ in range(25):
        resp = await client.get("/api/payment", headers=headers)
        statuses.append(resp.status_code)
        await asyncio.sleep(0.01)

    return {
        "requests_generated": len(statuses),
        "target_endpoint": "/api/payment (Sensitive)",
        "expected_detections": [
            "UNKNOWN_DEVICE",
            "LOCATION_ANOMALY",
            "API_ABUSE",
            "SENSITIVE_ENDPOINT",
            "ML_ANOMALY",
        ],
        "expected_risk_tier": "HIGH / CRITICAL",
        "sample_status_codes": statuses[:5],
    }


async def execute_simulation(scenario: ScenarioEnum) -> SimulationResponse:
    """Dispatches the chosen attack scenario using real local HTTP requests."""
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=20.0) as client:
        # Acquire token for authenticated scenarios
        user_token = await get_test_user_token(client)
        if not user_token and scenario != ScenarioEnum.CREDENTIAL_ATTACK:
            return SimulationResponse(
                scenario=scenario.value,
                status="failed",
                requests_generated=0,
                message="Unable to acquire simulator test token. Please verify backend auth.",
                details={},
            )

        details: Dict[str, Any] = {}
        requests_count = 0

        if scenario == ScenarioEnum.API_ABUSE:
            details = await run_api_abuse_simulation(client, user_token)
            requests_count = details.get("requests_generated", 35)
            msg = f"Executed {requests_count} rapid API calls against /api/orders."

        elif scenario == ScenarioEnum.CREDENTIAL_ATTACK:
            details = await run_credential_attack_simulation(client)
            requests_count = details.get("requests_generated", 12)
            msg = f"Generated {requests_count} authentication failures on /api/auth/login."

        elif scenario == ScenarioEnum.PRIVILEGE_MISUSE:
            details = await run_privilege_misuse_simulation(client, user_token)
            requests_count = details.get("requests_generated", 2)
            msg = "Attempted unauthorized access to admin endpoints with standard USER identity."

        elif scenario == ScenarioEnum.UNKNOWN_DEVICE:
            details = await run_unknown_device_simulation(client, user_token)
            requests_count = 1
            msg = "Sent request from unfamiliar device User-Agent."

        elif scenario == ScenarioEnum.LOCATION_ANOMALY:
            details = await run_location_anomaly_simulation(client, user_token)
            requests_count = 1
            msg = "Sent request from newly observed client IP."

        elif scenario == ScenarioEnum.COMBINED_ATTACK:
            details = await run_combined_attack_simulation(client, user_token)
            requests_count = details.get("requests_generated", 25)
            msg = "Executed multi-vector attack combining device, location, sensitive endpoint, and frequency."

        else:
            return SimulationResponse(
                scenario=scenario.value,
                status="error",
                requests_generated=0,
                message=f"Unknown scenario: {scenario}",
                details={},
            )

        # Query latest evaluated risk from /api/risk/me to attach to response
        try:
            if user_token:
                risk_resp = await client.get("/api/risk/me", headers={"Authorization": f"Bearer {user_token}"})
                if risk_resp.status_code == 200:
                    details["resulting_risk"] = risk_resp.json().get("data", {})
        except Exception:
            pass

        return SimulationResponse(
            scenario=scenario.value,
            status="completed",
            requests_generated=requests_count,
            message=msg,
            details=details,
        )
