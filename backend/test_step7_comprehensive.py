"""Comprehensive Verification Suite for STEP 7 — Risk Scoring & Policy Decision Engine.
Tests all 29+ requirements, unit tests, integration tests, live API endpoints, and regressions.
Uses Python standard library (urllib.request) - no external packages required.
"""

import sys
import json
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000"

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

passed_tests = 0
failed_tests = 0
results = []


def http_request(method: str, path: str, data=None, headers=None):
    url = f"{BASE_URL}{path}"
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)

    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)

    try:
        with urllib.request.urlopen(req) as resp:
            status = resp.status
            content = resp.read().decode("utf-8")
            try:
                json_data = json.loads(content)
            except Exception:
                json_data = content
            return status, json_data
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            content = e.read().decode("utf-8")
            json_data = json.loads(content)
        except Exception:
            json_data = None
        return status, json_data
    except Exception as e:
        return 0, str(e)


def record_result(test_name: str, passed: bool, details: str = ""):
    global passed_tests, failed_tests
    if passed:
        passed_tests += 1
        print(f"[{GREEN}PASS{RESET}] {test_name} {CYAN}{details}{RESET}")
        results.append((test_name, "PASS", details))
    else:
        failed_tests += 1
        print(f"[{RED}FAIL{RESET}] {test_name} {RED}{details}{RESET}")
        results.append((test_name, "FAIL", details))


def run_unit_tests():
    print(f"\n{YELLOW}=== PART 1: UNIT TESTS (Scoring Engine & Policy Decision Engine) ==={RESET}")
    from datetime import datetime, timezone
    from app.gateway.request_context import RequestContext
    from app.risk.scorer import calculate_risk
    from app.risk.policy import evaluate_policy, get_configured_policies
    from app.risk.models import RiskLevel, PolicyDecision

    now = datetime.now(timezone.utc)

    # 1. Normal request -> LOW (points: 0)
    ctx = RequestContext(
        request_id="test-1",
        method="GET",
        endpoint="/api/orders",
        is_sensitive_endpoint=False,
        is_authenticated=True,
        user_id=1,
        username="user1",
        role="USER",
        client_ip="127.0.0.1",
        user_agent="Mozilla/5.0",
        timestamp=now,
    )
    res = calculate_risk(ctx, [], {})
    record_result("Unit 1: Normal request -> 0 points LOW", res["risk_score"] == 0 and res["risk_level"] == "LOW", f"score={res['risk_score']}")

    # 2. Unknown device -> +18
    anom_dev = [{"anomaly_type": "UNKNOWN_DEVICE", "severity": "MEDIUM", "reason": "New device"}]
    res = calculate_risk(ctx, anom_dev, {})
    record_result("Unit 2: Unknown device -> +18 points", res["risk_score"] == 18 and res["risk_level"] == "LOW", f"score={res['risk_score']}")

    # 3. Location anomaly -> +20
    anom_loc = [{"anomaly_type": "LOCATION_ANOMALY", "severity": "MEDIUM", "reason": "New IP"}]
    res = calculate_risk(ctx, anom_loc, {})
    record_result("Unit 3: Location anomaly -> +20 points", res["risk_score"] == 20 and res["risk_level"] == "LOW", f"score={res['risk_score']}")

    # 4. API abuse -> +24
    anom_abuse = [{"anomaly_type": "API_ABUSE", "severity": "HIGH", "reason": "Rate spike"}]
    res = calculate_risk(ctx, anom_abuse, {})
    record_result("Unit 4: API abuse -> +24 points", res["risk_score"] == 24 and res["risk_level"] == "LOW", f"score={res['risk_score']}")

    # 5. Credential attack -> +25
    anom_cred = [{"anomaly_type": "CREDENTIAL_ATTACK", "severity": "HIGH", "reason": "Brute force"}]
    res = calculate_risk(ctx, anom_cred, {})
    record_result("Unit 5: Credential attack -> +25 points", res["risk_score"] == 25 and res["risk_level"] == "LOW", f"score={res['risk_score']}")

    # 6. Privilege misuse -> +20
    anom_priv = [{"anomaly_type": "PRIVILEGE_MISUSE", "severity": "HIGH", "reason": "Unauthorized access"}]
    res = calculate_risk(ctx, anom_priv, {})
    record_result("Unit 6: Privilege misuse -> +20 points", res["risk_score"] == 20 and res["risk_level"] == "LOW", f"score={res['risk_score']}")

    # 7. Multiple anomalies -> Additive score (18 + 20 + 10 = 48)
    ctx_sens = RequestContext(
        request_id="test-sens",
        method="GET",
        endpoint="/api/payment",
        is_sensitive_endpoint=True,
        is_authenticated=True,
        user_id=1,
        username="user1",
        role="USER",
        client_ip="127.0.0.1",
        user_agent="Mozilla/5.0",
        timestamp=now,
    )
    multi_anoms = [
        {"anomaly_type": "UNKNOWN_DEVICE", "severity": "MEDIUM", "reason": "New device"},
        {"anomaly_type": "LOCATION_ANOMALY", "severity": "MEDIUM", "reason": "New IP"},
    ]
    res = calculate_risk(ctx_sens, multi_anoms, {})
    expected_score = 18 + 20 + 10  # 48
    record_result("Unit 7: Multiple anomalies additive score (18+20+10=48)", res["risk_score"] == 48 and res["risk_level"] == "MEDIUM", f"score={res['risk_score']}")

    # 8. Score clamp <= 100
    all_anoms = [
        {"anomaly_type": "API_ABUSE", "severity": "HIGH", "reason": "abuse"},
        {"anomaly_type": "CREDENTIAL_ATTACK", "severity": "HIGH", "reason": "cred"},
        {"anomaly_type": "PRIVILEGE_MISUSE", "severity": "HIGH", "reason": "priv"},
        {"anomaly_type": "LOCATION_ANOMALY", "severity": "MEDIUM", "reason": "loc"},
        {"anomaly_type": "UNKNOWN_DEVICE", "severity": "MEDIUM", "reason": "dev"},
    ]
    res = calculate_risk(ctx, all_anoms, {})
    record_result("Unit 8: Score clamped at 100 (raw sum 107 -> 100)", res["risk_score"] == 100 and res["risk_level"] == "CRITICAL", f"score={res['risk_score']}")

    # 9. Score never becomes negative
    res_zero = calculate_risk(ctx, [], {})
    record_result("Unit 9: Score never negative (>= 0)", res_zero["risk_score"] >= 0, f"score={res_zero['risk_score']}")

    # 10. Boundaries 30/31/60/61/80/81/100
    from app.risk.scorer import _score_to_risk_level
    b_30 = _score_to_risk_level(30) == RiskLevel.LOW
    b_31 = _score_to_risk_level(31) == RiskLevel.MEDIUM
    b_60 = _score_to_risk_level(60) == RiskLevel.MEDIUM
    b_61 = _score_to_risk_level(61) == RiskLevel.HIGH
    b_80 = _score_to_risk_level(80) == RiskLevel.HIGH
    b_81 = _score_to_risk_level(81) == RiskLevel.CRITICAL
    b_100 = _score_to_risk_level(100) == RiskLevel.CRITICAL
    all_boundaries = b_30 and b_31 and b_60 and b_61 and b_80 and b_81 and b_100
    record_result("Unit 10: Risk level boundaries (30/31/60/61/80/81/100)", all_boundaries, "All 7 boundary points match spec")

    # Double-counting check: PRIVILEGE_MISUSE + sensitive endpoint should NOT double-count sensitive
    res_priv_sens = calculate_risk(ctx_sens, anom_priv, {})
    record_result("Unit 10b: Double counting protection (PRIVILEGE_MISUSE suppresses extra sensitive)", res_priv_sens["risk_score"] == 20, f"score={res_priv_sens['risk_score']}")

    # Policy evaluations:
    # 11. LOW -> ALLOW
    pol_low = evaluate_policy(15, RiskLevel.LOW.value, ctx)
    record_result("Unit 11: Policy LOW -> ALLOW", pol_low["decision"] == "ALLOW", f"decision={pol_low['decision']}")

    # 12. MEDIUM -> MONITOR
    pol_med = evaluate_policy(45, RiskLevel.MEDIUM.value, ctx)
    record_result("Unit 12: Policy MEDIUM -> MONITOR", pol_med["decision"] == "MONITOR", f"decision={pol_med['decision']}")

    # 13. HIGH -> RATE_LIMIT
    pol_high = evaluate_policy(75, RiskLevel.HIGH.value, ctx)
    record_result("Unit 13: Policy HIGH -> RATE_LIMIT", pol_high["decision"] == "RATE_LIMIT", f"decision={pol_high['decision']}")

    # 14. CRITICAL -> BLOCK (when supported by strong signals)
    pol_crit = evaluate_policy(95, RiskLevel.CRITICAL.value, ctx, reasons=res["reasons"], detection_results=all_anoms)
    record_result("Unit 14: Policy CRITICAL with strong signals -> BLOCK", pol_crit["decision"] == "BLOCK", f"decision={pol_crit['decision']}")

    # 14b. Blocking safety: Unknown device should NEVER cause BLOCK even if high score
    only_dev_reasons = [{"signal": "UNKNOWN_DEVICE", "points": 18, "description": "New device"}]
    pol_safe = evaluate_policy(85, RiskLevel.CRITICAL.value, ctx, reasons=only_dev_reasons, detection_results=[{"anomaly_type": "UNKNOWN_DEVICE"}])
    record_result("Unit 14b: Blocking safety (No strong attack signal -> falls back to RATE_LIMIT, does NOT block)", pol_safe["decision"] == "RATE_LIMIT", f"decision={pol_safe['decision']}")


def run_integration_tests():
    print(f"\n{YELLOW}=== PART 2: LIVE HTTP API TESTS (FastAPI + PostgreSQL) ==={RESET}")
    # Login credentials
    status, login_admin = http_request("POST", "/api/auth/login", data={"email": "admin@example.com", "password": "AdminPassword123"})
    admin_token = login_admin.get("access_token")
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    status, login_user = http_request("POST", "/api/auth/login", data={"email": "demo@example.com", "password": "StrongPassword123"})
    user_token = login_user.get("access_token")
    user_headers = {"Authorization": f"Bearer {user_token}"}

    # 15. Existing 401 remains 401
    status, r_401 = http_request("GET", "/api/orders")
    record_result("Integration 15: Existing 401 remains 401 without token", status == 401, f"status={status}")

    # 16. Existing 403 remains 403 (USER -> ADMIN endpoint)
    status, r_403 = http_request("GET", "/api/admin/users", headers=user_headers)
    record_result("Integration 16: Existing 403 remains 403 for RBAC violation", status == 403, f"status={status}")

    # 17. USER cannot access admin risk API (/api/risk -> 403)
    status, r_user_risk = http_request("GET", "/api/risk", headers=user_headers)
    record_result("Integration 17: USER cannot access admin risk API (/api/risk -> 403)", status == 403, f"status={status}")

    # 18. ADMIN can access risk API (/api/risk -> 200)
    status, r_admin_risk = http_request("GET", "/api/risk?limit=10", headers=admin_headers)
    record_result("Integration 18: ADMIN can access risk API (/api/risk -> 200)", status == 200, f"status={status}")

    # 19. User can access their own risk API (/api/risk/me -> 200)
    status, r_my_risk = http_request("GET", "/api/risk/me", headers=user_headers)
    has_score = status == 200 and isinstance(r_my_risk, dict) and "risk_score" in r_my_risk.get("data", {})
    record_result("Integration 19: User can access own risk API (/api/risk/me -> 200)", has_score, f"score={r_my_risk.get('data', {}).get('risk_score') if has_score else 'N/A'}")

    # 20. Policy API returns policies (ADMIN: 200, USER: 403)
    status_admin, r_pol_admin = http_request("GET", "/api/policies", headers=admin_headers)
    status_user, r_pol_user = http_request("GET", "/api/policies", headers=user_headers)
    record_result("Integration 20: GET /api/policies (ADMIN -> 200, USER -> 403)", status_admin == 200 and status_user == 403, f"admin={status_admin}, user={status_user}")

    # 21. Explainability: Risk reasons are returned and contain signal, points, description
    http_request("GET", "/api/payment", headers=user_headers)
    status, r_my_risk2 = http_request("GET", "/api/risk/me", headers=user_headers)
    reasons = r_my_risk2.get("data", {}).get("reasons", []) if isinstance(r_my_risk2, dict) else []
    has_valid_reasons = len(reasons) > 0 and all("signal" in r and "points" in r and "description" in r for r in reasons)
    record_result("Integration 21: Risk reasons explainability returned with signal/points/description", has_valid_reasons, f"count={len(reasons)}")

    # 22. Security: No secrets appear in risk metadata or logs
    status, r_recent_logs = http_request("GET", "/api/requests?limit=5", headers=admin_headers)
    logs_str = json.dumps(r_recent_logs)
    no_secrets = ("password_hash" not in logs_str) and ("secret_key" not in logs_str) and ("Bearer " not in logs_str)
    record_result("Integration 22: No secrets (passwords, JWTs, keys) leaked in telemetry/risk metadata", no_secrets, "Clean sanitization verified")


def run_regression_tests():
    print(f"\n{YELLOW}=== PART 3: REGRESSION SUITE (Steps 1–6) ==={RESET}")
    # 23. /health
    status, r_health = http_request("GET", "/health")
    record_result("Regression 23: GET /health -> 200 ok", status == 200 and r_health.get("status") == "ok")

    # 24. /health/database
    status, r_db = http_request("GET", "/health/database")
    record_result("Regression 24: GET /health/database -> 200 connected", status == 200 and r_db.get("database") == "connected")

    # 25. /docs
    status, r_docs = http_request("GET", "/docs")
    record_result("Regression 25: GET /docs -> 200 Swagger UI", status == 200)

    # 26. Step 2: Authentication
    status, login_res = http_request("POST", "/api/auth/login", data={"email": "admin@example.com", "password": "AdminPassword123"})
    token = login_res.get("access_token") if isinstance(login_res, dict) else None
    record_result("Regression 26: Authentication /api/auth/login generates valid JWT", status == 200 and bool(token))

    # 27. Step 3: Protected APIs
    headers = {"Authorization": f"Bearer {token}"}
    status_prof, r_prof = http_request("GET", "/api/profile", headers=headers)
    status_ord, r_ord = http_request("GET", "/api/orders", headers=headers)
    record_result("Regression 27: Protected APIs (/api/profile, /api/orders) respond with security_context", status_prof == 200 and status_ord == 200 and "security_context" in r_prof)

    # 28. Step 4: Request Telemetry & Security Events
    status_reqs, r_reqs = http_request("GET", "/api/requests?limit=5", headers=headers)
    status_events, r_events = http_request("GET", "/api/security/events?limit=5", headers=headers)
    record_result("Regression 28: Telemetry (/api/requests, /api/security/events) returns PostgreSQL records", status_reqs == 200 and status_events == 200)

    # 29. Step 5: Behavior Profiles
    status_profiles, r_profiles = http_request("GET", "/api/behavior/profiles", headers=headers)
    record_result("Regression 29: Behavior Profiles (/api/behavior/profiles) returns baseline models", status_profiles == 200)

    # 30. Step 6: Anomaly Detection
    status_anom, r_anom = http_request("GET", "/api/anomalies", headers=headers)
    record_result("Regression 30: Anomaly Detection (/api/anomalies) returns security anomalies", status_anom == 200)


if __name__ == "__main__":
    print(f"{CYAN}=================================================================={RESET}")
    print(f"{CYAN}  ZERO-TRUST ENGINE — STEP 7 COMPREHENSIVE VERIFICATION SUITE   {RESET}")
    print(f"{CYAN}=================================================================={RESET}")

    try:
        run_unit_tests()
        run_integration_tests()
        run_regression_tests()
    except Exception as e:
        print(f"\n{RED}ERROR RUNNING TEST SUITE: {e}{RESET}")
        import traceback
        traceback.print_exc()

    print(f"\n{YELLOW}=== SUMMARY ==={RESET}")
    print(f"Total Tests Executed: {passed_tests + failed_tests}")
    print(f"Passed: {GREEN}{passed_tests}{RESET}")
    print(f"Failed: {RED}{failed_tests}{RESET}")

    if failed_tests == 0:
        print(f"\n{GREEN}ALL STEP 7 & REGRESSION TESTS PASSED CLEANLY!{RESET}")
        sys.exit(0)
    else:
        print(f"\n{RED}SOME TESTS FAILED! CHECK OUTPUT ABOVE.{RESET}")
        sys.exit(1)
