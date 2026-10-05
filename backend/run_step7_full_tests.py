"""Comprehensive Step 7 and Regression Test Runner.
Executes all 12 checklist items live against FastAPI and PostgreSQL.
"""

import json
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

BASE_URL = "http://127.0.0.1:8000"

test_entries = []


def log_test(section: str, name: str, passed: bool, details: str):
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    status_str = "PASS" if passed else "FAIL"
    entry = f"[{now_str}] [{status_str}] [{section}] {name} - {details}"
    print(entry)
    test_entries.append((status_str, entry))


def http_req(method: str, path: str, data=None, token=None, headers=None):
    url = f"{BASE_URL}{path}"
    req_headers = {"Content-Type": "application/json"}
    if token:
        req_headers["Authorization"] = f"Bearer {token}"
    if headers:
        req_headers.update(headers)

    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)

    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req) as resp:
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            content = resp.read().decode("utf-8")
            try:
                data = json.loads(content)
            except Exception:
                data = content
            return resp.status, data, elapsed_ms, dict(resp.headers)
    except urllib.error.HTTPError as e:
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        try:
            content = e.read().decode("utf-8")
            data = json.loads(content)
        except Exception:
            data = None
        return e.code, data, elapsed_ms, dict(e.headers)
    except Exception as e:
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        return 0, str(e), elapsed_ms, {}


def main():
    print("=" * 85)
    print("  ZERO-TRUST API SECURITY & BEHAVIORAL ANOMALY ENGINE")
    print("  STEP 7 VERIFICATION & AUDIT TESTING EXECUTION")
    print(f"  Target: {BASE_URL} | Database: PostgreSQL zero_trust_db")
    print("=" * 85)

    # Unit modules
    from app.gateway.request_context import RequestContext
    from app.risk.scorer import calculate_risk, get_risk_level, _score_to_risk_level
    from app.risk.policy import evaluate_policy, get_configured_policies
    from app.risk.models import RiskLevel, PolicyDecision

    now = datetime.now(timezone.utc)
    base_ctx = RequestContext(
        request_id="test-ctx-normal",
        method="GET",
        endpoint="/api/orders",
        is_sensitive_endpoint=False,
        is_authenticated=True,
        user_id=1,
        username="demo@example.com",
        role="USER",
        client_ip="127.0.0.1",
        user_agent="Mozilla/5.0",
        timestamp=now,
    )

    sens_ctx = RequestContext(
        request_id="test-ctx-sens",
        method="GET",
        endpoint="/api/payment",
        is_sensitive_endpoint=True,
        is_authenticated=True,
        user_id=1,
        username="demo@example.com",
        role="USER",
        client_ip="127.0.0.1",
        user_agent="Mozilla/5.0",
        timestamp=now,
    )

    # -------------------------------------------------------------
    # 1. Normal request
    # -------------------------------------------------------------
    print("\n--- 1. Normal Request Evaluation ---")
    norm_res = calculate_risk(base_ctx, [], {})
    norm_pol = evaluate_policy(norm_res["risk_score"], norm_res["risk_level"], base_ctx)
    p1 = (norm_res["risk_score"] == 0 and norm_res["risk_level"] == "LOW" and norm_pol["decision"] == "ALLOW")
    log_test("STEP 7", "Normal Request Baseline Evaluation", p1, f"risk_score={norm_res['risk_score']}, risk_level={norm_res['risk_level']}, decision={norm_pol['decision']}")

    # -------------------------------------------------------------
    # 2. Unknown device (+18)
    # -------------------------------------------------------------
    print("\n--- 2. Unknown Device Signal ---")
    dev_anom = [{"anomaly_type": "UNKNOWN_DEVICE", "severity": "MEDIUM", "reason": "Request originated from an unrecognized device User-Agent."}]
    dev_res = calculate_risk(base_ctx, dev_anom, {})
    has_dev_reason = any(r["signal"] == "UNKNOWN_DEVICE" and r["points"] == 18 for r in dev_res["reasons"])
    p2 = (dev_res["risk_score"] == 18 and has_dev_reason and dev_res["risk_level"] == "LOW")
    log_test("STEP 7", "Unknown Device Signal (+18 Points)", p2, f"score={dev_res['risk_score']}, level={dev_res['risk_level']}, reasons={dev_res['reasons']}")

    # -------------------------------------------------------------
    # 3. Location anomaly (+20)
    # -------------------------------------------------------------
    print("\n--- 3. Location Anomaly Signal ---")
    loc_anom = [{"anomaly_type": "LOCATION_ANOMALY", "severity": "MEDIUM", "reason": "Request originated from an IP address not previously observed."}]
    loc_res = calculate_risk(base_ctx, loc_anom, {})
    p3 = (loc_res["risk_score"] == 20 and any(r["signal"] == "LOCATION_ANOMALY" and r["points"] == 20 for r in loc_res["reasons"]))
    log_test("STEP 7", "Location Anomaly Signal (+20 Points)", p3, f"score={loc_res['risk_score']}, level={loc_res['risk_level']}")

    # -------------------------------------------------------------
    # 4. API abuse (+24)
    # -------------------------------------------------------------
    print("\n--- 4. API Abuse Signal ---")
    abuse_anom = [{"anomaly_type": "API_ABUSE", "severity": "HIGH", "reason": "Request frequency is significantly higher than normal baseline."}]
    abuse_res = calculate_risk(base_ctx, abuse_anom, {})
    p4 = (abuse_res["risk_score"] == 24 and any(r["signal"] == "API_ABUSE" and r["points"] == 24 for r in abuse_res["reasons"]))
    log_test("STEP 7", "API Abuse Signal (+24 Points)", p4, f"score={abuse_res['risk_score']}, level={abuse_res['risk_level']}")

    # -------------------------------------------------------------
    # 5. Credential attack (+25)
    # -------------------------------------------------------------
    print("\n--- 5. Credential Attack Signal ---")
    cred_anom = [{"anomaly_type": "CREDENTIAL_ATTACK", "severity": "HIGH", "reason": "Failed request volume exceeds normal baseline threshold."}]
    cred_res = calculate_risk(base_ctx, cred_anom, {})
    p5 = (cred_res["risk_score"] == 25 and any(r["signal"] == "CREDENTIAL_ATTACK" and r["points"] == 25 for r in cred_res["reasons"]))
    log_test("STEP 7", "Credential Attack Signal (+25 Points)", p5, f"score={cred_res['risk_score']}, level={cred_res['risk_level']}")

    # -------------------------------------------------------------
    # 6. Privilege misuse (+20) & 403 Preservation
    # -------------------------------------------------------------
    print("\n--- 6. Privilege Misuse (+20) & 403 Preservation ---")
    priv_anom = [{"anomaly_type": "PRIVILEGE_MISUSE", "severity": "HIGH", "reason": "Unauthorized attempt to access privileged endpoint."}]
    priv_res = calculate_risk(base_ctx, priv_anom, {})
    p6_score = (priv_res["risk_score"] == 20 and any(r["signal"] == "PRIVILEGE_MISUSE" and r["points"] == 20 for r in priv_res["reasons"]))
    log_test("STEP 7", "Privilege Misuse Signal (+20 Points)", p6_score, f"score={priv_res['risk_score']}, level={priv_res['risk_level']}")

    # -------------------------------------------------------------
    # 7. Sensitive endpoint (+10) & Double-counting Guard
    # -------------------------------------------------------------
    print("\n--- 7. Sensitive Endpoint (+10) & Double-Counting Guard ---")
    sens_res = calculate_risk(sens_ctx, [], {})
    p7_sens = (sens_res["risk_score"] == 10 and any(r["signal"] == "SENSITIVE_ENDPOINT" and r["points"] == 10 for r in sens_res["reasons"]))
    log_test("STEP 7", "Sensitive Endpoint Signal Elevation (+10 Points)", p7_sens, f"score={sens_res['risk_score']}, is_sensitive=True")

    # Double-counting check: PRIVILEGE_MISUSE on sensitive endpoint should NOT add +10
    priv_sens_res = calculate_risk(sens_ctx, priv_anom, {})
    p7_no_double = (priv_sens_res["risk_score"] == 20 and not any(r["signal"] == "SENSITIVE_ENDPOINT" for r in priv_sens_res["reasons"]))
    log_test("STEP 7", "Double-Counting Prevention (PRIVILEGE_MISUSE suppresses extra sensitive)", p7_no_double, f"score={priv_sens_res['risk_score']}, double_counting_suppressed={p7_no_double}")

    # -------------------------------------------------------------
    # 8. Multiple anomalies & Score Clamping (0 <= score <= 100)
    # -------------------------------------------------------------
    print("\n--- 8. Multiple Anomalies & Clamping Ceiling ---")
    # 18 (device) + 20 (location) + 10 (sensitive) = 48
    multi_anoms = [
        {"anomaly_type": "UNKNOWN_DEVICE", "severity": "MEDIUM", "reason": "Unrecognized device"},
        {"anomaly_type": "LOCATION_ANOMALY", "severity": "MEDIUM", "reason": "Unrecognized location"},
    ]
    multi_res = calculate_risk(sens_ctx, multi_anoms, {})
    p8_additive = (multi_res["risk_score"] == 48 and multi_res["risk_level"] == "MEDIUM")
    log_test("STEP 7", "Multiple Anomalies Additive Sum (18+20+10=48)", p8_additive, f"score={multi_res['risk_score']}, level={multi_res['risk_level']}")

    # Clamping ceiling at 100
    flood_anoms = [
        {"anomaly_type": "API_ABUSE"},          # 24
        {"anomaly_type": "CREDENTIAL_ATTACK"},   # 25
        {"anomaly_type": "PRIVILEGE_MISUSE"},    # 20
        {"anomaly_type": "LOCATION_ANOMALY"},    # 20
        {"anomaly_type": "UNKNOWN_DEVICE"},      # 18 -> raw sum 107
    ]
    clamp_res = calculate_risk(base_ctx, flood_anoms, {})
    p8_clamp = (clamp_res["risk_score"] == 100 and clamp_res["risk_level"] == "CRITICAL")
    log_test("STEP 7", "Upper Clamping Ceiling Enforcement (Raw 107 -> Clamped 100)", p8_clamp, f"score={clamp_res['risk_score']}, level={clamp_res['risk_level']}")

    # -------------------------------------------------------------
    # 9. Risk Boundaries (0–30, 31–60, 61–80, 81–100)
    # -------------------------------------------------------------
    print("\n--- 9. Deterministic Risk Level Boundaries ---")
    b0 = get_risk_level(0) == "LOW"
    b30 = get_risk_level(30) == "LOW"
    b31 = get_risk_level(31) == "MEDIUM"
    b60 = get_risk_level(60) == "MEDIUM"
    b61 = get_risk_level(61) == "HIGH"
    b80 = get_risk_level(80) == "HIGH"
    b81 = get_risk_level(81) == "CRITICAL"
    b100 = get_risk_level(100) == "CRITICAL"
    all_b = b0 and b30 and b31 and b60 and b61 and b80 and b81 and b100
    log_test("STEP 7", "Risk Level Boundary Transitions (0/30/31/60/61/80/81/100)", all_b, "0-30: LOW | 31-60: MEDIUM | 61-80: HIGH | 81-100: CRITICAL verified")

    # -------------------------------------------------------------
    # 10. Policy Mapping (ALLOW, MONITOR, RATE_LIMIT, BLOCK)
    # -------------------------------------------------------------
    print("\n--- 10. Policy Mapping & Safety ---")
    pol_low = evaluate_policy(15, "LOW", base_ctx)["decision"] == "ALLOW"
    pol_med = evaluate_policy(45, "MEDIUM", base_ctx)["decision"] == "MONITOR"
    pol_high = evaluate_policy(75, "HIGH", base_ctx)["decision"] == "RATE_LIMIT"
    pol_crit = evaluate_policy(95, "CRITICAL", base_ctx, reasons=clamp_res["reasons"])["decision"] == "BLOCK"
    p10_pol = pol_low and pol_med and pol_high and pol_crit
    log_test("STEP 7", "Policy Mapping (LOW->ALLOW, MED->MONITOR, HIGH->RATE_LIMIT, CRIT->BLOCK)", p10_pol, "LOW: ALLOW | MEDIUM: MONITOR | HIGH: RATE_LIMIT | CRITICAL: BLOCK verified")

    # Blocking safety: benign signal (UNKNOWN_DEVICE) alone must NEVER block
    pol_safe = evaluate_policy(85, "CRITICAL", base_ctx, reasons=[{"signal": "UNKNOWN_DEVICE", "points": 18}])["decision"] == "RATE_LIMIT"
    log_test("STEP 7", "Blocking Safety Guard (Benign signal alone never triggers BLOCK)", pol_safe, "Safe fallback to RATE_LIMIT confirmed")

    # -------------------------------------------------------------
    # 11. API Security & Role Restrictions
    # -------------------------------------------------------------
    print("\n--- 11. API Security & Access Control ---")
    # Authenticate USER and ADMIN
    s_u, u_data, lat_u, _ = http_req("POST", "/api/auth/login", data={"email": "demo@example.com", "password": "StrongPassword123"})
    user_token = u_data["access_token"]

    s_a, a_data, lat_a, _ = http_req("POST", "/api/auth/login", data={"email": "admin@example.com", "password": "AdminPassword123"})
    admin_token = a_data["access_token"]

    # USER -> /api/risk (Expected: 403 Forbidden)
    s_ur, d_ur, lat_ur, _ = http_req("GET", "/api/risk", token=user_token)
    p11_ur = (s_ur == 403)
    log_test("STEP 7", "USER Blocked from Admin Risk API (GET /api/risk -> 403)", p11_ur, f"status={s_ur}, latency={lat_ur}ms")

    # ADMIN -> /api/risk (Expected: 200 OK)
    s_ar, d_ar, lat_ar, _ = http_req("GET", "/api/risk?limit=10", token=admin_token)
    p11_ar = (s_ar == 200 and isinstance(d_ar.get("data"), list))
    log_test("STEP 7", "ADMIN Allowed to Admin Risk API (GET /api/risk -> 200)", p11_ar, f"status={s_ar}, records={len(d_ar.get('data', []))}, latency={lat_ar}ms")

    # Authenticated USER -> /api/risk/me (Expected: 200 OK)
    s_me, d_me, lat_me, _ = http_req("GET", "/api/risk/me", token=user_token)
    p11_me = (s_me == 200 and "risk_score" in d_me.get("data", {}))
    log_test("STEP 7", "Authenticated USER Query Own Risk (GET /api/risk/me -> 200)", p11_me, f"status={s_me}, risk_score={d_me.get('data', {}).get('risk_score')}, latency={lat_me}ms")

    # ADMIN -> /api/policies (Expected: 200 OK) & USER -> /api/policies (Expected: 403)
    s_pol_a, d_pol_a, lat_pa, _ = http_req("GET", "/api/policies", token=admin_token)
    s_pol_u, d_pol_u, lat_pu, _ = http_req("GET", "/api/policies", token=user_token)
    p11_pol = (s_pol_a == 200 and s_pol_u == 403 and len(d_pol_a.get("policies", [])) == 4)
    log_test("STEP 7", "Policy Blueprint Endpoint (ADMIN -> 200, USER -> 403)", p11_pol, f"admin_status={s_pol_a}, user_status={s_pol_u}, active_policies={len(d_pol_a.get('policies', []))}")

    # RBAC 403 preservation: USER -> /api/admin/users
    s_rbac, d_rbac, lat_rbac, _ = http_req("GET", "/api/admin/users", token=user_token)
    p11_rbac = (s_rbac == 403 and d_rbac.get("error", {}).get("code") == "FORBIDDEN")
    log_test("STEP 7", "Existing RBAC 403 Preserved (USER -> /api/admin/users -> 403)", p11_rbac, f"status={s_rbac}, error_code={d_rbac.get('error', {}).get('code')}")

    # 401 Unauthorized preservation: Missing token -> /api/orders
    s_noauth, d_noauth, lat_noauth, _ = http_req("GET", "/api/orders")
    p11_401 = (s_noauth == 401)
    log_test("STEP 7", "Existing 401 Preserved (No JWT -> /api/orders -> 401)", p11_401, f"status={s_noauth}")

    # -------------------------------------------------------------
    # 12. Regression Suite (Steps 1–6)
    # -------------------------------------------------------------
    print("\n--- 12. Comprehensive Regression Suite (Steps 1–6) ---")

    # Step 1: /health & /health/database & /docs
    s_h, d_h, lat_h, _ = http_req("GET", "/health")
    p12_h = (s_h == 200 and d_h.get("status") == "ok")
    log_test("STEP 1", "Service Operational Health (/health -> 200)", p12_h, f"status={s_h}, latency={lat_h}ms")

    s_db, d_db, lat_db, _ = http_req("GET", "/health/database")
    p12_db = (s_db == 200 and d_db.get("database") == "connected")
    log_test("STEP 1", "PostgreSQL Database Connectivity (/health/database -> 200)", p12_db, f"status={s_db}, latency={lat_db}ms")

    s_docs, _, lat_docs, _ = http_req("GET", "/docs")
    p12_docs = (s_docs == 200)
    log_test("STEP 1", "Interactive OpenAPI Documentation (/docs -> 200)", p12_docs, f"status={s_docs}, latency={lat_docs}ms")

    # Step 2: Login & JWT authentication
    p12_auth = (s_u == 200 and bool(user_token) and s_a == 200 and bool(admin_token))
    log_test("STEP 2", "JWT Authentication & Principal Token Issuance", p12_auth, f"user_role={u_data.get('user', {}).get('role')}, admin_role={a_data.get('user', {}).get('role')}")

    # Step 3: Protected APIs
    s_prof, d_prof, lat_prof, _ = http_req("GET", "/api/profile", token=user_token)
    s_ord, d_ord, lat_ord, _ = http_req("GET", "/api/orders", token=user_token)
    s_pay, d_pay, lat_pay, _ = http_req("GET", "/api/payment", token=user_token)
    p12_apis = (s_prof == 200 and s_ord == 200 and s_pay == 200 and d_pay.get("security_context", {}).get("sensitive") is True)
    log_test("STEP 3", "Protected Gateway APIs (/api/profile, /api/orders, /api/payment)", p12_apis, f"profile={s_prof}, orders={s_ord}, payment(sensitive)={s_pay}")

    # Step 4: Request Telemetry & Security Events
    s_reqs, d_reqs, lat_reqs, _ = http_req("GET", "/api/requests?limit=10", token=admin_token)
    s_evts, d_evts, lat_evts, _ = http_req("GET", "/api/security/events?limit=10", token=admin_token)
    p12_telem = (s_reqs == 200 and s_evts == 200 and len(d_reqs.get("data", [])) > 0)
    log_test("STEP 4", "Persistent PostgreSQL Telemetry Logs & Security Events", p12_telem, f"request_logs_returned={len(d_reqs.get('data', []))}, security_events_returned={len(d_evts.get('data', []))}")

    # Step 5: Behavior Profiles & Feature Engine
    s_prof5, d_prof5, lat_prof5, _ = http_req("GET", "/api/behavior/profiles", token=admin_token)
    s_feat5, d_feat5, lat_feat5, _ = http_req("GET", "/api/behavior/features", token=user_token)
    p12_beh = (s_prof5 == 200 and s_feat5 == 200 and "requests_per_minute" in d_feat5.get("data", {}))
    log_test("STEP 5", "Behavior Profiles & Live Behavioral Feature Snapshot", p12_beh, f"modeled_profiles={len(d_prof5.get('data', []))}, features_status={s_feat5}")

    # Step 6: Rule-Based Anomaly Detection
    s_anom6, d_anom6, lat_anom6, _ = http_req("GET", "/api/anomalies?limit=10", token=admin_token)
    p12_anom = (s_anom6 == 200 and isinstance(d_anom6.get("data"), list))
    log_test("STEP 6", "Rule-Based Behavioral Anomaly Intelligence (/api/anomalies)", p12_anom, f"anomalies_detected={len(d_anom6.get('data', []))}, latency={lat_anom6}ms")

    # -------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------
    total = len(test_entries)
    passed = sum(1 for s, _ in test_entries if s == "PASS")
    failed = total - passed

    print("\n" + "=" * 85)
    print("  FINAL STEP 7 EXECUTION SUMMARY")
    print(f"  TOTAL CHECKS: {total} | PASSED: {passed} | FAILED: {failed}")
    print(f"  SUCCESS RATE: {(passed / total) * 100:.1f}%")
    print("=" * 85)

    return failed == 0


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
