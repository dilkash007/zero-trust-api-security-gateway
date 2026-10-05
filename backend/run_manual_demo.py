"""Manual Demo Test Script executing Section 45 & 46:
Step A: Train ML
Step B: Normal request
Step C: API abuse simulation
Step D: Unknown device simulation
Step E: Privilege misuse simulation
Step F: Combined attack simulation
Database verification: PostgreSQL records before vs after
"""

import json
import time
import urllib.request
from app.auth.jwt import create_access_token
from app.database.connection import SessionLocal
from app.database.models import ApiRequestLog, SecurityEvent, User, UserRole

BASE_URL = "http://127.0.0.1:8000"


def http_call(method: str, path: str, token: str = None, data: dict = None, extra_headers: dict = None):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)

    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode("utf-8")
            return resp.status, json.loads(content)
    except urllib.error.HTTPError as e:
        content = e.read().decode("utf-8")
        try:
            return e.code, json.loads(content)
        except Exception:
            return e.code, content


def main():
    db = SessionLocal()
    admin_user = db.query(User).filter(User.role == UserRole.ADMIN.value).first()
    standard_user = db.query(User).filter(User.role == UserRole.USER.value).first()

    admin_token = create_access_token(user_id=admin_user.id, role=admin_user.role)
    user_token = create_access_token(user_id=standard_user.id, role=standard_user.role)

    pre_logs = db.query(ApiRequestLog).count()
    pre_events = db.query(SecurityEvent).count()
    db.close()

    print("====================================================================")
    print("      STEP 8 MANUAL DEMO WALKTHROUGH & DATABASE VERIFICATION        ")
    print("====================================================================")
    print(f"Pre-Simulation DB State: {pre_logs} request logs, {pre_events} security events.\n")

    # Step A — Train ML
    print("[STEP A] Train ML Model via POST /api/ml/train")
    st_a, res_a = http_call("POST", "/api/ml/train", token=admin_token)
    print(f"  -> HTTP Status: {st_a}")
    print(f"  -> Response: {json.dumps(res_a.get('data', {}), indent=2)}")
    assert st_a == 200, "Train ML failed"

    # Step B — Normal request
    print("\n[STEP B] Normal API Request: GET /api/profile")
    st_b, res_b = http_call("GET", "/api/profile", token=user_token)
    st_risk_b, res_risk_b = http_call("GET", "/api/risk/me", token=user_token)
    print(f"  -> /api/profile Status: {st_b}")
    print(f"  -> Risk Assessment: Score={res_risk_b.get('data', {}).get('risk_score')}, Level={res_risk_b.get('data', {}).get('risk_level')}, Decision={res_risk_b.get('data', {}).get('decision')}")

    # Step C — API abuse
    print("\n[STEP C] Attack Simulation: API_ABUSE")
    st_c, res_c = http_call("POST", "/api/simulator/run", token=admin_token, data={"scenario": "API_ABUSE"})
    print(f"  -> Simulation Status: {res_c.get('status')}, Requests: {res_c.get('requests_generated')}")
    print(f"  -> Result Details: {json.dumps(res_c.get('details', {}), indent=2)}")

    # Step D — Unknown device
    print("\n[STEP D] Attack Simulation: UNKNOWN_DEVICE")
    st_d, res_d = http_call("POST", "/api/simulator/run", token=admin_token, data={"scenario": "UNKNOWN_DEVICE"})
    print(f"  -> Simulation Status: {res_d.get('status')}")
    print(f"  -> Resulting Risk: {json.dumps(res_d.get('details', {}).get('resulting_risk', {}), indent=2)}")

    # Step E — Privilege misuse
    print("\n[STEP E] Attack Simulation: PRIVILEGE_MISUSE")
    st_e, res_e = http_call("POST", "/api/simulator/run", token=admin_token, data={"scenario": "PRIVILEGE_MISUSE"})
    print(f"  -> Simulation Status: {res_e.get('status')}")
    print(f"  -> Details: {json.dumps(res_e.get('details', {}), indent=2)}")

    # Step F — Combined attack
    print("\n[STEP F] Attack Simulation: COMBINED_ATTACK (Primary Demo)")
    st_f, res_f = http_call("POST", "/api/simulator/run", token=admin_token, data={"scenario": "COMBINED_ATTACK"})
    print(f"  -> Simulation Status: {res_f.get('status')}, Requests: {res_f.get('requests_generated')}")
    print(f"  -> Details: {json.dumps(res_f.get('details', {}), indent=2)}")

    # Database Verification (Section 46)
    db = SessionLocal()
    post_logs = db.query(ApiRequestLog).count()
    post_events = db.query(SecurityEvent).count()
    recent_logs = db.query(ApiRequestLog).order_by(ApiRequestLog.id.desc()).limit(5).all()
    recent_evs = db.query(SecurityEvent).order_by(SecurityEvent.id.desc()).limit(5).all()
    db.close()

    print("\n====================================================================")
    print("                    DATABASE VERIFICATION AUDIT                     ")
    print("====================================================================")
    print(f"PostgreSQL Request Logs: {pre_logs} -> {post_logs} (Delta: +{post_logs - pre_logs} real rows)")
    print(f"PostgreSQL Security Events: {pre_events} -> {post_events} (Delta: +{post_events - pre_events} real events)")
    print("\nSample Recent DB Request Logs:")
    for l in recent_logs:
        print(f"  - ID: {l.id} | ReqID: {l.request_id[:8]}.. | Endpoint: {l.endpoint} | Status: {l.status_code} | Risk: {l.risk_score} ({l.risk_level}) | Policy: {l.policy_decision}")
    print("\nSample Recent DB Security Events:")
    for ev in recent_evs:
        print(f"  - Event: {ev.event_type} | Severity: {ev.severity} | Endpoint: {ev.endpoint} | Msg: {ev.message}")

    assert post_logs > pre_logs, "Logs did not increase!"
    print("\n>>> MANUAL DEMO WALKTHROUGH & DATABASE AUDIT: COMPLETE SUCCESS <<<\n")


if __name__ == "__main__":
    main()
