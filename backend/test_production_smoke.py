"""Production Conversion Smoke Test"""
import sys
sys.path.insert(0, ".")
import requests, json

BASE = "http://localhost:8000"

def login(username, password):
    r = requests.post(f"{BASE}/auth/login", json={"username": username, "password": password})
    return r.json().get("data", {}).get("access_token")

def hdr(tok): return {"Authorization": f"Bearer {tok}"}

print("=" * 60)
print("PRODUCTION CONVERSION SMOKE TESTS")
print("=" * 60)

# --- 1. Health check & version
r = requests.get(f"{BASE}/health")
v = r.json()
print(f"\n[1] Health: {v['status']} | version={v['version']}")
assert v["version"] == "1.0.0", f"VERSION MISMATCH: {v['version']}"
print("    PASS: Version 1.0.0 confirmed")

# --- 2. Security headers
r = requests.get(f"{BASE}/health")
headers = r.headers
required_headers = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]
print(f"\n[2] Security Headers:")
all_headers_ok = True
for h in required_headers:
    val = headers.get(h, "MISSING")
    ok = val != "MISSING"
    all_headers_ok = all_headers_ok and ok
    status = "PASS" if ok else "FAIL"
    print(f"    [{status}] {h}: {val[:70]}")
print(f"    {'PASS: All headers present' if all_headers_ok else 'FAIL: Missing headers'}")

# --- 3. Authenticated request with X-Request-ID
tok = login("alice", "password123")
if tok:
    r = requests.get(f"{BASE}/api/profile", headers=hdr(tok))
    print(f"\n[3] Authenticated Request: status={r.status_code}")
    rid = r.headers.get("X-Request-ID", "MISSING")
    print(f"    X-Request-ID: {rid}")
    print(f"    {'PASS' if rid != 'MISSING' else 'FAIL'}: X-Request-ID present in response")
else:
    print("\n[3] SKIP: Login failed (DB may need seeding)")

# --- 4. Rate limit test on protected endpoint with simulated IPs
print(f"\n[4] In-Memory Rate Limiter (Burst Test):")
# Use a dedicated test IP so we don't block real test traffic
test_ip = "10.254.254.1"
blocked = 0
success = 0
for i in range(30):
    auth_header = hdr(tok) if tok else {}
    merged_headers = {**auth_header, "X-Simulated-IP": test_ip}
    r = requests.get(
        f"{BASE}/api/requests",
        headers=merged_headers
    )
    if r.status_code == 429:
        blocked += 1
    else:
        success += 1

print(f"    Total: 30 requests | Allowed: {success} | Blocked (429): {blocked}")
if blocked > 0:
    last_429 = r.json()
    print(f"    Response code: {last_429.get('error', {}).get('code', 'N/A')}")
    print("    PASS: Rate limiter is active and enforcing limits")
else:
    print("    INFO: No requests blocked (window not exceeded yet — expected on fresh run)")

# --- 5. Config values
print(f"\n[5] Production Config:")
from app.config import settings
items = [
    ("POLICY_ENFORCEMENT_ACTIVE", settings.POLICY_ENFORCEMENT_ACTIVE),
    ("RATE_LIMIT_REQUESTS", settings.RATE_LIMIT_REQUESTS),
    ("RATE_LIMIT_WINDOW_SECONDS", settings.RATE_LIMIT_WINDOW_SECONDS),
    ("RATE_LIMIT_BURST_REQUESTS", settings.RATE_LIMIT_BURST_REQUESTS),
    ("RATE_LIMIT_BURST_WINDOW_SECONDS", settings.RATE_LIMIT_BURST_WINDOW_SECONDS),
    ("REDIS_URL", settings.REDIS_URL or "(not set — in-memory fallback active)"),
    ("DEBUG", settings.DEBUG),
]
for k, v in items:
    print(f"    {k} = {v}")

# --- 6. DB health
r = requests.get(f"{BASE}/health/database")
print(f"\n[6] Database Health: {r.json()}")
print(f"    {'PASS' if r.status_code == 200 else 'FAIL'}: DB connectivity")

print("\n" + "=" * 60)
print("PRODUCTION SMOKE TEST COMPLETE")
print("=" * 60)
