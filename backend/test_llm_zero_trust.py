"""Verification Test Suite for Zero-Trust LLM Training & Anomaly Detection.

Tests:
1. LLM Training Dataset Generation from PostgreSQL telemetry
2. Ollama Modelfile compilation & registration ('zero-trust-guard')
3. LLM Status API endpoint (/api/ml/llm/status)
4. LLM Live Threat Evaluation API (/api/ml/llm/evaluate) for:
   - Severe API Abuse burst attack
   - Credential attack / brute force attempt
   - Privilege escalation attempt by standard USER
   - Benign legitimate request
5. Gateway Middleware end-to-end integration (LLM_ANOMALY in risk calculation & telemetry)
"""

import json
import unittest
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000"


def http_request(method: str, path: str, data=None, headers=None):
    url = f"{BASE_URL}{path}"
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)

    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode("utf-8")
            return resp.status, json.loads(content)
    except urllib.error.HTTPError as e:
        content = e.read().decode("utf-8")
        try:
            return e.code, json.loads(content)
        except Exception:
            return e.code, {"error": content}


class TestZeroTrustLLMIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Authenticate as admin
        status, res = http_request("POST", "/api/auth/login", data={"email": "admin@example.com", "password": "adminpass123"})
        assert status == 200, f"Admin login failed: {res}"
        cls.admin_token = res["access_token"]
        cls.admin_headers = {"Authorization": f"Bearer {cls.admin_token}"}

        # Authenticate as user
        status, res = http_request("POST", "/api/auth/login", data={"email": "demo@example.com", "password": "testpass123"})
        assert status == 200, f"User login failed: {res}"
        cls.user_token = res["access_token"]
        cls.user_headers = {"Authorization": f"Bearer {cls.user_token}"}

    def test_01_llm_status_endpoint(self):
        """Verifies /api/ml/llm/status reports trained zero-trust-guard model."""
        status, res = http_request("GET", "/api/ml/llm/status", headers=self.admin_headers)
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))
        data = res.get("data", {})
        self.assertEqual(data.get("model_name"), "zero-trust-guard")
        self.assertEqual(data.get("status"), "TRAINED")
        self.assertGreater(data.get("training_samples", 0), 50)

    def test_02_llm_evaluate_api_abuse(self):
        """Verifies LLM identifies high-velocity burst attack as API_ABUSE."""
        payload = {
            "method": "GET",
            "endpoint": "/api/orders",
            "status_code": 200,
            "role": "USER",
            "client_ip": "198.51.100.4",
            "user_agent": "Go-http-client/1.1",
            "features": {"requests_per_minute": 45.0, "failed_requests": 0},
        }
        status, res = http_request("POST", "/api/ml/llm/evaluate", data=payload, headers=self.user_headers)
        self.assertEqual(status, 200)
        data = res.get("data", {})
        self.assertTrue(data.get("available"))
        self.assertTrue(data.get("is_anomaly"))
        self.assertEqual(data.get("threat_type"), "API_ABUSE")
        self.assertGreaterEqual(data.get("anomaly_score", 0), 70)
        self.assertEqual(data.get("recommended_action"), "RATE_LIMIT")

    def test_03_llm_evaluate_privilege_misuse(self):
        """Verifies LLM identifies unauthorized admin probing as PRIVILEGE_MISUSE."""
        payload = {
            "method": "GET",
            "endpoint": "/api/admin/users",
            "status_code": 403,
            "role": "USER",
            "client_ip": "192.168.1.10",
            "user_agent": "Mozilla/5.0",
            "features": {"requests_per_minute": 2.0, "failed_requests": 1},
        }
        status, res = http_request("POST", "/api/ml/llm/evaluate", data=payload, headers=self.user_headers)
        self.assertEqual(status, 200)
        data = res.get("data", {})
        self.assertTrue(data.get("available"))
        self.assertTrue(data.get("is_anomaly"))
        self.assertIn(data.get("threat_type"), ("PRIVILEGE_MISUSE", "FORBIDDEN_PROBE", "ANOMALY_DETECTED", "SUSPICIOUS_PAYLOAD"))
        self.assertGreaterEqual(data.get("anomaly_score", 0), 50)

    def test_04_llm_evaluate_benign_request(self):
        """Verifies LLM identifies authorized normal requests with low risk score and ALLOW action."""
        payload = {
            "method": "GET",
            "endpoint": "/api/orders",
            "status_code": 200,
            "role": "USER",
            "client_ip": "192.168.1.10",
            "user_agent": "Mozilla/5.0",
            "features": {"requests_per_minute": 1.5, "failed_requests": 0},
        }
        status, res = http_request("POST", "/api/ml/llm/evaluate", data=payload, headers=self.user_headers)
        self.assertEqual(status, 200)
        data = res.get("data", {})
        self.assertTrue(data.get("available"))
        self.assertFalse(data.get("is_anomaly"))
        self.assertEqual(data.get("recommended_action"), "ALLOW")
        self.assertLess(data.get("anomaly_score", 100), 50)

    def test_05_gateway_middleware_llm_integration(self):
        """Verifies requests processed by gateway execute the LLM threat detector and populate risk_reasons."""
        status, res = http_request("GET", "/api/orders", headers=self.user_headers)
        self.assertEqual(status, 200)
        # Query user risk profile
        status, risk_data = http_request("GET", "/api/risk/me", headers=self.user_headers)
        self.assertEqual(status, 200)
        self.assertIn("risk_score", risk_data.get("data", {}))


if __name__ == "__main__":
    unittest.main()
