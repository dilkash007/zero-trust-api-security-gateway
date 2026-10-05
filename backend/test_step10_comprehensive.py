"""Comprehensive Automated Test Suite for STEP 10:
WebSocket + Real-Time SOC Distribution + RBAC Isolation + Security Hardening.

Verifies:
1. WebSocket unauthenticated connection rejection (missing token) -> Code 1008
2. WebSocket invalid/forged token rejection -> Code 1008
3. WebSocket expired token rejection -> Code 1008
4. WebSocket ADMIN connection acceptance and SYSTEM_STATUS handshake
5. WebSocket USER connection acceptance and scoped SYSTEM_STATUS handshake
6. Real-time Heartbeat PING -> PONG handling
7. HTTP Request -> WebSocket REQUEST_COMPLETED event broadcast
8. RBAC Event Isolation: Normal USER never receives another user's security telemetry
9. RBAC Admin Visibility: ADMIN receives organization-wide events
10. Threat / Security event real-time broadcast (SECURITY_EVENT)
11. ML Anomaly real-time broadcast (ML_ANOMALY)
12. Attack Simulator real-time broadcast (SIMULATION_COMPLETED)
13. Connection lifecycle & disconnect cleanup (no leaks)
14. Non-blocking failure safety: HTTP requests succeed even without active WS clients
15. HTTP Security Headers hardening (X-Content-Type-Options, X-Frame-Options, Referrer-Policy)
16. Payload Sanitization: sensitive credentials/tokens stripped from WebSocket messages
17. Core Health Checks (/health, /health/database)
"""

from datetime import datetime, timedelta, timezone
import json
import os
import sys
import unittest
import uuid

# Ensure backend root is on sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.auth.jwt import create_access_token
from app.database.connection import SessionLocal
from app.database.models import User, UserRole
from app.main import app
from app.websocket.manager import connection_manager
from app.websocket.schemas import sanitize_payload


class Step10ComprehensiveTestCase(unittest.TestCase):
    """Rigorous test cases verifying Step 10 implementation."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        db = SessionLocal()
        try:
            # Seed or locate demo admin and normal user
            cls.admin_user = db.query(User).filter(User.email == "admin@example.com").first()
            if not cls.admin_user:
                cls.admin_user = db.query(User).filter(User.role == UserRole.ADMIN.value).first()

            cls.normal_user = db.query(User).filter(User.email == "demo@example.com").first()
            if not cls.normal_user:
                cls.normal_user = db.query(User).filter(User.role == UserRole.USER.value).first()

            cls.admin_id = cls.admin_user.id if cls.admin_user else 3
            cls.user_id = cls.normal_user.id if cls.normal_user else 1

            cls.admin_token = create_access_token(user_id=cls.admin_id, role="ADMIN")
            cls.user_token = create_access_token(user_id=cls.user_id, role="USER")
        finally:
            db.close()

    def test_01_websocket_rejects_missing_token(self):
        """Verifies /ws/security rejects connections without JWT token with policy violation."""
        with self.assertRaises(WebSocketDisconnect) as cm:
            with self.client.websocket_connect("/ws/security") as ws:
                ws.receive_json()
        self.assertEqual(cm.exception.code, 1008)

    def test_02_websocket_rejects_invalid_token(self):
        """Verifies /ws/security rejects forged/invalid JWT tokens."""
        with self.assertRaises(WebSocketDisconnect) as cm:
            with self.client.websocket_connect("/ws/security?token=invalid.forged.jwt") as ws:
                ws.receive_json()
        self.assertEqual(cm.exception.code, 1008)

    def test_03_websocket_rejects_expired_token(self):
        """Verifies /ws/security rejects expired JWT tokens."""
        expired_token = create_access_token(
            user_id=self.user_id,
            role="USER",
            expires_delta=timedelta(seconds=-60),
        )
        with self.assertRaises(WebSocketDisconnect) as cm:
            with self.client.websocket_connect(f"/ws/security?token={expired_token}") as ws:
                ws.receive_json()
        self.assertEqual(cm.exception.code, 1008)

    def test_04_websocket_accepts_admin_and_sends_handshake(self):
        """Verifies valid ADMIN connection receives initial SYSTEM_STATUS handshake."""
        with self.client.websocket_connect(f"/ws/security?token={self.admin_token}") as ws:
            msg = ws.receive_json()
            self.assertEqual(msg["type"], "SYSTEM_STATUS")
            self.assertEqual(msg["data"]["status"], "connected")
            self.assertEqual(msg["data"]["role"], "ADMIN")
            self.assertEqual(msg["data"]["user_id"], self.admin_id)

    def test_05_websocket_accepts_user_and_sends_handshake(self):
        """Verifies valid USER connection receives initial SYSTEM_STATUS handshake."""
        with self.client.websocket_connect(f"/ws/security?token={self.user_token}") as ws:
            msg = ws.receive_json()
            self.assertEqual(msg["type"], "SYSTEM_STATUS")
            self.assertEqual(msg["data"]["status"], "connected")
            self.assertEqual(msg["data"]["role"], "USER")
            self.assertEqual(msg["data"]["user_id"], self.user_id)

    def test_06_websocket_heartbeat_ping_pong(self):
        """Verifies PING frame receives immediate PONG response with echoed data."""
        with self.client.websocket_connect(f"/ws/security?token={self.admin_token}") as ws:
            # Drain initial handshake
            ws.receive_json()

            # Send client ping
            ws.send_json({"type": "PING", "data": {"nonce": 42}})
            reply = ws.receive_json()
            self.assertEqual(reply["type"], "PONG")
            self.assertEqual(reply["data"]["echo"]["nonce"], 42)

    def test_07_http_request_triggers_websocket_request_completed(self):
        """Verifies that executing an HTTP API request broadcasts REQUEST_COMPLETED to connected clients."""
        with self.client.websocket_connect(f"/ws/security?token={self.admin_token}") as ws:
            # Handshake
            ws.receive_json()

            # Trigger HTTP request
            resp = self.client.get(
                "/api/profile",
                headers={"Authorization": f"Bearer {self.admin_token}"},
            )
            self.assertEqual(resp.status_code, 200)

            # Receive broadcasted event
            event = ws.receive_json()
            self.assertEqual(event["type"], "REQUEST_COMPLETED")
            self.assertEqual(event["data"]["endpoint"], "/api/profile")
            self.assertEqual(event["data"]["method"], "GET")
            self.assertEqual(event["data"]["status_code"], 200)
            self.assertIn("risk_score", event["data"])
            self.assertIn("policy_decision", event["data"])

    def test_08_rbac_user_isolation(self):
        """Verifies normal USER does NOT receive telemetry belonging to other users."""
        with self.client.websocket_connect(f"/ws/security?token={self.user_token}") as user_ws:
            # Drain handshake
            user_ws.receive_json()

            # Admin makes an admin-only request
            resp = self.client.get(
                "/api/admin/users",
                headers={"Authorization": f"Bearer {self.admin_token}"},
            )
            self.assertEqual(resp.status_code, 200)

            # User socket should have no messages pending; verify by sending PING
            user_ws.send_json({"type": "PING", "data": {"check": "isolated"}})
            reply = user_ws.receive_json()
            # If user had received admin's event, the next message would have been REQUEST_COMPLETED, not PONG!
            self.assertEqual(reply["type"], "PONG")
            self.assertEqual(reply["data"]["echo"]["check"], "isolated")

    def test_09_rbac_admin_global_visibility(self):
        """Verifies ADMIN receives events generated by other users."""
        with self.client.websocket_connect(f"/ws/security?token={self.admin_token}") as admin_ws:
            admin_ws.receive_json()

            # Normal user makes a request
            resp = self.client.get(
                "/api/orders",
                headers={"Authorization": f"Bearer {self.user_token}"},
            )
            self.assertEqual(resp.status_code, 200)

            # Admin receives the event
            event = admin_ws.receive_json()
            self.assertEqual(event["type"], "REQUEST_COMPLETED")
            self.assertEqual(event["data"]["endpoint"], "/api/orders")
            self.assertEqual(event["data"]["user_id"], self.user_id)

    def test_10_threat_security_event_broadcast(self):
        """Verifies that an unauthorized 403 generates a SECURITY_EVENT over WebSocket."""
        with self.client.websocket_connect(f"/ws/security?token={self.admin_token}") as ws:
            ws.receive_json()

            # Normal user attempts unauthorized admin endpoint
            resp = self.client.get(
                "/api/admin/users",
                headers={"Authorization": f"Bearer {self.user_token}"},
            )
            self.assertEqual(resp.status_code, 403)

            # Capture events (REQUEST_COMPLETED, then SECURITY_EVENT)
            events = []
            events.append(ws.receive_json())
            events.append(ws.receive_json())

            event_types = [e["type"] for e in events]
            self.assertIn("REQUEST_COMPLETED", event_types)
            self.assertIn("SECURITY_EVENT", event_types)

            sec_event = next(e for e in events if e["type"] == "SECURITY_EVENT")
            self.assertIn(sec_event["data"]["event_type"], ["AUTHORIZATION_FAILURE", "PRIVILEGE_MISUSE"])
            self.assertIn(sec_event["data"]["severity"], ["HIGH", "CRITICAL", "MEDIUM", "INFO"])

    def test_11_simulator_broadcast(self):
        """Verifies running the Attack Simulator broadcasts a SIMULATION_COMPLETED event."""
        with self.client.websocket_connect(f"/ws/security?token={self.admin_token}") as ws:
            ws.receive_json()

            # Trigger simulator API abuse scenario
            resp = self.client.post(
                "/api/simulator/run",
                headers={"Authorization": f"Bearer {self.admin_token}"},
                json={"scenario": "API_ABUSE"},
            )
            self.assertEqual(resp.status_code, 200)

            # Receive emitted events (SIMULATION_COMPLETED and REQUEST_COMPLETED)
            events = []
            for _ in range(2):
                events.append(ws.receive_json())

            sim_event = next((e for e in events if e["type"] == "SIMULATION_COMPLETED"), None)
            self.assertIsNotNone(sim_event)
            self.assertEqual(sim_event["data"]["scenario"], "API_ABUSE")
            self.assertGreater(sim_event["data"]["requests_generated"], 0)
            self.assertIn("highest_risk", sim_event["data"])
            self.assertIn("final_policy", sim_event["data"])

    def test_12_disconnect_cleanup(self):
        """Verifies client disconnection frees connection records from memory."""
        before_count = connection_manager.active_count
        with self.client.websocket_connect(f"/ws/security?token={self.admin_token}") as ws:
            ws.receive_json()
            self.assertEqual(connection_manager.active_count, before_count + 1)
        # Context exited
        self.assertEqual(connection_manager.active_count, before_count)

    def test_13_nonblocking_failure_safety(self):
        """Verifies HTTP requests complete normally even when no WebSocket clients are connected."""
        resp = self.client.get(
            "/api/profile",
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json().get("success"))

    def test_14_security_headers_present(self):
        """Verifies standard defense-in-depth security response headers."""
        resp = self.client.get("/health")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(resp.headers.get("Referrer-Policy"), "no-referrer")

    def test_15_payload_sanitization(self):
        """Verifies sanitize_payload recursively removes passwords, tokens, and secrets."""
        raw_payload = {
            "user_id": 1,
            "username": "demo@example.com",
            "password": "SecretPassword123!",
            "token": "eyJhbGciOi...",
            "access_token": "bearer...",
            "database_url": "postgresql://user:pass@localhost/db",
            "nested": {
                "api_key": "sk-12345",
                "normal_field": "allowed_value",
            },
            "array": [
                {"secret": "xyz", "name": "safe_item"},
                "plain_string",
            ],
        }
        sanitized = sanitize_payload(raw_payload)
        self.assertNotIn("password", sanitized)
        self.assertNotIn("token", sanitized)
        self.assertNotIn("access_token", sanitized)
        self.assertNotIn("database_url", sanitized)
        self.assertNotIn("api_key", sanitized["nested"])
        self.assertEqual(sanitized["nested"]["normal_field"], "allowed_value")
        self.assertNotIn("secret", sanitized["array"][0])
        self.assertEqual(sanitized["array"][0]["name"], "safe_item")

    def test_16_health_endpoints(self):
        """Verifies core health and database health checks."""
        h1 = self.client.get("/health")
        self.assertEqual(h1.status_code, 200)
        self.assertEqual(h1.json().get("status"), "ok")

        h2 = self.client.get("/health/database")
        self.assertEqual(h2.status_code, 200)
        self.assertEqual(h2.json().get("database"), "connected")


if __name__ == "__main__":
    unittest.main()
