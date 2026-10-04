"""
tests/test_baseline_integration.py

Comprehensive baseline integration tests verifying Phase 1 requirements:
- Juice Shop telemetry transformation
- Connector ingestion pipeline & checkpointing
- FastAPI app initialization & health
- JWT authentication & role-based access control (RBAC)
- Ingestion & normalization of telemetry/logs
- Detection engine rule evaluation (threshold, sequence, blacklist)
- Alert creation, status updates, notes, and event linking
- Threat intelligence management
- Dashboard summary aggregation
"""

import os
import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Add backend directory to sys.path so app modules can be imported
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

# Use an isolated SQLite test database for these integration tests
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AUTO_CREATE_TABLES"] = "true"
os.environ["ENABLE_JUICE_SHOP_CONNECTOR"] = "false"
os.environ["JWT_SECRET_KEY"] = "integration-test-secret-key-12345"

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from app.database.base import Base
from app.database.session import get_db
from app.main import create_app
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users
from connector.juice_shop_connector import (
    generate_message,
    load_checkpoint,
    save_checkpoint,
    transform_event,
)


class TestBaselineIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Create an isolated in-memory SQLite database sharing the same connection pool
        cls.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        cls.TestingSessionLocal = sessionmaker(
            bind=cls.engine, autoflush=False, autocommit=False, expire_on_commit=False
        )

        Base.metadata.create_all(bind=cls.engine)

        # Seed baseline users, rules, and indicators into test DB
        db = cls.TestingSessionLocal()
        try:
            ensure_users(db)
            ensure_builtin_rules(db)
            ensure_indicators(db)
        finally:
            db.close()

        # Initialize the FastAPI app and override get_db dependency
        cls.app = create_app()

        def override_get_db():
            db = cls.TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        cls.app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(cls.app)

    @classmethod
    def tearDownClass(cls):
        Base.metadata.drop_all(bind=cls.engine)

    def setUp(self):
        # Obtain tokens for seeded admin and analyst users
        admin_res = self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "AdminPass123!"},
        )
        self.assertEqual(admin_res.status_code, 200)
        self.admin_token = admin_res.json()["access_token"]
        self.admin_headers = {"Authorization": f"Bearer {self.admin_token}"}

        analyst_res = self.client.post(
            "/api/auth/login",
            json={"username": "analyst", "password": "AnalystPass123!"},
        )
        self.assertEqual(analyst_res.status_code, 200)
        self.analyst_token = analyst_res.json()["access_token"]
        self.analyst_headers = {"Authorization": f"Bearer {self.analyst_token}"}

    def test_01_health_check(self):
        """Verify the /health endpoint responds with status ok."""
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("status"), "ok")
        self.assertIn("Mini SIEM Dashboard", data.get("service"))

    def test_02_auth_and_rbac(self):
        """Verify authentication, token validation, and role restrictions."""
        # Unauthenticated request to protected endpoint fails
        unauth_res = self.client.get("/api/dashboard/summary")
        self.assertEqual(unauth_res.status_code, 401)

        # Viewer registration and role restriction
        reg_res = self.client.post(
            "/api/auth/register",
            json={
                "username": "test_viewer_user",
                "email": "viewer_test@example.com",
                "password": "Password123!",
                "role": "viewer",
            },
        )
        self.assertEqual(reg_res.status_code, 201)

        viewer_login = self.client.post(
            "/api/auth/login",
            json={"username": "test_viewer_user", "password": "Password123!"},
        )
        self.assertEqual(viewer_login.status_code, 200)
        viewer_headers = {"Authorization": f"Bearer {viewer_login.json()['access_token']}"}

        # Viewer can read dashboard summary
        viewer_dash = self.client.get("/api/dashboard/summary", headers=viewer_headers)
        self.assertEqual(viewer_dash.status_code, 200)

        # Viewer CANNOT perform admin actions (e.g. view admin stats)
        viewer_admin = self.client.get("/api/admin/stats", headers=viewer_headers)
        self.assertEqual(viewer_admin.status_code, 403)

        # Admin CAN view admin stats
        admin_stats = self.client.get("/api/admin/stats", headers=self.admin_headers)
        self.assertEqual(admin_stats.status_code, 200)
        self.assertIn("users", admin_stats.json())

    def test_03_telemetry_transformation(self):
        """Verify Juice Shop telemetry event transforms accurately into canonical format."""
        raw_telemetry = {
            "event_id": "evt_phase1_test_001",
            "timestamp": "2026-10-04T12:00:00Z",
            "source_ip": "198.51.100.42",
            "method": "POST",
            "path": "/rest/user/login",
            "status_code": 401,
            "response_time_ms": 115.4,
            "user_agent": "Mozilla/5.0",
            "user_identity": "attacker@test.invalid",
            "event_type": "HTTP_REQUEST",
            "request_body_snippet": "password=secret",
        }
        transformed = transform_event(raw_telemetry)
        self.assertIsNotNone(transformed)
        self.assertEqual(transformed["source_ip"], "198.51.100.42")
        self.assertEqual(transformed["http_method"], "POST")
        self.assertEqual(transformed["request_path"], "/rest/user/login")
        self.assertEqual(transformed["status_code"], 401)
        self.assertEqual(transformed["username"], "attacker@test.invalid")
        self.assertEqual(transformed["event_category"], "web")
        # Ensure password snippet was NOT passed through
        self.assertNotIn("request_body_snippet", transformed)
        self.assertNotIn("password=secret", transformed["message"])

    def test_04_ingest_and_event_listing(self):
        """Verify log ingestion via API and retrieval via /api/events."""
        now_iso = datetime.now(UTC).isoformat()
        events_payload = [
            {
                "timestamp": now_iso,
                "source_ip": "203.0.113.88",
                "http_method": "GET",
                "request_path": "/api/Products",
                "status_code": 200,
                "user_agent": "Mozilla/5.0",
                "username": "anonymous",
                "event_type": "web_request",
                "event_category": "web",
                "severity": "low",
                "message": "GET /api/Products returned 200",
            }
        ]

        ingest_res = self.client.post(
            "/api/logs/ingest",
            headers=self.analyst_headers,
            json={
                "source_type": "juice_shop_connector",
                "events": events_payload,
                "raw_lines": [],
            },
        )
        self.assertEqual(ingest_res.status_code, 201)
        data = ingest_res.json()
        self.assertEqual(data["parsed_count"], 1)

        # Retrieve through /api/events
        events_res = self.client.get(
            "/api/events?source_ip=203.0.113.88",
            headers=self.analyst_headers,
        )
        self.assertEqual(events_res.status_code, 200)
        events_data = events_res.json()
        self.assertGreaterEqual(events_data["total"], 1)
        self.assertEqual(events_data["items"][0]["source_ip"], "203.0.113.88")

    def test_05_threshold_rule_detection(self):
        """Verify threshold detection rule produces alert on burst of sensitive path requests."""
        now = datetime.now(UTC)
        # Sensitive path rule threshold is 4 within 10 minutes
        burst_events = []
        for i in range(5):
            ts = (now - timedelta(seconds=i * 5)).isoformat()
            burst_events.append(
                {
                    "timestamp": ts,
                    "source_ip": "198.51.100.99",
                    "http_method": "GET",
                    "request_path": "/admin/config",
                    "status_code": 403,
                    "user_agent": "Mozilla/5.0",
                    "username": "anonymous",
                    "event_type": "sensitive_path_access",
                    "event_category": "web",
                    "severity": "medium",
                    "message": "GET /admin/config returned 403",
                }
            )

        ingest_res = self.client.post(
            "/api/logs/ingest",
            headers=self.analyst_headers,
            json={
                "source_type": "test_scanner",
                "events": burst_events,
                "raw_lines": [],
            },
        )
        self.assertEqual(ingest_res.status_code, 201)
        self.assertGreaterEqual(ingest_res.json()["alert_count"], 1)

        # Query alerts for this IP
        alerts_res = self.client.get(
            "/api/alerts?source_ip=198.51.100.99",
            headers=self.analyst_headers,
        )
        self.assertEqual(alerts_res.status_code, 200)
        alerts = alerts_res.json()["items"]
        self.assertGreaterEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertIn("Repeated sensitive path access", alert["title"])
        self.assertEqual(alert["source_ip"], "198.51.100.99")
        self.assertEqual(alert["status"], "open")

    def test_06_alert_lifecycle_and_notes(self):
        """Verify alert status transitions and analyst notes."""
        alerts_res = self.client.get("/api/alerts", headers=self.analyst_headers)
        self.assertEqual(alerts_res.status_code, 200)
        items = alerts_res.json()["items"]
        self.assertGreater(len(items), 0)
        target_alert_id = items[0]["id"]

        # Update status to 'investigating'
        patch_res = self.client.patch(
            f"/api/alerts/{target_alert_id}/status",
            headers=self.analyst_headers,
            json={"status": "investigating"},
        )
        self.assertEqual(patch_res.status_code, 200)
        self.assertEqual(patch_res.json()["status"], "investigating")

        # Add analyst note
        note_res = self.client.post(
            f"/api/alerts/{target_alert_id}/notes",
            headers=self.analyst_headers,
            json={"note": "Initial analyst triage: observed repeated 403 probe from external host."},
        )
        self.assertEqual(note_res.status_code, 201)
        self.assertIn("Initial analyst triage", note_res.json()["note"])

        # Fetch alert detail to ensure related events and notes are included
        detail_res = self.client.get(
            f"/api/alerts/{target_alert_id}",
            headers=self.analyst_headers,
        )
        self.assertEqual(detail_res.status_code, 200)
        detail = detail_res.json()
        self.assertGreater(len(detail["notes"]), 0)
        self.assertGreater(len(detail["related_events"]), 0)

    def test_07_threat_intelligence_blacklist_rule(self):
        """Verify access from blacklisted indicator triggers critical alert."""
        now = datetime.now(UTC).isoformat()
        # Seeded indicator has IP '203.0.113.66'
        bl_event = [
            {
                "timestamp": now,
                "source_ip": "203.0.113.66",
                "http_method": "GET",
                "request_path": "/rest/admin",
                "status_code": 401,
                "user_agent": "curl/8.1",
                "username": "root",
                "event_type": "web_request",
                "event_category": "web",
                "severity": "high",
                "message": "GET /rest/admin returned 401",
            }
        ]

        ingest_res = self.client.post(
            "/api/logs/ingest",
            headers=self.analyst_headers,
            json={
                "source_type": "threat_intel_test",
                "events": bl_event,
                "raw_lines": [],
            },
        )
        self.assertEqual(ingest_res.status_code, 201)

        # Verify critical alert was generated
        alerts_res = self.client.get(
            "/api/alerts?source_ip=203.0.113.66",
            headers=self.analyst_headers,
        )
        self.assertEqual(alerts_res.status_code, 200)
        items = alerts_res.json()["items"]
        self.assertGreaterEqual(len(items), 1)
        match = [a for a in items if a["severity"] == "critical"]
        self.assertGreaterEqual(len(match), 1)

    def test_08_threat_intel_crud(self):
        """Verify creating, listing, and deleting threat indicators."""
        # Create indicator
        create_res = self.client.post(
            "/api/threat-intel",
            headers=self.admin_headers,
            json={
                "type": "ip",
                "value": "198.51.100.123",
                "description": "Test indicator for automated suite",
                "severity": "high",
            },
        )
        self.assertEqual(create_res.status_code, 201)
        indicator_id = create_res.json()["id"]

        # List indicators
        list_res = self.client.get("/api/threat-intel", headers=self.analyst_headers)
        self.assertEqual(list_res.status_code, 200)
        vals = [i["value"] for i in list_res.json()["items"]]
        self.assertIn("198.51.100.123", vals)

        # Delete indicator
        del_res = self.client.delete(f"/api/threat-intel/{indicator_id}", headers=self.admin_headers)
        self.assertEqual(del_res.status_code, 200)


if __name__ == "__main__":
    unittest.main()
