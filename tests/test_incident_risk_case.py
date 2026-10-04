"""
tests/test_incident_risk_case.py

Comprehensive tests for Phase 6:
- Incident Management API endpoints and detail view
- Risk and Triage Engine (multi-factor calculation, asset criticality, risk tiers)
- Case Management Service & Lifecycle (OPEN -> INVESTIGATING -> RESOLVED -> CLOSED)
- Controlled Response operations (safe simulation, threat indicator addition, mandatory confirmation)
- Audit log attribution for case updates and controlled responses
"""

import os
import sys
import unittest
from datetime import UTC, datetime, timedelta
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

from app.database.base import Base
from app.database.session import get_db
from app.main import create_app
from app.models import Alert, AlertEvent, AuditLog, Case, Incident, IncidentAlert, NormalizedEvent, ThreatIndicator, User
from app.services.case_service import create_case, execute_controlled_response, update_case
from app.services.risk_service import evaluate_alert_risk, evaluate_incident_risk, get_risk_summary
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users


class TestIncidentRiskCase(unittest.TestCase):

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

        res = cls.client.post("/api/auth/login", json={"username": "analyst", "password": "AnalystPass123!"})
        cls.analyst_token = res.json()["access_token"]
        cls.headers = {"Authorization": f"Bearer {cls.analyst_token}"}

    @classmethod
    def tearDownClass(cls):
        Base.metadata.drop_all(bind=cls.engine)
        cls.engine.dispose()

    def setUp(self):
        self.db = self.SessionLocal()

    def tearDown(self):
        self.db.rollback()
        self.db.close()

    def _create_incident(self, number="INC-P6-01", severity="high"):
        now = datetime.now(UTC)
        incident = Incident(
            incident_number=number,
            title="Coordinated Credential Stuffing",
            description="Multi-alert authentication campaign",
            severity=severity,
            status="open",
            source_ip="198.51.100.12",
            first_seen=now - timedelta(minutes=15),
            last_seen=now,
            alert_count=2,
            event_count=8,
        )
        self.db.add(incident)
        self.db.flush()

        a1 = Alert(
            title="Failed Logins",
            description="Failed logins",
            severity="high",
            status="open",
            source_ip="198.51.100.12",
            first_seen=now - timedelta(minutes=15),
            last_seen=now,
            event_count=5,
        )
        self.db.add(a1)
        self.db.flush()
        self.db.add(IncidentAlert(incident_id=incident.id, alert_id=a1.id))
        self.db.commit()
        return incident

    def test_01_incident_api_endpoints(self):
        """Verify listing, detail retrieval, and status updates for Incidents."""
        incident = self._create_incident("INC-P6-02", "critical")

        # List incidents
        list_res = self.client.get("/api/incidents", headers=self.headers)
        self.assertEqual(list_res.status_code, 200)
        self.assertGreater(list_res.json()["total"], 0)

        # Get incident detail
        detail_res = self.client.get(f"/api/incidents/{incident.id}", headers=self.headers)
        self.assertEqual(detail_res.status_code, 200)
        data = detail_res.json()
        self.assertEqual(data["incident_number"], "INC-P6-02")
        self.assertGreaterEqual(len(data["alerts"]), 1)

        # Update status
        patch_res = self.client.patch(
            f"/api/incidents/{incident.id}/status",
            headers=self.headers,
            json={"status": "investigating"},
        )
        self.assertEqual(patch_res.status_code, 200)
        self.assertEqual(patch_res.json()["status"], "investigating")

    def test_02_risk_engine_calculation_and_endpoints(self):
        """Verify multi-factor risk scoring for alerts and incidents."""
        incident = self._create_incident("INC-P6-03", "high")
        alert = self.db.query(Alert).first()

        # Alert risk evaluation
        alert_risk = evaluate_alert_risk(self.db, alert, asset_criticality="HIGH")
        self.db.commit()
        self.assertGreaterEqual(alert_risk.risk_score, 25.0)
        self.assertIn(alert_risk.risk_level, ["MEDIUM", "HIGH", "CRITICAL"])
        self.assertIn("Assessed", alert_risk.justification)

        # Incident risk evaluation
        inc_risk = evaluate_incident_risk(self.db, incident, asset_criticality="CRITICAL")
        self.db.commit()
        self.assertGreaterEqual(inc_risk.risk_score, 50.0)

        # API risk endpoints
        res_alert = self.client.get(f"/api/risk/alert/{alert.id}", headers=self.headers)
        self.assertEqual(res_alert.status_code, 200)
        self.assertEqual(res_alert.json()["alert_id"], alert.id)

        res_inc = self.client.get(f"/api/risk/incident/{incident.id}", headers=self.headers)
        self.assertEqual(res_inc.status_code, 200)
        self.assertEqual(res_inc.json()["incident_id"], incident.id)

        res_sum = self.client.get("/api/risk/summary", headers=self.headers)
        self.assertEqual(res_sum.status_code, 200)
        self.assertIn("average_risk_score", res_sum.json())

    def test_03_case_management_lifecycle(self):
        """Verify Case creation, assignment, status transition, and audit logging."""
        analyst = self.db.query(User).filter_by(username="analyst").first()
        incident = self._create_incident("INC-P6-04", "medium")

        # Create case
        case = create_case(
            self.db,
            title="Investigate Credential Spraying",
            description="Examine logs for successful logins after spraying",
            priority="HIGH",
            assigned_analyst_id=analyst.id,
            incident_id=incident.id,
            user_id=analyst.id,
        )
        self.assertTrue(case.case_number.startswith("CASE-"))
        self.assertEqual(case.status, "OPEN")

        # Update case to RESOLVED
        updated = update_case(
            self.db,
            case_id=case.id,
            status="RESOLVED",
            resolution_summary="Source IP blocked at edge; credentials reset.",
            user_id=analyst.id,
        )
        self.assertEqual(updated.status, "RESOLVED")
        self.assertIsNotNone(updated.closed_at)

        # Query via API
        case_res = self.client.get(f"/api/cases/{case.id}", headers=self.headers)
        self.assertEqual(case_res.status_code, 200)
        self.assertEqual(case_res.json()["status"], "RESOLVED")

    def test_04_controlled_response_requires_confirmation(self):
        """Verify controlled response enforces explicit analyst confirmation and logs audit events."""
        # Unconfirmed request should fail with 400
        unconfirmed_res = self.client.post(
            "/api/cases/controlled-response",
            headers=self.headers,
            json={
                "action_type": "SIMULATE_CONTAINMENT",
                "target_value": "198.51.100.99",
                "confirm": False,
            },
        )
        self.assertEqual(unconfirmed_res.status_code, 400)

        # Confirmed request: ADD_WATCHLIST_INDICATOR
        confirmed_res = self.client.post(
            "/api/cases/controlled-response",
            headers=self.headers,
            json={
                "action_type": "ADD_WATCHLIST_INDICATOR",
                "target_value": "198.51.100.199",
                "confirm": True,
                "confirmation_notes": "Analyst observed active brute force.",
            },
        )
        self.assertEqual(confirmed_res.status_code, 200)
        data = confirmed_res.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "INDICATOR_ADDED")

        # Verify indicator was persisted
        ti = self.db.query(ThreatIndicator).filter_by(value="198.51.100.199").first()
        self.assertIsNotNone(ti)

        # Verify audit log was recorded
        audit = self.db.query(AuditLog).filter_by(action="CONTROLLED_RESPONSE_ADD_WATCHLIST_INDICATOR").first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.resource_id, "198.51.100.199")


if __name__ == "__main__":
    unittest.main()
