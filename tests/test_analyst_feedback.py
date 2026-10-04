"""
tests/test_analyst_feedback.py

Comprehensive tests for Phase 9 Analyst Feedback Loop & Controlled Rule Tuning:
- Ground truth analyst classification recording (TRUE_POSITIVE, FALSE_POSITIVE, BENIGN, SUSPICIOUS)
- Automatic alert and incident lifecycle state transitions
- Controlled rule tuning proposal submission
- Safe rule tuning application safeguard (confirm=False rejection, confirm=True execution)
- Feedback summary metrics, noisiest rule rankings, and AI-analyst agreement
- REST API endpoints (/api/feedback, /alert, /incident, /rules/tuning-proposals, /rules/apply-tuning, /summary)
"""

from __future__ import annotations

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
from app.models import (
    AIAnalysis,
    Alert,
    AlertEvent,
    AnalystFeedback,
    AuditLog,
    DetectionRule,
    Incident,
    IncidentAlert,
    NormalizedEvent,
    User,
)
from app.services.feedback_service import (
    apply_rule_tuning_proposal,
    get_feedback_summary,
    list_tuning_proposals,
    record_alert_feedback,
    record_incident_feedback,
)
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users


class TestAnalystFeedbackLoop(unittest.TestCase):

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

        # Analyst token
        res = cls.client.post("/api/auth/login", json={"username": "analyst", "password": "AnalystPass123!"})
        cls.analyst_token = res.json()["access_token"]
        cls.headers = {"Authorization": f"Bearer {cls.analyst_token}"}

        # Admin token
        res_adm = cls.client.post("/api/auth/login", json={"username": "admin", "password": "AdminPass123!"})
        cls.admin_token = res_adm.json()["access_token"]
        cls.admin_headers = {"Authorization": f"Bearer {cls.admin_token}"}

    @classmethod
    def tearDownClass(cls):
        Base.metadata.drop_all(bind=cls.engine)
        cls.engine.dispose()

    def setUp(self):
        self.db = self.SessionLocal()

    def tearDown(self):
        self.db.rollback()
        self.db.close()

    def _create_test_alert(self, title="Possible directory brute force", rule_name=None, status="open") -> Alert:
        now = datetime.now(UTC)
        rule = None
        if rule_name:
            rule = self.db.query(DetectionRule).filter(DetectionRule.name.ilike(f"%{rule_name}%")).first()
        else:
            rule = self.db.query(DetectionRule).first()

        alert = Alert(
            rule_id=rule.id if rule else None,
            title=title,
            description="Testing analyst feedback loop",
            severity="medium",
            status=status,
            source_ip="198.51.100.12",
            first_seen=now,
            last_seen=now,
            event_count=5,
        )
        self.db.add(alert)
        self.db.commit()
        return alert

    def test_01_alert_feedback_submission_and_status_transition(self):
        """Verify analyst feedback transitions alert state and logs audit record."""
        alert = self._create_test_alert(status="open")
        analyst = self.db.query(User).filter(User.username == "analyst").first()

        # Submit FALSE_POSITIVE feedback
        fb = record_alert_feedback(
            self.db,
            alert_id=alert.id,
            analyst_id=analyst.id,
            classification="FALSE_POSITIVE",
            notes="Routine internal healthcheck probe falsely detected as brute force.",
        )

        self.assertIsNotNone(fb)
        self.assertEqual(fb.classification, "FALSE_POSITIVE")
        self.assertEqual(alert.status, "false_positive")

        # Verify AuditLog created
        log = self.db.query(AuditLog).filter(
            AuditLog.action == "ANALYST_FEEDBACK_SUBMITTED",
            AuditLog.resource_id == str(alert.id),
        ).first()
        self.assertIsNotNone(log)
        self.assertEqual(log.details_json["classification"], "FALSE_POSITIVE")

    def test_02_incident_feedback_cascading(self):
        """Verify incident feedback cascades false-positive status to all correlated alerts."""
        now = datetime.now(UTC)
        incident = Incident(
            incident_number="INC-FB-01",
            title="Suspected Port Scanning Campaign",
            description="Testing incident feedback cascading",
            severity="medium",
            status="open",
            source_ip="203.0.113.44",
            first_seen=now,
            last_seen=now,
            alert_count=2,
            event_count=6,
        )
        self.db.add(incident)
        self.db.flush()

        a1 = self._create_test_alert(title="Alert 1 in incident")
        a2 = self._create_test_alert(title="Alert 2 in incident")

        self.db.add_all([
            IncidentAlert(incident_id=incident.id, alert_id=a1.id),
            IncidentAlert(incident_id=incident.id, alert_id=a2.id),
        ])
        self.db.commit()

        analyst = self.db.query(User).filter(User.username == "analyst").first()
        record_incident_feedback(
            self.db,
            incident_id=incident.id,
            analyst_id=analyst.id,
            classification="FALSE_POSITIVE",
            notes="Authorized scheduled network discovery scan by IT department.",
        )

        self.assertEqual(incident.status, "false_positive")
        self.assertEqual(a1.status, "false_positive")
        self.assertEqual(a2.status, "false_positive")

    def test_03_rule_tuning_proposal_and_controlled_execution(self):
        """Verify rule tuning proposal workflow and safe execution safeguard."""
        rule = self.db.query(DetectionRule).first()
        initial_threshold = rule.threshold
        alert = self._create_test_alert(rule_name=rule.name)
        analyst = self.db.query(User).filter(User.username == "analyst").first()

        # Propose tuning modification
        tuning_payload = {
            "rule_id": rule.id,
            "tuning_type": "INCREASE_THRESHOLD",
            "parameters": {"new_threshold": initial_threshold + 5},
            "rationale": "High volume of low-threat scanner noise requires threshold increase",
        }
        fb = record_alert_feedback(
            self.db,
            alert_id=alert.id,
            analyst_id=analyst.id,
            classification="FALSE_POSITIVE",
            rule_adjustment_suggested=True,
            suggested_rule_changes_json=tuning_payload,
        )

        # Verify proposal listed
        proposals = list_tuning_proposals(self.db)
        matching = [p for p in proposals if p["feedback_id"] == fb.id]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["status"], "PENDING_REVIEW")

        # Safeguard: Execution must fail without confirm=True
        with self.assertRaises(ValueError):
            apply_rule_tuning_proposal(self.db, feedback_id=fb.id, user_id=analyst.id, confirm=False)

        # Execution with confirm=True
        result = apply_rule_tuning_proposal(self.db, feedback_id=fb.id, user_id=analyst.id, confirm=True)
        self.assertTrue(result["success"])
        self.assertEqual(rule.threshold, initial_threshold + 5)

        # AuditLog recorded
        tuning_log = self.db.query(AuditLog).filter(
            AuditLog.action == "RULE_TUNING_APPLIED",
            AuditLog.resource_id == str(rule.id),
        ).first()
        self.assertIsNotNone(tuning_log)

    def test_04_feedback_summary_metrics(self):
        """Verify get_feedback_summary aggregates ground truth stats, FP rate, and noisy rules."""
        summary = get_feedback_summary(self.db)
        self.assertIn("total_feedbacks", summary)
        self.assertIn("classification_breakdown", summary)
        self.assertIn("false_positive_rate", summary)
        self.assertIn("noisiest_rules", summary)
        self.assertGreaterEqual(summary["total_feedbacks"], 1)

    def test_05_feedback_rest_api_endpoints(self):
        """Verify REST API endpoints for feedback submission, list, proposal inspection, and tuning execution."""
        alert = self._create_test_alert()

        # 1. POST /api/feedback/alert/{id}
        fb_res = self.client.post(
            f"/api/feedback/alert/{alert.id}",
            json={
                "classification": "FALSE_POSITIVE",
                "notes": "Benign pentest traffic",
                "rule_adjustment_suggested": True,
                "suggested_rule_changes_json": {
                    "rule_id": alert.rule_id,
                    "tuning_type": "INCREASE_THRESHOLD",
                    "parameters": {"new_threshold": 10},
                    "rationale": "Noise reduction",
                },
            },
            headers=self.headers,
        )
        self.assertEqual(fb_res.status_code, 201)
        fb_data = fb_res.json()
        feedback_id = fb_data["id"]

        # 2. GET /api/feedback
        list_res = self.client.get("/api/feedback", headers=self.headers)
        self.assertEqual(list_res.status_code, 200)
        self.assertGreater(list_res.json()["total"], 0)

        # 3. GET /api/feedback/rules/tuning-proposals
        proposals_res = self.client.get("/api/feedback/rules/tuning-proposals", headers=self.headers)
        self.assertEqual(proposals_res.status_code, 200)
        self.assertIsInstance(proposals_res.json(), list)

        # 4. POST /api/feedback/rules/apply-tuning (Safeguard rejection on unconfirmed)
        apply_unconf = self.client.post(
            "/api/feedback/rules/apply-tuning",
            json={"feedback_id": feedback_id, "confirm": False},
            headers=self.admin_headers,
        )
        self.assertEqual(apply_unconf.status_code, 400)

        # 5. POST /api/feedback/rules/apply-tuning (Success with confirm=True)
        apply_conf = self.client.post(
            "/api/feedback/rules/apply-tuning",
            json={"feedback_id": feedback_id, "confirm": True},
            headers=self.admin_headers,
        )
        self.assertEqual(apply_conf.status_code, 200)
        self.assertTrue(apply_conf.json()["success"])

        # 6. GET /api/feedback/summary
        summary_res = self.client.get("/api/feedback/summary", headers=self.headers)
        self.assertEqual(summary_res.status_code, 200)
        self.assertIn("false_positive_rate", summary_res.json())


if __name__ == "__main__":
    unittest.main()
