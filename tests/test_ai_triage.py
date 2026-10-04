"""
tests/test_ai_triage.py

Comprehensive tests for Phase 8 Evidence-Grounded SLM/LLM Assistance & Claims Audit:
- Evidence-grounded alert triage generation
- Correlated incident triage generation
- Claims Audit Engine: claim extraction, evidence linkage, grounding rate computation, hallucination detection
- Uncertainty notes transparency for sparse or unverified data
- Analyst agreement feedback recording and immutable audit logging
- REST API endpoints (/api/ai/triage/alert, /incident, /analyses, /feedback, /summary)
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
    AuditLog,
    DetectionQuality,
    DetectionRule,
    Incident,
    IncidentAlert,
    NormalizedEvent,
    RiskAssessment,
    ThreatIndicator,
    User,
)
from app.services.ai_triage_service import (
    get_ai_triage_summary,
    record_analyst_agreement,
    triage_alert,
    triage_incident,
)
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users


class TestAITriageAndClaimsAudit(unittest.TestCase):

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

    def _create_alert_with_evidence(
        self,
        title="SQL injection attempt detected",
        severity="critical",
        source_ip="198.51.100.99",
        count=3,
    ) -> Alert:
        now = datetime.now(UTC)
        rule = self.db.query(DetectionRule).filter(DetectionRule.name.ilike(f"%{title[:10]}%")).first()
        alert = Alert(
            rule_id=rule.id if rule else None,
            title=title,
            description="Testing AI triage and claims audit",
            severity=severity,
            status="open",
            source_ip=source_ip,
            affected_user="victim_db_user",
            first_seen=now - timedelta(minutes=2),
            last_seen=now,
            event_count=count,
        )
        self.db.add(alert)
        self.db.flush()

        for i in range(count):
            ev = NormalizedEvent(
                timestamp=now - timedelta(seconds=i * 10),
                source_ip=source_ip,
                username="victim_db_user",
                event_type="web_attack",
                event_category="web",
                severity=severity,
                message=f"Attack probe {i}: SELECT * FROM users WHERE '1'='1'",
                request_path=f"/rest/products/search?q=' OR 1=1--",
                http_method="GET",
                status_code=500 if i == 0 else 200,
            )
            self.db.add(ev)
            self.db.flush()
            self.db.add(AlertEvent(alert_id=alert.id, event_id=ev.id))

        self.db.commit()
        return alert

    def test_01_alert_evidence_grounded_triage(self):
        """Verify triage_alert produces an evidence-grounded AI analysis with verified claims."""
        alert = self._create_alert_with_evidence()
        analysis = triage_alert(self.db, alert)
        self.db.commit()

        self.assertIsNotNone(analysis)
        self.assertEqual(analysis.alert_id, alert.id)
        self.assertIn("SLM-SecurityTriage", analysis.model_name)
        self.assertEqual(analysis.suggested_classification, "TRUE_POSITIVE")
        self.assertEqual(analysis.suggested_severity, "CRITICAL")
        self.assertGreaterEqual(analysis.confidence, 0.70)

        # Check claims audit metrics
        self.assertGreater(analysis.ai_claim_count, 0)
        self.assertGreater(analysis.supported_claim_count, 0)
        self.assertGreaterEqual(analysis.grounding_rate, 0.75)

        # Verify claims structure
        claims = analysis.supporting_evidence_json.get("claims", [])
        self.assertGreater(len(claims), 0)
        for claim in claims:
            self.assertIn("claim_text", claim)
            self.assertIn("is_supported", claim)

        # Audit log entry must be present
        log = self.db.query(AuditLog).filter(
            AuditLog.action == "AI_TRIAGE_GENERATED",
            AuditLog.resource_id == str(alert.id),
        ).first()
        self.assertIsNotNone(log)

    def test_02_incident_evidence_grounded_triage(self):
        """Verify triage_incident correlates multi-alert campaigns into evidence-backed incident triage."""
        now = datetime.now(UTC)
        incident = Incident(
            incident_number="INC-AI-01",
            title="Multi-stage Infiltration Attempt",
            description="Testing AI incident triage",
            severity="high",
            status="open",
            source_ip="203.0.113.77",
            first_seen=now,
            last_seen=now,
            alert_count=2,
            event_count=4,
        )
        self.db.add(incident)
        self.db.flush()

        a1 = self._create_alert_with_evidence("Path traversal attempt detected", severity="high", source_ip="203.0.113.77", count=2)
        a2 = self._create_alert_with_evidence("Cross-site scripting probe detected", severity="medium", source_ip="203.0.113.77", count=2)

        self.db.add_all([
            IncidentAlert(incident_id=incident.id, alert_id=a1.id),
            IncidentAlert(incident_id=incident.id, alert_id=a2.id),
        ])
        self.db.commit()

        analysis = triage_incident(self.db, incident)
        self.db.commit()

        self.assertIsNotNone(analysis)
        self.assertEqual(analysis.incident_id, incident.id)
        self.assertIn(incident.incident_number, analysis.summary)
        self.assertGreater(analysis.ai_claim_count, 0)
        self.assertGreaterEqual(analysis.grounding_rate, 0.60)

    def test_03_claims_audit_unsupported_claim_detection(self):
        """Verify Claims Audit detects missing evidence and flags uncertainty notes."""
        now = datetime.now(UTC)
        # Create alert with no linked events (sparse telemetry)
        alert = Alert(
            title="Suspicious user agent",
            description="Sparse telemetry alert",
            severity="low",
            status="open",
            source_ip=None,
            first_seen=now,
            last_seen=now,
            event_count=0,
        )
        self.db.add(alert)
        self.db.commit()

        analysis = triage_alert(self.db, alert)
        self.db.commit()

        self.assertIsNotNone(analysis)
        # Unsupported claim count should be > 0 because source IP is missing
        self.assertGreater(analysis.unsupported_claim_count, 0)
        self.assertIn("lacked verified concrete evidence", analysis.uncertainty_notes)

    def test_04_analyst_agreement_feedback(self):
        """Verify recording analyst agreement (AGREE/DISAGREE) with audit logging."""
        alert = self._create_alert_with_evidence("SQL injection attempt detected", count=2)
        analysis = triage_alert(self.db, alert)
        self.db.commit()

        analyst = self.db.query(User).filter(User.username == "analyst").first()
        updated = record_analyst_agreement(
            self.db,
            analysis_id=analysis.id,
            agreement="AGREE",
            user_id=analyst.id,
            notes="Confirmed malicious SQLi query syntax in search parameter.",
        )

        self.assertEqual(updated.analyst_agreement, "AGREE")

        # Verify AuditLog recorded
        feedback_log = self.db.query(AuditLog).filter(
            AuditLog.action == "AI_TRIAGE_FEEDBACK_RECORDED",
            AuditLog.resource_id == str(analysis.id),
        ).first()
        self.assertIsNotNone(feedback_log)
        self.assertEqual(feedback_log.details_json["agreement"], "AGREE")

        # Test invalid agreement rejection
        with self.assertRaises(ValueError):
            record_analyst_agreement(self.db, analysis_id=analysis.id, agreement="INVALID_STATUS", user_id=analyst.id)

    def test_05_ai_triage_rest_api_endpoints(self):
        """Verify REST API endpoints for AI triage, detail, feedback, and summary."""
        alert = self._create_alert_with_evidence("Path traversal attempt detected", count=2)

        # 1. POST /api/ai/triage/alert/{id}
        triage_res = self.client.post(f"/api/ai/triage/alert/{alert.id}", headers=self.headers)
        self.assertEqual(triage_res.status_code, 200)
        data = triage_res.json()
        self.assertEqual(data["alert_id"], alert.id)
        self.assertIn("grounding_rate", data)
        self.assertGreaterEqual(data["grounding_rate"], 0.60)
        analysis_id = data["id"]

        # 2. GET /api/ai/analyses/{id}
        detail_res = self.client.get(f"/api/ai/analyses/{analysis_id}", headers=self.headers)
        self.assertEqual(detail_res.status_code, 200)
        self.assertEqual(detail_res.json()["id"], analysis_id)

        # 3. POST /api/ai/analyses/{id}/feedback
        feedback_res = self.client.post(
            f"/api/ai/analyses/{analysis_id}/feedback",
            json={"agreement": "AGREE", "notes": "Verified by Tier 2 analyst"},
            headers=self.headers,
        )
        self.assertEqual(feedback_res.status_code, 200)
        self.assertEqual(feedback_res.json()["analyst_agreement"], "AGREE")

        # 4. GET /api/ai/analyses (list)
        list_res = self.client.get("/api/ai/analyses", headers=self.headers)
        self.assertEqual(list_res.status_code, 200)
        self.assertGreater(list_res.json()["total"], 0)

        # 5. GET /api/ai/summary
        summary_res = self.client.get("/api/ai/summary", headers=self.headers)
        self.assertEqual(summary_res.status_code, 200)
        summary_data = summary_res.json()
        self.assertIn("total_analyses", summary_data)
        self.assertIn("average_grounding_rate", summary_data)
        self.assertIn("agreement_breakdown", summary_data)
        self.assertGreaterEqual(summary_data["total_analyses"], 1)


if __name__ == "__main__":
    unittest.main()
