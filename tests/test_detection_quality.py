"""
tests/test_detection_quality.py

Comprehensive tests for Phase 5 Detection Quality Engine:
- Explainable multi-factor scoring (evidence, correlation, rule, behavioral, context)
- Transparent factor breakdown in factors_json
- Alert-level and incident-level quality evaluation
- Quality summary aggregation and tier distribution
- REST API endpoints (/api/detection-quality, /api/detection-quality/summary, etc.)
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
from app.models import Alert, AlertEvent, DetectionQuality, DetectionRule, Incident, IncidentAlert, NormalizedEvent, ThreatIndicator, User
from app.services.detection_quality_service import (
    evaluate_alert_quality,
    evaluate_incident_quality,
    get_detection_quality_summary,
)
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users


class TestDetectionQuality(unittest.TestCase):

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

    def _create_alert_with_events(self, title, severity="high", source_ip="198.51.100.44", user="victim_user", count=3):
        now = datetime.now(UTC)
        rule = self.db.query(DetectionRule).filter(DetectionRule.name.ilike(f"%{title[:10]}%")).first()
        alert = Alert(
            rule_id=rule.id if rule else None,
            title=title,
            description="Testing detection quality",
            severity=severity,
            status="open",
            source_ip=source_ip,
            affected_user=user,
            first_seen=now - timedelta(minutes=5),
            last_seen=now,
            event_count=count,
        )
        self.db.add(alert)
        self.db.flush()

        events = []
        for i in range(count):
            ev = NormalizedEvent(
                timestamp=now - timedelta(seconds=i * 10),
                source_ip=source_ip,
                username=user,
                event_type="web_request",
                event_category="web",
                severity=severity,
                message=f"Event {i} for {title}",
            )
            self.db.add(ev)
            self.db.flush()
            events.append(ev)
            self.db.add(AlertEvent(alert_id=alert.id, event_id=ev.id))

        self.db.commit()
        return alert

    def test_01_explainable_alert_quality_scoring(self):
        """Verify evaluate_alert_quality computes all five factors and sets transparent explanation."""
        alert = self._create_alert_with_events("SQL injection attempt detected", severity="critical", count=4)
        dq = evaluate_alert_quality(self.db, alert)
        self.db.commit()

        self.assertIsNotNone(dq)
        self.assertGreaterEqual(dq.overall_quality, 0.75)
        self.assertGreaterEqual(dq.rule_confidence, 0.90)
        self.assertGreater(dq.evidence_completeness, 0.70)
        self.assertGreater(dq.context_confidence, 0.50)

        # Check factors_json structure
        factors = dq.factors_json
        self.assertIn("weights", factors)
        self.assertEqual(factors["weights"]["evidence_completeness"], 0.25)
        self.assertEqual(factors["weights"]["correlation_strength"], 0.20)
        self.assertEqual(factors["weights"]["rule_confidence"], 0.20)
        self.assertEqual(factors["weights"]["behavioral_confidence"], 0.15)
        self.assertEqual(factors["weights"]["context_confidence"], 0.20)

        # Explanation must be detailed
        self.assertIn("Quality:", dq.explanation)

    def test_02_incident_quality_evaluation(self):
        """Verify evaluate_incident_quality aggregates quality across component alerts."""
        now = datetime.now(UTC)
        incident = Incident(
            incident_number="INC-DQ-01",
            title="Coordinated Credential Probing",
            description="Multi-alert campaign",
            severity="high",
            status="open",
            source_ip="198.51.100.55",
            first_seen=now,
            last_seen=now,
            alert_count=2,
            event_count=6,
        )
        self.db.add(incident)
        self.db.flush()

        a1 = self._create_alert_with_events("Repeated sensitive path access", severity="high", source_ip="198.51.100.55")
        a2 = self._create_alert_with_events("Multiple failed login attempts from same IP", severity="high", source_ip="198.51.100.55")

        self.db.add_all([
            IncidentAlert(incident_id=incident.id, alert_id=a1.id),
            IncidentAlert(incident_id=incident.id, alert_id=a2.id),
        ])
        self.db.commit()

        inc_dq = evaluate_incident_quality(self.db, incident)
        self.db.commit()

        self.assertIsNotNone(inc_dq)
        self.assertEqual(inc_dq.incident_id, incident.id)
        self.assertGreaterEqual(inc_dq.overall_quality, 0.70)
        self.assertEqual(inc_dq.factors_json["component_alert_count"], 2)

    def test_03_quality_summary_aggregation(self):
        """Verify get_detection_quality_summary aggregates tier counts and rankings."""
        summary = get_detection_quality_summary(self.db)
        self.assertIn("average_quality", summary)
        self.assertIn("tier_distribution", summary)
        self.assertIn("high", summary["tier_distribution"])
        self.assertIn("rule_quality_rankings", summary)
        self.assertGreaterEqual(summary["average_quality"], 0.0)

    def test_04_detection_quality_api_endpoints(self):
        """Verify REST API endpoints for detection quality inspection."""
        alert = self._create_alert_with_events("Suspicious user agent", severity="high", count=2)

        # Query alert quality via API
        alert_res = self.client.get(f"/api/detection-quality/alert/{alert.id}", headers=self.headers)
        self.assertEqual(alert_res.status_code, 200)
        data = alert_res.json()
        self.assertEqual(data["alert_id"], alert.id)
        self.assertGreaterEqual(data["overall_quality"], 0.60)
        self.assertIn("evidence_completeness", data["factors_json"])

        # Query summary via API
        summary_res = self.client.get("/api/detection-quality/summary", headers=self.headers)
        self.assertEqual(summary_res.status_code, 200)
        summary_data = summary_res.json()
        self.assertIn("average_quality", summary_data)
        self.assertIn("weak_detection_count", summary_data)

        # List all detection quality records
        list_res = self.client.get("/api/detection-quality", headers=self.headers)
        self.assertEqual(list_res.status_code, 200)
        self.assertGreater(list_res.json()["total"], 0)


if __name__ == "__main__":
    unittest.main()
