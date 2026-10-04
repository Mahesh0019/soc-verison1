"""
tests/test_evidence_engine.py

Comprehensive tests for Phase 4 Evidence Engine:
- Evidence package creation for alerts and incidents
- Calculation of explainable completeness scores
- Evidence lineage: triggering event, supporting events, detection rules, context, timeline
- Evidence API endpoints (/api/evidence, /api/evidence/alert/{id}, /api/evidence/incident/{id})
"""

import os
import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from app.database.base import Base
from app.database.session import get_db
from app.main import create_app
from app.models import Alert, AlertEvent, DetectionRule, Evidence, Incident, IncidentAlert, NormalizedEvent, ThreatIndicator, User
from app.services.evidence_service import (
    build_evidence_package,
    build_incident_evidence_package,
    calculate_evidence_completeness,
)
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users


class TestEvidenceEngine(unittest.TestCase):

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

        # Get analyst authentication token
        res = cls.client.post("/api/auth/login", json={"username": "analyst", "password": "AnalystPass123!"})
        cls.analyst_token = res.json()["access_token"]
        cls.headers = {"Authorization": f"Bearer {cls.analyst_token}"}

    @classmethod
    def tearDownClass(cls):
        Base.metadata.drop_all(bind=cls.engine)

    def setUp(self):
        self.db = self.SessionLocal()

    def tearDown(self):
        self.db.rollback()
        self.db.close()

    def test_01_build_alert_evidence_package(self):
        """Verify build_evidence_package produces structured evidence records across all key dimensions."""
        now = datetime.now(UTC)
        rule = self.db.query(DetectionRule).first()

        # Create alert with linked events
        alert = Alert(
            rule_id=rule.id if rule else None,
            title="Evidence Test Alert",
            description="Testing evidence synthesis",
            severity="high",
            status="open",
            source_ip="198.51.100.99",
            affected_user="test_target",
            first_seen=now - timedelta(minutes=5),
            last_seen=now,
            event_count=2,
        )
        self.db.add(alert)
        self.db.flush()

        ev1 = NormalizedEvent(
            timestamp=now - timedelta(minutes=5),
            source_ip="198.51.100.99",
            username="test_target",
            event_type="web_request",
            event_category="web",
            severity="medium",
            message="GET /admin returned 403",
        )
        ev2 = NormalizedEvent(
            timestamp=now,
            source_ip="198.51.100.99",
            username="test_target",
            event_type="web_request",
            event_category="web",
            severity="high",
            message="GET /admin/config returned 403",
        )
        self.db.add_all([ev1, ev2])
        self.db.flush()

        self.db.add_all([AlertEvent(alert_id=alert.id, event_id=ev1.id), AlertEvent(alert_id=alert.id, event_id=ev2.id)])
        self.db.commit()

        # Build evidence package
        items = build_evidence_package(self.db, alert)
        self.assertGreaterEqual(len(items), 4)

        types = {i.evidence_type for i in items}
        self.assertIn("detection_rule", types)
        self.assertIn("triggering_event", types)
        self.assertIn("related_events", types)
        self.assertIn("entity_context", types)
        self.assertIn("timeline", types)

        completeness = calculate_evidence_completeness(items)
        self.assertGreaterEqual(completeness, 0.85)

    def test_02_threat_intel_evidence_enrichment(self):
        """Verify threat intelligence IOC match adds threat_intel evidence item."""
        now = datetime.now(UTC)
        # Seeded indicator has IP '203.0.113.66'
        alert = Alert(
            title="Blacklisted Indicator Activity",
            description="Matched malicious scanner",
            severity="critical",
            status="open",
            source_ip="203.0.113.66",
            first_seen=now,
            last_seen=now,
            event_count=1,
        )
        self.db.add(alert)
        self.db.commit()

        items = build_evidence_package(self.db, alert)
        ti_items = [i for i in items if i.evidence_type == "threat_intel"]
        self.assertEqual(len(ti_items), 1)
        self.assertEqual(ti_items[0].data_json["value"], "203.0.113.66")

    def test_03_incident_evidence_package(self):
        """Verify build_incident_evidence_package synthesizes incident-level evidence."""
        now = datetime.now(UTC)
        incident = Incident(
            incident_number="INC-EVID-01",
            title="Coordinated Reconnaissance",
            description="Multiple scanning probes observed",
            severity="high",
            status="open",
            source_ip="198.51.100.22",
            first_seen=now,
            last_seen=now,
            alert_count=2,
            event_count=10,
        )
        self.db.add(incident)
        self.db.commit()

        items = build_incident_evidence_package(self.db, incident)
        self.assertGreaterEqual(len(items), 2)
        types = {i.evidence_type for i in items}
        self.assertIn("incident_summary", types)
        self.assertIn("correlated_alerts", types)

    def test_04_evidence_api_endpoints(self):
        """Verify REST API endpoints for evidence retrieval."""
        now = datetime.now(UTC)
        alert = Alert(
            title="API Evidence Test Alert",
            description="Testing evidence endpoints",
            severity="medium",
            status="open",
            source_ip="198.51.100.33",
            first_seen=now,
            last_seen=now,
            event_count=1,
        )
        self.db.add(alert)
        self.db.flush()

        ev = NormalizedEvent(
            timestamp=now,
            source_ip="198.51.100.33",
            event_type="web_request",
            event_category="web",
            severity="medium",
            message="GET /api/test returned 200",
        )
        self.db.add(ev)
        self.db.flush()
        self.db.add(AlertEvent(alert_id=alert.id, event_id=ev.id))
        self.db.commit()

        # Query alert evidence package
        res = self.client.get(f"/api/evidence/alert/{alert.id}", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["alert_id"], alert.id)
        self.assertGreater(data["total_evidence_items"], 0)
        self.assertGreaterEqual(data["completeness_score"], 0.70)

        # List all evidence items
        list_res = self.client.get("/api/evidence", headers=self.headers)
        self.assertEqual(list_res.status_code, 200)
        self.assertGreater(list_res.json()["total"], 0)

        # Get specific evidence item
        item_id = data["items"][0]["id"]
        item_res = self.client.get(f"/api/evidence/{item_id}", headers=self.headers)
        self.assertEqual(item_res.status_code, 200)
        self.assertEqual(item_res.json()["id"], item_id)


if __name__ == "__main__":
    unittest.main()
