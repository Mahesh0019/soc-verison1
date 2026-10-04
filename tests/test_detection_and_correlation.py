"""
tests/test_detection_and_correlation.py

Comprehensive test suite for Phase 3:
- Preserved baseline rules (threshold, sequence, threat intel)
- New pattern detection rules (SQLi, path traversal, XSS)
- Event and alert correlation engine
- Multi-stage attack chain grouping into structured Incidents
- Incident deduplication within sliding window
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

from app.database.base import Base
from app.models import Alert, DetectionRule, Incident, IncidentAlert, NormalizedEvent, ThreatIndicator, User
from app.rules.builtin import builtin_rules
from app.rules.correlation import calculate_correlation_metrics, classify_alert_stage, correlate_incidents
from app.rules.engine import evaluate_rules_for_events
from app.services.seed import ensure_builtin_rules, ensure_indicators


class TestDetectionAndCorrelation(unittest.TestCase):

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
            ensure_builtin_rules(db)
            ensure_indicators(db)
        finally:
            db.close()

    @classmethod
    def tearDownClass(cls):
        Base.metadata.drop_all(bind=cls.engine)

    def setUp(self):
        self.db = self.SessionLocal()

    def tearDown(self):
        self.db.rollback()
        self.db.close()

    def _create_event(self, **kwargs) -> NormalizedEvent:
        now = datetime.now(UTC)
        defaults = {
            "timestamp": now,
            "source_ip": "198.51.100.50",
            "destination_ip": "10.0.0.1",
            "username": "alice",
            "hostname": "web-01",
            "event_type": "web_request",
            "event_category": "web",
            "severity": "low",
            "message": "GET / HTTP/1.1",
            "raw_log": "raw log string",
            "user_agent": "Mozilla/5.0",
            "request_path": "/",
            "http_method": "GET",
            "status_code": 200,
            "geo_country": "US",
        }
        defaults.update(kwargs)
        event = NormalizedEvent(**defaults)
        self.db.add(event)
        self.db.flush()
        return event

    def test_01_sqli_pattern_rule(self):
        """Verify pattern detection rule triggers alert on SQL injection signatures."""
        event = self._create_event(
            source_ip="203.0.113.111",
            request_path="/rest/products/search?q=' OR 1=1 --",
            message="GET /rest/products/search?q=' OR 1=1 -- returned 200",
            status_code=200,
        )
        alert_count = evaluate_rules_for_events(self.db, [event], auto_correlate=False)
        self.assertGreaterEqual(alert_count, 1)

        alert = self.db.query(Alert).filter(Alert.source_ip == "203.0.113.111").first()
        self.assertIsNotNone(alert)
        self.assertIn("SQL injection", alert.title)
        self.assertEqual(alert.severity, "critical")

    def test_02_path_traversal_pattern_rule(self):
        """Verify pattern detection rule triggers alert on directory traversal sequences."""
        event = self._create_event(
            source_ip="203.0.113.112",
            request_path="/ftp?file=../../../../etc/passwd",
            message="GET /ftp?file=../../../../etc/passwd returned 403",
            status_code=403,
        )
        alert_count = evaluate_rules_for_events(self.db, [event], auto_correlate=False)
        self.assertGreaterEqual(alert_count, 1)

        alert = self.db.query(Alert).filter(Alert.source_ip == "203.0.113.112").first()
        self.assertIsNotNone(alert)
        self.assertIn("Path traversal", alert.title)
        self.assertEqual(alert.severity, "high")

    def test_03_xss_pattern_rule(self):
        """Verify pattern detection rule triggers alert on XSS probe signatures."""
        event = self._create_event(
            source_ip="203.0.113.113",
            request_path="/search?q=<script>alert(1)</script>",
            message="GET /search?q=<script>alert(1)</script> returned 200",
            status_code=200,
        )
        alert_count = evaluate_rules_for_events(self.db, [event], auto_correlate=False)
        self.assertGreaterEqual(alert_count, 1)

        alert = self.db.query(Alert).filter(Alert.source_ip == "203.0.113.113").first()
        self.assertIsNotNone(alert)
        self.assertIn("Cross-site scripting", alert.title)

    def test_04_correlation_engine_groups_alerts_into_incident(self):
        """Verify multi-stage attack from same source IP correlates into an Incident."""
        attacker_ip = "198.51.100.77"
        now = datetime.now(UTC)

        # Stage 1: Reconnaissance (suspicious UA)
        ev1 = self._create_event(
            timestamp=now - timedelta(minutes=15),
            source_ip=attacker_ip,
            user_agent="sqlmap/1.7.2#stable",
            request_path="/api/Products",
        )

        # Stage 2: Probing (sensitive path access)
        evs2 = [
            self._create_event(
                timestamp=now - timedelta(minutes=10, seconds=i * 5),
                source_ip=attacker_ip,
                request_path="/admin/users",
                status_code=401,
            )
            for i in range(5)
        ]

        # Stage 3: Exploitation (SQL injection)
        ev3 = self._create_event(
            timestamp=now - timedelta(minutes=5),
            source_ip=attacker_ip,
            request_path="/api/Products?q=' UNION SELECT 1,2,3 --",
            message="SQLi probe",
        )

        all_events = [ev1] + evs2 + [ev3]
        alert_count = evaluate_rules_for_events(self.db, all_events, auto_correlate=True)
        self.assertGreaterEqual(alert_count, 2)

        # Query incidents for this attacker IP
        incidents = self.db.query(Incident).filter(Incident.source_ip == attacker_ip).all()
        self.assertEqual(len(incidents), 1, "Multiple alerts from same IP should correlate into ONE active Incident")

        inc = incidents[0]
        self.assertTrue(inc.incident_number.startswith("INC-"))
        self.assertGreaterEqual(inc.alert_count, 2)
        self.assertEqual(inc.severity, "critical", "Incident severity should escalate to critical from SQLi alert")
        self.assertIn("Multi-stage", inc.description)
        self.assertIn("Observed stages", inc.description)

    def test_05_incident_deduplication_within_window(self):
        """Verify incremental alerts within the sliding window update existing incident rather than duplicating."""
        attacker_ip = "198.51.100.88"
        now = datetime.now(UTC)

        # First alert batch: Probing
        batch1 = [
            self._create_event(
                timestamp=now - timedelta(minutes=20, seconds=i * 5),
                source_ip=attacker_ip,
                request_path="/.env",
                status_code=403,
            )
            for i in range(5)
        ]
        evaluate_rules_for_events(self.db, batch1, auto_correlate=True)

        inc_count_1 = self.db.query(Incident).filter(Incident.source_ip == attacker_ip).count()
        self.assertEqual(inc_count_1, 1)

        # Second alert batch 10 minutes later: Credential testing (failed logins)
        batch2 = [
            self._create_event(
                timestamp=now - timedelta(minutes=10, seconds=i * 5),
                source_ip=attacker_ip,
                username="admin",
                event_type="failed_login",
                event_category="authentication",
                status_code=401,
            )
            for i in range(6)
        ]
        evaluate_rules_for_events(self.db, batch2, auto_correlate=True)

        # Verify still ONE incident, but with updated counts and extended description
        incidents = self.db.query(Incident).filter(Incident.source_ip == attacker_ip).all()
        self.assertEqual(len(incidents), 1, "Incremental alerts within window must NOT create duplicate incidents")

        inc = incidents[0]
        self.assertGreaterEqual(inc.alert_count, 2)
        self.assertEqual(len(inc.alerts), inc.alert_count)

    def test_06_correlation_metrics_calculation(self):
        """Verify calculate_correlation_metrics accurately computes strength and stages."""
        now = datetime.now(UTC)
        a1 = Alert(title="Suspicious user agent", severity="high", first_seen=now, last_seen=now, event_count=2)
        a2 = Alert(title="Repeated sensitive path access", severity="high", first_seen=now, last_seen=now, event_count=4)
        a3 = Alert(title="SQL injection attempt detected", severity="critical", first_seen=now, last_seen=now, event_count=1)

        metrics = calculate_correlation_metrics([a1, a2, a3])
        self.assertEqual(metrics["highest_severity"], "critical")
        self.assertIn("reconnaissance", metrics["stages_observed"])
        self.assertIn("probing", metrics["stages_observed"])
        self.assertIn("exploitation", metrics["stages_observed"])
        self.assertGreaterEqual(metrics["correlation_strength"], 0.75)


if __name__ == "__main__":
    unittest.main()
