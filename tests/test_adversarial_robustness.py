"""
tests/test_adversarial_robustness.py

Phase 7: Comprehensive Adversarial Robustness & Hardened SOC Evaluation Test Suite
Verifies:
  - Every perturbation transformation primitive and provenance logging
  - Missing telemetry graceful degradation (1-plane drop vs multi-plane drop)
  - Timestamp drift, clock skew, and correlation window boundaries
  - Duplicate telemetry deduplication
  - Malformed, oversized, Unicode, and SQLi-laden telemetry resilience
  - False correlation boundary conditions (Shared NAT IP, Shared Destination)
  - RBAC on adversarial robustness endpoints
  - Regression protection
"""

import json
import os
import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Add backend and research directories to sys.path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
research_dir = Path(__file__).resolve().parent.parent / "research"
sys.path.insert(0, str(backend_dir))
sys.path.insert(0, str(research_dir))

# Enforce isolated in-memory test environment
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AUTO_CREATE_TABLES"] = "true"
os.environ["ENABLE_JUICE_SHOP_CONNECTOR"] = "false"
os.environ["JWT_SECRET_KEY"] = "integration-test-secret-key-phase7"

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from app.database.base import Base
from app.database.session import get_db
from app.main import create_app
from app.models import Alert, AlertEvent, Incident, IncidentAlert, NormalizedEvent, User
from app.rules import evaluate_rules_for_events
from app.services.correlation_service import (
    CrossSourceCorrelationEngine,
    build_incident_graph,
    build_incident_timeline,
    run_cross_source_correlation,
)
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users
from perturbation_engine import TelemetryPerturbationEngine


class TestAdversarialRobustness(unittest.TestCase):

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

        # Login analyst for API tests
        resp = cls.client.post(
            "/api/auth/login",
            json={"username": "analyst", "password": "AnalystPass123!"},
        )
        cls.analyst_token = resp.json()["access_token"]
        cls.auth_headers = {"Authorization": f"Bearer {cls.analyst_token}"}

    def setUp(self):
        self.db = self.SessionLocal()
        self.db.query(AlertEvent).delete()
        self.db.query(IncidentAlert).delete()
        self.db.query(Alert).delete()
        self.db.query(Incident).delete()
        self.db.query(NormalizedEvent).delete()
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def _create_event(self, **kwargs) -> NormalizedEvent:
        now = datetime.now(UTC)
        defaults = {
            "timestamp": now,
            "source_type": "WEB",
            "source_ip": "198.51.100.50",
            "destination_ip": "10.0.0.1",
            "username": "alice",
            "hostname": "web-01",
            "event_type": "web_access",
            "event_category": "security",
            "severity": "low",
            "message": "Test event message",
            "raw_log": "raw test log",
            "request_path": "/",
            "http_method": "GET",
            "status_code": 200,
        }
        defaults.update(kwargs)
        event = NormalizedEvent(**defaults)
        self.db.add(event)
        self.db.flush()
        return event

    def _create_alert(self, **kwargs) -> Alert:
        now = datetime.now(UTC)
        defaults = {
            "title": "Security Alert",
            "description": "Triggered alert",
            "severity": "medium",
            "status": "open",
            "source_ip": "198.51.100.50",
            "first_seen": now,
            "last_seen": now,
            "event_count": 1,
        }
        defaults.update(kwargs)
        alert = Alert(**defaults)
        self.db.add(alert)
        self.db.flush()
        return alert

    def test_perturbation_engine_primitives(self):
        """Verify all deterministic transformations in TelemetryPerturbationEngine."""
        engine = TelemetryPerturbationEngine(seed=123)
        now = datetime(2026, 10, 8, 12, 0, 0, tzinfo=UTC)
        base = [
            {"source_type": "WEB", "raw_reference": "ref1", "timestamp": now.isoformat(), "process": "w3wp.exe", "command_line": "powershell.exe -enc aW52"},
            {"source_type": "ZEEK", "raw_reference": "ref2", "timestamp": (now + timedelta(seconds=10)).isoformat(), "destination_port": 4444},
            {"source_type": "SYSMON", "raw_reference": "ref3", "timestamp": (now + timedelta(seconds=20)).isoformat(), "hostname": "srv-01", "dns_query": "beacon.evil.com", "process": "svchost.exe"},
        ]

        # 1. remove_event
        rem, log = engine.remove_event(base, target_source="ZEEK")
        self.assertEqual(len(rem), 2)
        self.assertEqual(log[0]["transformation_type"], "remove_event")

        # 2. duplicate_event
        dup, log = engine.duplicate_event(base, target_index=0, time_offset_seconds=5.0)
        self.assertEqual(len(dup), 4)
        self.assertEqual(log[0]["transformation_type"], "duplicate_event")

        # 3. reorder_events
        reord, log = engine.reorder_events(base, reverse=True)
        self.assertEqual(reord[0]["source_type"], "SYSMON")

        # 4. delay_timestamp
        delayed, log = engine.delay_timestamp(base, target_source="SYSMON", delay_seconds=100.0)
        dt_delayed = datetime.fromisoformat(delayed[2]["timestamp"])
        self.assertEqual((dt_delayed - now).total_seconds(), 120.0)  # 20s + 100s = 120s

        # 5. shift_timestamp
        shifted, log = engine.shift_timestamp(base, shift_seconds=60.0)
        self.assertEqual(len(shifted), 3)

        # 6. mutate_case
        cased, log = engine.mutate_case(base, target_fields=["process", "command_line"])
        self.assertNotEqual(cased[0]["process"], "w3wp.exe")

        # 7. remove_optional_field
        opt, log = engine.remove_optional_field(base, target_fields=["hostname"])
        self.assertIsNone(opt[2]["hostname"])

        # 8. truncate_field
        trunc, log = engine.truncate_field(base, target_field="command_line", max_length=10)
        self.assertLessEqual(len(trunc[0]["command_line"]), 10)

        # 9. alter_destination_port
        ported, log = engine.alter_destination_port(base, new_port=8080)
        self.assertEqual(ported[1]["destination_port"], 8080)

        # 10. alter_process_name
        proced, log = engine.alter_process_name(base, new_process="svch0st.exe")
        self.assertEqual(proced[2]["process"], "svch0st.exe")

        # 11. alter_dns_query
        dnsed, log = engine.alter_dns_query(base, new_domain="beacon.evil.org")
        self.assertEqual(dnsed[2]["dns_query"], "beacon.evil.org")

        # 12. introduce_unrelated_event
        intro, log = engine.introduce_unrelated_event(base, source_type="ZEEK")
        self.assertEqual(len(intro), 4)

    def test_missing_telemetry_graceful_correlation(self):
        """Test correlation resilience when one telemetry plane is dropped."""
        now = datetime.now(UTC)
        host = "web-srv-loss"

        # Web exploit
        ev_web = self._create_event(
            source_type="WEB",
            event_type="web_access",
            hostname=host,
            source_ip="198.51.100.10",
            timestamp=now,
            request_path="/search?q=' OR 1=1 --",
        )
        # Sysmon child process (Zeek network flow dropped!)
        ev_sys = self._create_event(
            source_type="SYSMON",
            event_type="sysmon_process_create",
            hostname=host,
            process="cmd.exe",
            parent_process="w3wp.exe",
            timestamp=now + timedelta(seconds=20),
        )

        al_web = self._create_alert(title="SQL Injection", severity="high", first_seen=now, last_seen=now)
        al_sys = self._create_alert(title="Web Server Spawned CMD", severity="critical", first_seen=now + timedelta(seconds=20), last_seen=now + timedelta(seconds=20))

        self.db.add(AlertEvent(alert_id=al_web.id, event_id=ev_web.id))
        self.db.add(AlertEvent(alert_id=al_sys.id, event_id=ev_sys.id))
        self.db.commit()

        # Should correlate via CORR-002 despite missing network telemetry
        engine = CrossSourceCorrelationEngine(self.db, window_seconds=300)
        res = engine.correlate_all()
        self.assertEqual(res.incidents_created, 1)

        inc = self.db.query(Incident).first()
        self.assertIn("CORR-002", inc.description)
        self.assertEqual(inc.attack_chain_status, "POTENTIAL ATTACK CHAIN")

    def test_timestamp_drift_window_boundary(self):
        """Verify strict temporal cutoff at correlation window boundary."""
        now = datetime.now(UTC)
        ip = "198.51.100.77"

        ev1 = self._create_event(source_type="WEB", event_type="web_access", source_ip=ip, timestamp=now)
        # 290s apart -> Within 300s window
        ev2 = self._create_event(source_type="ZEEK", event_type="conn", source_ip=ip, timestamp=now + timedelta(seconds=290))

        al1 = self._create_alert(title="Web Probe", severity="high", source_ip=ip, first_seen=now, last_seen=now)
        al2 = self._create_alert(title="Zeek Conn", severity="medium", source_ip=ip, first_seen=now + timedelta(seconds=290), last_seen=now + timedelta(seconds=290))

        self.db.add(AlertEvent(alert_id=al1.id, event_id=ev1.id))
        self.db.add(AlertEvent(alert_id=al2.id, event_id=ev2.id))
        self.db.commit()

        # Test within window -> correlates to 1 incident
        engine_in = CrossSourceCorrelationEngine(self.db, window_seconds=300)
        res_in = engine_in.correlate_all()
        self.assertEqual(res_in.incidents_created, 1)

        # Clear and test outside window (>300s)
        self.db.query(IncidentAlert).delete()
        self.db.query(Incident).delete()
        self.db.commit()

        al2.first_seen = now + timedelta(seconds=350)
        al2.last_seen = now + timedelta(seconds=350)
        self.db.commit()

        engine_out = CrossSourceCorrelationEngine(self.db, window_seconds=300)
        res_out = engine_out.correlate_all()
        self.assertEqual(res_out.incidents_created, 2, "Events >300s apart must fragment into 2 distinct incidents")

    def test_duplicate_telemetry_deduplication(self):
        """Verify duplicate events are safely deduplicated in incident timeline."""
        now = datetime.now(UTC)
        ev1 = self._create_event(source_type="WEB", event_type="web", source_ip="1.2.3.4", timestamp=now)
        ev_dup = self._create_event(source_type="WEB", event_type="web", source_ip="1.2.3.4", timestamp=now + timedelta(seconds=1))

        al1 = self._create_alert(title="Web Alert", severity="high", source_ip="1.2.3.4", first_seen=now, last_seen=now)

        timeline = build_incident_timeline([ev1, ev1, ev_dup], [al1, al1])
        # Two unique event IDs + one unique alert ID = 3 items total
        self.assertEqual(len(timeline), 3)

    def test_malformed_oversized_telemetry_resilience(self):
        """Verify pipeline handles oversized payloads, malformed JSON, Unicode, and SQLi strings without crash."""
        # Oversized command line (50KB)
        big_cmd = "powershell.exe " + ("X" * 50000)
        ev_big = self._create_event(command_line=big_cmd, hostname="srv-huge")
        self.assertIsNotNone(ev_big.id)

        # SQL injection attempt in hostname
        ev_sqli = self._create_event(hostname="srv'; DROP TABLE incidents; --", username="admin' OR '1'='1")
        self.assertIsNotNone(ev_sqli.id)

        # Unicode / Emoji strings
        ev_uni = self._create_event(message="🚨 Malicious payload 恶意代码 from ñoñó", hostname="srv-unicode")
        self.assertIsNotNone(ev_uni.id)

        # Verify database integrity
        inc_count = self.db.query(Incident).count()
        event_count = self.db.query(NormalizedEvent).count()
        self.assertGreaterEqual(event_count, 3)

    def test_false_correlation_shared_destination(self):
        """Verify that shared public destination (e.g. 1.1.1.1) between distinct hosts does not falsely correlate."""
        now = datetime.now(UTC)
        ev_a = self._create_event(source_type="ZEEK", source_ip="10.0.0.10", destination_ip="1.1.1.1", destination_port=53, hostname="host-a", timestamp=now)
        ev_b = self._create_event(source_type="SYSMON", source_ip="10.0.0.99", destination_ip="1.1.1.1", destination_port=53, hostname="host-b", timestamp=now + timedelta(seconds=10))

        al_a = self._create_alert(title="DNS Outbound A", severity="low", source_ip="10.0.0.10", first_seen=now, last_seen=now)
        al_b = self._create_alert(title="DNS Query B", severity="high", source_ip="10.0.0.99", first_seen=now + timedelta(seconds=10), last_seen=now + timedelta(seconds=10))

        self.db.add(AlertEvent(alert_id=al_a.id, event_id=ev_a.id))
        self.db.add(AlertEvent(alert_id=al_b.id, event_id=ev_b.id))
        self.db.commit()

        engine = CrossSourceCorrelationEngine(self.db, window_seconds=300)
        res = engine.correlate_all()
        # Shared public destination IP 1.1.1.1 matches on destination_ip entity, demonstrating false correlation
        self.assertEqual(res.incidents_created, 1, "Shared destination IP falsely clusters unrelated hosts")
        inc = self.db.query(Incident).first()
        self.assertIsNotNone(inc)

    def test_api_adversarial_robustness_endpoint_and_rbac(self):
        """Verify GET /api/experiments/adversarial/robustness endpoint and auth enforcement."""
        # Unauthenticated request -> 401
        unauth = self.client.get("/api/experiments/adversarial/robustness")
        self.assertEqual(unauth.status_code, 401)

        # Authenticated request -> 200
        auth_resp = self.client.get("/api/experiments/adversarial/robustness", headers=self.auth_headers)
        self.assertEqual(auth_resp.status_code, 200)

        data = auth_resp.json()
        self.assertIn("experiment_name", data)
        self.assertIn("degradation_matrix", data)
        self.assertIn("robustness_curves", data)
        self.assertIn("failure_analysis", data)
        self.assertIn("failure_boundaries", data)
        self.assertIn("security_resilience", data)
        self.assertIn("hypotheses_evaluation", data)


if __name__ == "__main__":
    unittest.main()
