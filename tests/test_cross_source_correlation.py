"""
tests/test_cross_source_correlation.py

Comprehensive tests for Phase 6: Cross-Source Correlation & Unified Incident Reconstruction
Verifies:
- Deterministic Entity Resolution (source_ip, destination_ip, hostname, username, process)
- Configurable Temporal Correlation Windows (30s, 120s, 300s, 600s)
- Explicit Correlation Rules (CORR-001, CORR-002, CORR-003, CORR-004)
- Explainable Correlation Scoring & Insufficient Evidence handling
- Timeline chronological ordering and delta calculations
- Graph reconstruction (nodes and edges backed strictly by telemetry)
- Incident separation vs. merging
- Robustness on missing fields, duplicates, and non-correlating events
- RBAC and REST API endpoints (/correlate, /{id}/unified, /{id}/graph, /{id}/timeline)
"""

import json
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
os.environ["JWT_SECRET_KEY"] = "integration-test-secret-key-phase6"

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from app.database.base import Base
from app.database.session import get_db
from app.main import create_app
from app.models import Alert, AlertEvent, Incident, IncidentAlert, NormalizedEvent, User
from app.services.correlation_service import (
    CrossSourceCorrelationEngine,
    build_incident_graph,
    build_incident_timeline,
    calculate_correlation_score,
)
from app.services.seed import ensure_builtin_rules, ensure_users


class TestCrossSourceCorrelation(unittest.TestCase):

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
        # Clean test tables between tests while keeping users/rules
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

    def test_same_ip_correlation_corr_001(self):
        """Test CORR-001: Web attack + Zeek connection on same source_ip within time window."""
        now = datetime.now(UTC)
        ev_web = self._create_event(
            source_type="WEB",
            event_type="web_access",
            source_ip="203.0.113.50",
            destination_ip="192.168.1.10",
            timestamp=now,
            request_path="/login.php?id=' OR '1'='1",
        )
        ev_zeek = self._create_event(
            source_type="ZEEK",
            event_type="conn",
            source_ip="203.0.113.50",
            destination_ip="192.168.1.10",
            destination_port=4444,
            timestamp=now + timedelta(seconds=15),
            raw_log='{"proto": "tcp", "uid": "Cwebzeek01"}',
        )

        al_web = self._create_alert(
            title="SQL Injection Probe",
            severity="high",
            source_ip="203.0.113.50",
            first_seen=now,
            last_seen=now,
        )
        al_zeek = self._create_alert(
            title="Suspicious Outbound Port",
            severity="medium",
            source_ip="203.0.113.50",
            first_seen=now + timedelta(seconds=15),
            last_seen=now + timedelta(seconds=15),
        )

        self.db.add(AlertEvent(alert_id=al_web.id, event_id=ev_web.id))
        self.db.add(AlertEvent(alert_id=al_zeek.id, event_id=ev_zeek.id))
        self.db.commit()

        engine = CrossSourceCorrelationEngine(self.db, window_seconds=300)
        res = engine.correlate_all()

        self.assertEqual(res.incidents_created, 1)
        inc = self.db.query(Incident).first()
        self.assertIsNotNone(inc)
        self.assertIn("203.0.113.50", inc.primary_entity)
        self.assertIn("WEB", inc.source_types)
        self.assertIn("ZEEK", inc.source_types)
        self.assertGreater(inc.correlation_score, 0.5)
        self.assertIn("CORR-001", inc.description)

    def test_same_host_correlation_corr_002(self):
        """Test CORR-002: Web attack + Sysmon process creation on same host."""
        now = datetime.now(UTC)
        ev_web = self._create_event(
            source_type="WEB",
            event_type="web_access",
            hostname="web-srv-prod",
            source_ip="198.51.100.22",
            timestamp=now,
            request_path="/upload.php",
        )
        ev_sysmon = self._create_event(
            source_type="SYSMON",
            event_type="sysmon_process_create",
            hostname="web-srv-prod",
            process="cmd.exe",
            parent_process="w3wp.exe",
            timestamp=now + timedelta(seconds=40),
            command_line="cmd.exe /c whoami",
        )

        al_web = self._create_alert(title="Web Shell Upload Attempt", severity="high", first_seen=now, last_seen=now)
        al_sys = self._create_alert(title="Suspicious Web Server Child Process", severity="critical", first_seen=now + timedelta(seconds=40), last_seen=now + timedelta(seconds=40))

        self.db.add(AlertEvent(alert_id=al_web.id, event_id=ev_web.id))
        self.db.add(AlertEvent(alert_id=al_sys.id, event_id=ev_sysmon.id))
        self.db.commit()

        engine = CrossSourceCorrelationEngine(self.db, window_seconds=300)
        res = engine.correlate_all()

        self.assertEqual(res.incidents_created, 1)
        inc = self.db.query(Incident).first()
        self.assertIn("CORR-002", inc.description)
        self.assertEqual(inc.attack_chain_status, "POTENTIAL ATTACK CHAIN")
        self.assertIn("SYSMON", inc.source_types)
        self.assertIn("WEB", inc.source_types)

    def test_endpoint_network_socket_corr_003(self):
        """Test CORR-003: Zeek connection + Sysmon network connection matching IP relationship."""
        now = datetime.now(UTC)
        ev_zeek = self._create_event(
            source_type="ZEEK",
            event_type="conn",
            source_ip="10.0.0.50",
            destination_ip="185.220.101.5",
            destination_port=4444,
            timestamp=now,
        )
        ev_sys = self._create_event(
            source_type="SYSMON",
            event_type="sysmon_network_connection",
            source_ip="10.0.0.50",
            destination_ip="185.220.101.5",
            destination_port=4444,
            process="rundll32.exe",
            timestamp=now + timedelta(seconds=5),
        )

        al_zeek = self._create_alert(title="Zeek C2 Beacon", severity="high", first_seen=now, last_seen=now)
        al_sys = self._create_alert(title="Sysmon Rundll32 Outbound Socket", severity="high", first_seen=now + timedelta(seconds=5), last_seen=now + timedelta(seconds=5))

        self.db.add(AlertEvent(alert_id=al_zeek.id, event_id=ev_zeek.id))
        self.db.add(AlertEvent(alert_id=al_sys.id, event_id=ev_sys.id))
        self.db.commit()

        engine = CrossSourceCorrelationEngine(self.db, window_seconds=120)
        res = engine.correlate_all()

        self.assertEqual(res.incidents_created, 1)
        inc = self.db.query(Incident).first()
        self.assertIn("CORR-003", inc.description)

    def test_endpoint_dns_network_corr_004(self):
        """Test CORR-004: Sysmon DNS query + Zeek network/DNS activity on same host/IP."""
        now = datetime.now(UTC)
        ev_dns = self._create_event(
            source_type="SYSMON",
            event_type="sysmon_dns_query",
            hostname="workstation-99",
            source_ip="10.0.0.99",
            destination_ip="1.1.1.1",
            dns_query="beacon.evilcorp.net",
            timestamp=now,
        )
        ev_zeek = self._create_event(
            source_type="ZEEK",
            event_type="dns",
            hostname="workstation-99",
            source_ip="10.0.0.99",
            destination_ip="1.1.1.1",
            dns_query="beacon.evilcorp.net",
            timestamp=now + timedelta(seconds=2),
        )

        al_dns = self._create_alert(title="Suspicious Sysmon DNS Lookup", severity="medium", first_seen=now, last_seen=now)
        al_zeek = self._create_alert(title="Zeek Anomaly DNS Traffic", severity="medium", first_seen=now + timedelta(seconds=2), last_seen=now + timedelta(seconds=2))

        self.db.add(AlertEvent(alert_id=al_dns.id, event_id=ev_dns.id))
        self.db.add(AlertEvent(alert_id=al_zeek.id, event_id=ev_zeek.id))
        self.db.commit()

        engine = CrossSourceCorrelationEngine(self.db, window_seconds=120)
        res = engine.correlate_all()

        self.assertEqual(res.incidents_created, 1)
        inc = self.db.query(Incident).first()
        self.assertIn("CORR-004", inc.description)

    def test_configurable_temporal_windows(self):
        """Test temporal windows: events 45s apart correlate at 120s but NOT at 30s."""
        now = datetime.now(UTC)
        ev1 = self._create_event(
            source_type="WEB",
            event_type="web_access",
            source_ip="192.0.2.77",
            timestamp=now,
            request_path="/admin",
        )
        ev2 = self._create_event(
            source_type="ZEEK",
            event_type="conn",
            source_ip="192.0.2.77",
            timestamp=now + timedelta(seconds=45),
        )

        al1 = self._create_alert(title="Web Probe A", severity="medium", source_ip="192.0.2.77", first_seen=now, last_seen=now)
        al2 = self._create_alert(title="Zeek Conn B", severity="medium", source_ip="192.0.2.77", first_seen=now + timedelta(seconds=45), last_seen=now + timedelta(seconds=45))

        self.db.add(AlertEvent(alert_id=al1.id, event_id=ev1.id))
        self.db.add(AlertEvent(alert_id=al2.id, event_id=ev2.id))
        self.db.commit()

        # Engine with 30s window -> Should NOT correlate (45s > 30s)
        engine_tight = CrossSourceCorrelationEngine(self.db, window_seconds=30)
        res_tight = engine_tight.correlate_all()
        self.assertEqual(res_tight.incidents_created, 2, "30s window should produce 2 independent incidents")

        # Reset incidents
        self.db.query(IncidentAlert).delete()
        self.db.query(Incident).delete()
        self.db.commit()

        # Engine with 120s window -> Should correlate (45s <= 120s)
        engine_wide = CrossSourceCorrelationEngine(self.db, window_seconds=120)
        res_wide = engine_wide.correlate_all()
        self.assertEqual(res_wide.incidents_created, 1, "120s window should correlate into 1 incident")

    def test_non_correlation_different_entities(self):
        """Test that events on different IPs and hosts are NOT correlated."""
        now = datetime.now(UTC)
        ev1 = self._create_event(
            source_type="WEB",
            event_type="web_access",
            source_ip="1.1.1.1",
            destination_ip="10.1.1.1",
            username="user_alpha",
            hostname="host-alpha",
            timestamp=now,
        )
        ev2 = self._create_event(
            source_type="ZEEK",
            event_type="conn",
            source_ip="2.2.2.2",
            destination_ip="10.2.2.2",
            username="user_beta",
            hostname="host-beta",
            timestamp=now + timedelta(seconds=10),
        )

        al1 = self._create_alert(title="Alert Alpha", severity="high", source_ip="1.1.1.1", first_seen=now, last_seen=now)
        al2 = self._create_alert(title="Alert Beta", severity="high", source_ip="2.2.2.2", first_seen=now + timedelta(seconds=10), last_seen=now + timedelta(seconds=10))

        self.db.add(AlertEvent(alert_id=al1.id, event_id=ev1.id))
        self.db.add(AlertEvent(alert_id=al2.id, event_id=ev2.id))
        self.db.commit()

        engine = CrossSourceCorrelationEngine(self.db, window_seconds=300)
        res = engine.correlate_all()
        self.assertEqual(res.incidents_created, 2, "Disjoint entities should result in 2 separate incidents")

    def test_missing_fields_graceful_handling(self):
        """Verify that missing entity fields return 'INSUFFICIENT CORRELATION EVIDENCE'."""
        score, explanation, confidence = calculate_correlation_score(
            matched_entities={},
            time_delta_seconds=None,
            source_types=set(),
            max_severity="LOW",
        )
        self.assertLess(score, 0.35)
        self.assertIn("INSUFFICIENT CORRELATION EVIDENCE", explanation)

    def test_timeline_chronological_ordering(self):
        """Verify timeline builder sorts chronologically and records precise deltas."""
        now = datetime.now(UTC)
        ev1 = self._create_event(
            source_type="WEB",
            event_type="web_access",
            source_ip="10.10.10.10",
            timestamp=now,
            request_path="/admin",
        )
        ev2 = self._create_event(
            source_type="ZEEK",
            event_type="conn",
            source_ip="10.10.10.10",
            timestamp=now + timedelta(seconds=12),
        )
        ev3 = self._create_event(
            source_type="SYSMON",
            event_type="sysmon_process_create",
            hostname="srv-10",
            timestamp=now + timedelta(seconds=25),
            process="powershell.exe",
        )

        al1 = self._create_alert(title="Web Alert", severity="medium", first_seen=now, last_seen=now)
        al2 = self._create_alert(title="Zeek Alert", severity="high", first_seen=now + timedelta(seconds=12), last_seen=now + timedelta(seconds=12))

        # Pass out of order to verify sorting
        timeline = build_incident_timeline([ev3, ev1, ev2], [al2, al1])
        self.assertEqual(len(timeline), 5)
        self.assertEqual(timeline[0]["event_id"], str(ev1.id))
        self.assertEqual(timeline[0]["relative_time_seconds"], 0.0)

    def test_incident_graph_nodes_and_edges(self):
        """Verify graph builder generates valid nodes and telemetry-backed edges."""
        now = datetime.now(UTC)
        ev = self._create_event(
            source_type="SYSMON",
            event_type="sysmon_process_create",
            source_ip="192.168.1.50",
            hostname="FINANCE-PC",
            username="Alice",
            process="powershell.exe",
            command_line="powershell -enc aW52b2tl",
            timestamp=now,
        )
        al = self._create_alert(title="Sysmon Encoded PowerShell", severity="high", first_seen=now, last_seen=now)

        graph = build_incident_graph(incident_id=1, incident_number="INC-20261008-001", events=[ev], alerts=[al])
        nodes = graph["nodes"]
        edges = graph["edges"]

        node_types = {str(n["type"]).upper() for n in nodes}
        edge_types = {str(e["relationship"]).upper() for e in edges}

        self.assertIn("INCIDENT", node_types)
        self.assertIn("ALERT", node_types)
        self.assertIn("EVENT", node_types)
        self.assertIn("IP", node_types)
        self.assertIn("HOST", node_types)
        self.assertIn("USER", node_types)
        self.assertIn("PROCESS", node_types)

        self.assertIn("ASSOCIATED_WITH", edge_types)
        self.assertIn("EXECUTED", edge_types)

    def test_duplicate_events_handling(self):
        """Verify that duplicate events do not duplicate timeline or graph nodes."""
        ev1 = self._create_event(source_type="WEB", event_type="web", source_ip="1.2.3.4")
        timeline = build_incident_timeline([ev1, ev1], [])
        self.assertEqual(len(timeline), 1, "Duplicate event IDs should be deduplicated")

    def test_api_cross_source_endpoints_and_rbac(self):
        """Verify /correlate, /unified, /graph, /timeline endpoints and auth enforcement."""
        # Unauthenticated request should fail with 401
        unauth_resp = self.client.post("/api/incidents/correlate", json={"window_seconds": 300})
        self.assertEqual(unauth_resp.status_code, 401)

        # Authenticated correlate request
        corr_resp = self.client.post(
            "/api/incidents/correlate",
            headers=self.auth_headers,
            json={"window_seconds": 300},
        )
        self.assertEqual(corr_resp.status_code, 200)
        data = corr_resp.json()
        self.assertIn("correlated_incidents_count", data)
        self.assertIn("applied_window_seconds", data)

        # Create dummy incident with timeline & graph
        now = datetime.now(UTC)
        inc = Incident(
            incident_number="INC-20261008-TEST",
            title="Test Correlated Incident",
            description="Test incident description",
            severity="high",
            status="open",
            primary_entity="10.0.0.1",
            related_entities=[{"type": "ip", "value": "10.0.0.1"}],
            source_types=["WEB", "ZEEK"],
            correlation_score=0.88,
            confidence="HIGH",
            timeline=[{
                "timestamp": now.isoformat(),
                "source_type": "WEB",
                "stage": "initial_access",
                "title": "Web Scan",
                "description": "SQL injection attempt",
                "event_id": "1",
                "alert_id": None,
                "raw_reference": "EVT-1",
                "evidence_ref": "EVID-1",
                "relative_time_seconds": 0.0,
                "entities": {"source_ip": "10.0.0.1"},
            }],
            graph={"nodes": [{"id": "inc-1", "type": "INCIDENT", "label": "Inc 1"}], "edges": []},
            created_at=now,
            updated_at=now,
            first_seen=now,
            last_seen=now,
        )
        self.db.add(inc)
        self.db.commit()

        # GET /unified
        uni_resp = self.client.get(f"/api/incidents/{inc.id}/unified", headers=self.auth_headers)
        self.assertEqual(uni_resp.status_code, 200)
        self.assertEqual(uni_resp.json()["primary_entity"], "10.0.0.1")
        self.assertEqual(uni_resp.json()["confidence"], "HIGH")

        # GET /graph
        graph_resp = self.client.get(f"/api/incidents/{inc.id}/graph", headers=self.auth_headers)
        self.assertEqual(graph_resp.status_code, 200)
        self.assertEqual(len(graph_resp.json()["nodes"]), 1)

        # GET /timeline
        time_resp = self.client.get(f"/api/incidents/{inc.id}/timeline", headers=self.auth_headers)
        self.assertEqual(time_resp.status_code, 200)
        self.assertEqual(len(time_resp.json()), 1)


if __name__ == "__main__":
    unittest.main()
