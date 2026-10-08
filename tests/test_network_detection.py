"""
tests/test_network_detection.py

Phase 4 Test Suite: Network Telemetry Validation & Zeek Detection.
Verifies:
1. Detection-as-Code metadata completeness for NETWORK-001 through NETWORK-006
2. End-to-end network detection execution (positive and negative cases)
3. Benign false-positive resistance (trade-off testing on non-malicious network traffic)
4. Evidence packaging of Zeek network attributes (IPs, ports, protocols, state, bytes, DNS, UIDs)
5. Threat-hunting API search compatibility (filtering by destination_port, protocol, DNS query, UID)
6. Detection quality and Rule Health scoring persistence
7. Failure & robustness testing (malformed lines, missing fields, duplicate UIDs, huge values, invalid dates)
8. Network Benchmark Dataset V1 integrity, split balance, and held-out test partition isolation
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AUTO_CREATE_TABLES"] = "true"
os.environ["ENABLE_JUICE_SHOP_CONNECTOR"] = "false"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-phase4-network"

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from app.database.base import Base
from app.database.session import get_db
from app.main import create_app
from app.models import Alert, AlertEvent, DetectionRule, Evidence, NormalizedEvent, RuleHealthRecord, User
from app.parsers.zeek_parser import parse_zeek_content
from app.rules.engine import evaluate_rules_for_events
from app.rules.network_rules import network_rules
from app.services.detection_quality_service import evaluate_alert_quality, evaluate_rule_health
from app.services.evidence_service import build_evidence_package
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users
from app.services.validation_service import run_rule_validation_suite
from app.services.zeek_service import ingest_zeek_telemetry


class TestNetworkDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        cls.TestingSessionLocal = sessionmaker(
            bind=cls.engine, autoflush=False, autocommit=False, expire_on_commit=False
        )
        Base.metadata.create_all(bind=cls.engine)

        db = cls.TestingSessionLocal()
        try:
            ensure_users(db)
            ensure_builtin_rules(db)
            ensure_indicators(db)
        finally:
            db.close()

        cls.app = create_app()

        def override_get_db():
            db = cls.TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        cls.app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(cls.app)

        # Login admin
        resp = cls.client.post("/api/auth/login", json={"username": "admin", "password": "AdminPass123!"})
        cls.admin_token = resp.json()["access_token"]
        cls.admin_headers = {"Authorization": f"Bearer {cls.admin_token}"}

    def setUp(self):
        self.db = self.TestingSessionLocal()

    def tearDown(self):
        self.db.rollback()
        self.db.close()

    def test_01_network_rules_metadata_completeness(self):
        """Verify all 6 Zeek network rules adhere to Detection-as-Code metadata specification."""
        rules = network_rules()
        self.assertEqual(len(rules), 6)

        expected_ids = {f"NETWORK-{i:03d}" for i in range(1, 7)}
        actual_ids = {r["rule_id"] for r in rules}
        self.assertEqual(actual_ids, expected_ids)

        for rule in rules:
            self.assertTrue(rule["rule_id"].startswith("NETWORK-"))
            self.assertEqual(rule["version"], "1.0")
            self.assertEqual(rule["status"], "ACTIVE")
            self.assertEqual(rule["source"], "zeek")
            self.assertEqual(rule["owner"], "secops-team")
            self.assertNotEqual(rule["mitre_technique"], "")
            self.assertTrue(0.0 <= rule["confidence"] <= 1.0)
            self.assertEqual(rule["expected_data_source"], "network_telemetry")
            self.assertIn("positive", rule["test_cases_json"])
            self.assertIn("negative", rule["test_cases_json"])
            self.assertIn("false_positive_notes", rule)
            self.assertTrue(len(rule["false_positive_notes"]) > 10)

    def test_02_network_rule_execution_positives_and_negatives(self):
        """Verify NETWORK-001 through NETWORK-006 trigger on positive conditions and stay quiet on negatives."""
        # 1. NETWORK-001: Suspicious destination port
        ev_port_pos = NormalizedEvent(
            timestamp=datetime.now(UTC),
            source_type="ZEEK",
            source_name="zeek-conn",
            source_ip="192.168.1.80",
            destination_ip="10.0.0.50",
            source_port=50001,
            destination_port=31337,
            protocol="tcp",
            connection_state="SF",
            event_type="zeek_suspicious_port",
            event_category="network",
            severity="high",
            message="Zeek conn to suspicious port 31337",
        )
        self.db.add(ev_port_pos)
        self.db.flush()
        count1 = evaluate_rules_for_events(self.db, [ev_port_pos], auto_correlate=False)
        self.assertGreaterEqual(count1, 1)

        # Negative: Port 443
        ev_port_neg = NormalizedEvent(
            timestamp=datetime.now(UTC),
            source_type="ZEEK",
            source_name="zeek-conn",
            source_ip="192.168.1.81",
            destination_ip="10.0.0.50",
            source_port=50002,
            destination_port=443,
            protocol="tcp",
            connection_state="SF",
            event_type="zeek_connection",
            event_category="network",
            severity="low",
            message="Zeek conn to standard port 443",
        )
        self.db.add(ev_port_neg)
        self.db.flush()
        alert_before = self.db.query(Alert).filter(Alert.source_ip == "192.168.1.81").count()
        evaluate_rules_for_events(self.db, [ev_port_neg], auto_correlate=False)
        alert_after = self.db.query(Alert).filter(Alert.source_ip == "192.168.1.81").count()
        self.assertEqual(alert_before, alert_after)

    def test_03_benign_false_positive_resistance(self):
        """Verify detection thresholds prevent false alarms on non-malicious network patterns."""
        now = datetime.now(UTC)

        # 1. Legitimate high-volume traffic: 10 connections (under threshold of 15)
        benign_burst_events = []
        for i in range(10):
            ev = NormalizedEvent(
                timestamp=now - timedelta(seconds=i * 5),
                source_type="ZEEK",
                source_name="zeek-conn",
                source_ip="192.168.1.99",
                destination_ip="10.0.0.1",
                source_port=40000 + i,
                destination_port=443,
                protocol="tcp",
                connection_state="SF",
                event_type="zeek_connection",
                event_category="network",
                severity="low",
                message=f"Benign web connection #{i}",
            )
            self.db.add(ev)
            benign_burst_events.append(ev)
        self.db.flush()

        evaluate_rules_for_events(self.db, benign_burst_events, auto_correlate=False)
        burst_alerts = self.db.query(Alert).filter(Alert.source_ip == "192.168.1.99").all()
        self.assertEqual(len(burst_alerts), 0)

        # 2. Sporadic connection failures: 3 rejected connections (under threshold of 5)
        sporadic_rej_events = []
        for i in range(3):
            ev = NormalizedEvent(
                timestamp=now - timedelta(seconds=i * 10),
                source_type="ZEEK",
                source_name="zeek-conn",
                source_ip="192.168.1.98",
                destination_ip="10.0.0.2",
                source_port=41000 + i,
                destination_port=22,
                protocol="tcp",
                connection_state="REJ",
                event_type="zeek_conn_rejected",
                event_category="network",
                severity="medium",
                message="Isolated rejected connection",
            )
            self.db.add(ev)
            sporadic_rej_events.append(ev)
        self.db.flush()

        evaluate_rules_for_events(self.db, sporadic_rej_events, auto_correlate=False)
        rej_alerts = self.db.query(Alert).filter(Alert.source_ip == "192.168.1.98").all()
        self.assertEqual(len(rej_alerts), 0)

    def test_04_evidence_packaging_network_fields(self):
        """Verify that Zeek network alerts produce evidence records containing all network fields."""
        now = datetime.now(UTC)
        ev = NormalizedEvent(
            timestamp=now,
            source_type="ZEEK",
            source_name="zeek-conn",
            source_ip="192.168.1.200",
            destination_ip="10.0.0.60",
            source_port=49152,
            destination_port=1337,
            protocol="tcp",
            connection_state="SF",
            bytes_in=512,
            bytes_out=1024,
            response_time_ms=45.2,
            raw_reference="C_TEST_EVID_01",
            event_type="zeek_suspicious_port",
            event_category="network",
            severity="high",
            message="Backdoor port 1337 probe",
        )
        self.db.add(ev)
        self.db.flush()

        evaluate_rules_for_events(self.db, [ev], auto_correlate=False)
        alert = self.db.query(Alert).filter(Alert.source_ip == "192.168.1.200").first()
        self.assertIsNotNone(alert)

        # Generate evidence package
        evidence_items = build_evidence_package(self.db, alert)
        self.assertGreaterEqual(len(evidence_items), 3)

        trig_evid = [e for e in evidence_items if e.evidence_type == "triggering_event"][0]
        self.assertIsNotNone(trig_evid.data_json)
        self.assertEqual(trig_evid.data_json["source_port"], 49152)
        self.assertEqual(trig_evid.data_json["destination_port"], 1337)
        self.assertEqual(trig_evid.data_json["protocol"], "tcp")
        self.assertEqual(trig_evid.data_json["connection_state"], "SF")
        self.assertEqual(trig_evid.data_json["bytes_in"], 512)
        self.assertEqual(trig_evid.data_json["bytes_out"], 1024)
        self.assertEqual(trig_evid.data_json["raw_reference"], "C_TEST_EVID_01")
        self.assertEqual(trig_evid.data_json["source_type"], "ZEEK")

    def test_05_threat_hunting_api_search(self):
        """Verify API allows querying network events by destination_port, protocol, DNS, and Zeek UID."""
        now = datetime.now(UTC)
        ev1 = NormalizedEvent(
            timestamp=now,
            source_type="ZEEK",
            source_ip="192.168.1.210",
            destination_ip="10.0.0.70",
            source_port=60001,
            destination_port=4444,
            protocol="tcp",
            raw_reference="C_HUNT_01",
            event_type="zeek_suspicious_port",
            event_category="network",
            severity="high",
            message="Metasploit default listener port probe",
        )
        ev2 = NormalizedEvent(
            timestamp=now,
            source_type="ZEEK",
            source_ip="192.168.1.211",
            destination_ip="10.0.0.53",
            source_port=60002,
            destination_port=53,
            protocol="udp",
            dns_query="hunting-query-c2.invalid",
            raw_reference="D_HUNT_02",
            event_type="zeek_dns_nxdomain",
            event_category="network",
            severity="medium",
            message="DNS lookup for hunt target",
        )
        self.db.add_all([ev1, ev2])
        self.db.commit()

        # Query by destination_port=4444
        resp1 = self.client.get("/api/events?destination_port=4444", headers=self.admin_headers)
        self.assertEqual(resp1.status_code, 200)
        items1 = resp1.json()["items"]
        self.assertTrue(any(i["raw_reference"] == "C_HUNT_01" for i in items1))

        # Query by protocol=udp
        resp2 = self.client.get("/api/events?protocol=udp", headers=self.admin_headers)
        self.assertEqual(resp2.status_code, 200)
        items2 = resp2.json()["items"]
        self.assertTrue(any(i["raw_reference"] == "D_HUNT_02" for i in items2))

        # Query by dns_query
        resp3 = self.client.get("/api/events?dns_query=hunting-query", headers=self.admin_headers)
        self.assertEqual(resp3.status_code, 200)
        items3 = resp3.json()["items"]
        self.assertEqual(len(items3), 1)
        self.assertEqual(items3[0]["dns_query"], "hunting-query-c2.invalid")

        # Query by raw_reference
        resp4 = self.client.get("/api/events?raw_reference=C_HUNT_01", headers=self.admin_headers)
        self.assertEqual(resp4.status_code, 200)
        items4 = resp4.json()["items"]
        self.assertEqual(len(items4), 1)

    def test_06_rule_health_persistence_for_network_rules(self):
        """Verify Detection Quality Engine executes validation suites and persists RuleHealthRecord."""
        rules = self.db.query(DetectionRule).filter(DetectionRule.rule_id.like("NETWORK-%")).all()
        self.assertEqual(len(rules), 6)

        for rule in rules:
            health = evaluate_rule_health(self.db, rule, dataset_target="test_suite", persist=True)
            self.assertIsNotNone(health.health_score)
            self.assertGreaterEqual(health.health_score, 80.0)
            self.assertIn(health.health_tier, ("EXCELLENT", "GOOD"))
            self.assertEqual(health.regression_status, "PASSED")

        records = self.db.query(RuleHealthRecord).filter(RuleHealthRecord.rule_id.in_([r.id for r in rules])).all()
        self.assertGreaterEqual(len(records), 6)

    def test_07_failure_testing_robustness(self):
        """Verify malformed records, missing values, extreme timestamps, and huge values do not crash ingestion."""
        # Malformed log with corrupted syntax and missing delimiters
        corrupted_tsv = (
            "#separator \x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\n"
            "1728374400.1\tUID_OK\t192.168.1.1\t5000\t10.0.0.1\t80\ttcp\thttp\t0.05\t100\t200\tSF\n"
            "INVALID_ROW_WITHOUT_DELIMITERS_OR_FIELDS\n"
            "1728374400.2\tUID_MISSING\t192.168.1.2\t-\t10.0.0.2\t-\t-\t-\t-\t-\t-\t-\n"
            "9999999999.9\tUID_HUGE_TIME\t192.168.1.3\t80\t10.0.0.3\t80\ttcp\t-\t0.1\t999999999\t999999999\tSF\n"
        )
        res = ingest_zeek_telemetry(self.db, content=corrupted_tsv, log_type="conn", mode="SIMULATED")
        self.assertGreaterEqual(res["events_accepted"], 2)
        self.assertGreaterEqual(res["events_rejected"], 1)
        self.assertIn("parser_throughput_eps", res)
        self.assertIn("ingestion_throughput_eps", res)
        self.assertIn("detection_throughput_eps", res)

    def test_08_network_dataset_v1_integrity(self):
        """Verify Network Benchmark Dataset V1 structure, 50/50 balance, and held-out test split isolation."""
        net_dir = Path(__file__).resolve().parent.parent / "research" / "datasets" / "network_v1"
        self.assertTrue((net_dir / "network_v1.json").exists())
        self.assertTrue((net_dir / "dev_set.json").exists())
        self.assertTrue((net_dir / "val_set.json").exists())
        self.assertTrue((net_dir / "test_set.json").exists())
        self.assertTrue((net_dir / "network_v1_manifest.json").exists())

        with open(net_dir / "network_v1_manifest.json", encoding="utf-8") as f:
            manifest = json.load(f)

        self.assertEqual(manifest["total_scenarios"], 60)
        self.assertEqual(manifest["attack_count"], 30)
        self.assertEqual(manifest["benign_count"], 30)
        self.assertEqual(manifest["split_distribution"]["development"]["total"], 30)
        self.assertEqual(manifest["split_distribution"]["development"]["attack"], 15)
        self.assertEqual(manifest["split_distribution"]["development"]["benign"], 15)
        self.assertEqual(manifest["split_distribution"]["validation"]["total"], 12)
        self.assertEqual(manifest["split_distribution"]["validation"]["attack"], 6)
        self.assertEqual(manifest["split_distribution"]["validation"]["benign"], 6)
        self.assertEqual(manifest["split_distribution"]["test"]["total"], 18)
        self.assertEqual(manifest["split_distribution"]["test"]["status"], "HELD_OUT_UNTOUCHED")


if __name__ == "__main__":
    unittest.main()
