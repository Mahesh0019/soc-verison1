"""
tests/test_sysmon_telemetry.py

Phase 5 Windows / Sysmon Endpoint Telemetry Comprehensive Test Suite:
1. Sysmon Parser Tests (Event IDs 1, 3, 5, 7, 11, 22 in XML and JSONL formats)
2. Missing field handling, malformed XML/JSON containment, oversized field bounds, timestamp normalization
3. Detection-as-Code metadata completeness for ENDPOINT-001 through ENDPOINT-005
4. Endpoint rule accuracy (positive condition triggers and negative suppression)
5. End-to-end replay API (/api/telemetry/sysmon/replay) with throughput & latency metrics
6. NormalizedEvent filtering by source_type=SYSMON
7. Distinct performance metrics verification (parser, ingestion, detection, and total SOC throughput)
8. Evidence package extraction for endpoint alerts
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

# Setup SQLite in-memory DB for test isolation before backend imports
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AUTO_CREATE_TABLES"] = "true"
os.environ["ENABLE_JUICE_SHOP_CONNECTOR"] = "false"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-phase5-sysmon"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.main import create_app
from app.models import Alert, DetectionRule, NormalizedEvent, User
from app.parsers.sysmon_parser import (
    normalize_sysmon_event,
    parse_sysmon_json,
    parse_sysmon_log,
    parse_sysmon_timestamp,
    parse_sysmon_xml,
)
from app.rules import endpoint_rules, evaluate_rules_for_events
from app.services.evidence_service import build_evidence_package, calculate_evidence_completeness
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users
from app.services.sysmon_service import ingest_sysmon_telemetry


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "sysmon"


class TestSysmonParser(unittest.TestCase):
    """Unit tests for Sysmon XML and JSON parser engine."""

    def test_01_parse_valid_event1_xml(self):
        """Verify Sysmon Event ID 1 (Process Create) XML parses with all core endpoint fields."""
        xml_file = FIXTURES_DIR / "event1_process_create.xml"
        content = xml_file.read_text(encoding="utf-8")
        events, errors = parse_sysmon_xml(content)

        self.assertEqual(len(errors), 0)
        self.assertEqual(len(events), 1)

        ev = events[0]
        self.assertEqual(ev["source_type"], "SYSMON")
        self.assertEqual(ev["source_name"], "Microsoft-Windows-Sysmon")
        self.assertEqual(ev["event_type"], "sysmon_process_create")
        self.assertEqual(ev["event_category"], "endpoint")
        self.assertEqual(ev["hostname"], "CORP-WKSTN-01.corp.local")
        self.assertEqual(ev["username"], "CORP\\jsmith")
        self.assertEqual(ev["process"], "cmd.exe")
        self.assertEqual(ev["image_path"], "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(ev["parent_process"], "explorer.exe")
        self.assertEqual(ev["process_id"], 4128)
        self.assertEqual(ev["parent_process_id"], 1024)
        self.assertEqual(ev["command_line"], "cmd.exe /c whoami")
        self.assertIn("SHA256=", ev["file_hash"])
        self.assertIn("Process Create: cmd.exe", ev["message"])

    def test_02_parse_valid_event3_xml(self):
        """Verify Sysmon Event ID 3 (Network Connection) XML parses network telemetry fields."""
        xml_file = FIXTURES_DIR / "event3_network_connect.xml"
        content = xml_file.read_text(encoding="utf-8")
        events, errors = parse_sysmon_xml(content)

        self.assertEqual(len(errors), 0)
        self.assertEqual(len(events), 1)

        ev = events[0]
        self.assertEqual(ev["event_type"], "sysmon_network_connection")
        self.assertEqual(ev["process"], "certutil.exe")
        self.assertEqual(ev["source_ip"], "10.0.0.15")
        self.assertEqual(ev["source_port"], 49152)
        self.assertEqual(ev["destination_ip"], "198.51.100.80")
        self.assertEqual(ev["destination_port"], 8080)
        self.assertEqual(ev["protocol"], "tcp")
        self.assertIn("Network Connection: certutil.exe", ev["message"])

    def test_03_parse_valid_event22_xml(self):
        """Verify Sysmon Event ID 22 (DNS Query) XML parses DNS fields."""
        xml_file = FIXTURES_DIR / "event22_dns_query.xml"
        content = xml_file.read_text(encoding="utf-8")
        events, errors = parse_sysmon_xml(content)

        self.assertEqual(len(errors), 0)
        self.assertEqual(len(events), 1)

        ev = events[0]
        self.assertEqual(ev["event_type"], "sysmon_dns_query")
        self.assertEqual(ev["process"], "powershell.exe")
        self.assertEqual(ev["dns_query"], "c2-stage.duckdns.org")
        self.assertEqual(ev["dns_response"], "::ffff:198.51.100.99;")

    def test_04_parse_jsonl_all_event_ids(self):
        """Verify JSON Lines format parses Event IDs 1, 3, 5, 7, 11, 22 correctly."""
        jsonl_file = FIXTURES_DIR / "sample_sysmon.jsonl"
        content = jsonl_file.read_text(encoding="utf-8")
        events, errors = parse_sysmon_json(content)

        self.assertEqual(len(errors), 0)
        self.assertEqual(len(events), 6)

        event_types = [e["event_type"] for e in events]
        self.assertIn("sysmon_process_create", event_types)
        self.assertIn("sysmon_network_connection", event_types)
        self.assertIn("sysmon_process_terminate", event_types)
        self.assertIn("sysmon_image_load", event_types)
        self.assertIn("sysmon_file_create", event_types)
        self.assertIn("sysmon_dns_query", event_types)

    def test_05_missing_fields_graceful_handling(self):
        """Verify event with sparse/missing fields maps safely to None without crashing."""
        sparse_json = json.dumps({"EventID": 1, "Image": "C:\\Windows\\notepad.exe"})
        events, errors = parse_sysmon_json(sparse_json)

        self.assertEqual(len(errors), 0)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["process"], "notepad.exe")
        self.assertIsNone(ev["command_line"])
        self.assertIsNone(ev["parent_process"])
        self.assertIsNone(ev["process_id"])
        self.assertIsNone(ev["file_hash"])
        self.assertIsNone(ev["source_ip"])

    def test_06_malformed_xml_containment(self):
        """Verify malformed XML does not crash the parser and produces a clean error diagnostic."""
        malformed_xml = "<Event><System><EventID>1</EventID></System><UnclosedTag>"
        events, errors = parse_sysmon_xml(malformed_xml)
        self.assertGreater(len(errors), 0)
        self.assertEqual(len(events), 0)

    def test_07_malformed_json_containment(self):
        """Verify malformed JSON does not crash the parser and logs the offending line."""
        bad_content = '{"EventID": 1, "Image": "cmd.exe"}\nINVALID_JSON_HERE\n{"EventID": 3, "Image": "edge.exe"}'
        events, errors = parse_sysmon_json(bad_content)
        self.assertEqual(len(events), 2)
        self.assertEqual(len(errors), 1)
        self.assertIn("Line 2", errors[0])

    def test_08_unknown_event_id_handling(self):
        """Verify unsupported or future Event IDs are safely parsed with fallback naming."""
        raw = {"EventID": 999, "Computer": "CORP-WKSTN-01", "Image": "C:\\Windows\\test.exe"}
        events, errors = parse_sysmon_json(json.dumps(raw))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "sysmon_event_999")

    def test_09_oversized_field_bounding(self):
        """Verify oversized fields are safely truncated to protect system and database bounds."""
        giant_cmd = "powershell.exe " + ("A" * 20000)
        raw = {"EventID": 1, "CommandLine": giant_cmd, "Image": "C:\\Windows\\" + ("B" * 5000)}
        events, errors = parse_sysmon_json(json.dumps(raw))
        self.assertEqual(len(events), 1)
        self.assertLessEqual(len(events[0]["command_line"]), 8192)
        self.assertLessEqual(len(events[0]["image_path"]), 1024)

    def test_10_timestamp_normalization(self):
        """Verify Sysmon timestamps normalize reliably across ISO, UtcTime, and epoch."""
        ts1 = parse_sysmon_timestamp("2026-10-08 08:30:00.123")
        self.assertEqual(ts1.year, 2026)
        self.assertEqual(ts1.minute, 30)

        ts2 = parse_sysmon_timestamp("2026-10-08T08:30:00.000000000Z")
        self.assertEqual(ts2.year, 2026)

        ts3 = parse_sysmon_timestamp(1791457800.0)
        self.assertIsInstance(ts3, datetime)

        # Invalid timestamp fallback
        ts_bad = parse_sysmon_timestamp("not-a-timestamp")
        self.assertIsInstance(ts_bad, datetime)


class TestEndpointDetection(unittest.TestCase):
    """Detection-as-Code metadata and rule accuracy tests for ENDPOINT-001 through ENDPOINT-005."""

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

    def test_11_detection_metadata_completeness(self):
        """Verify ENDPOINT-001 through ENDPOINT-005 adhere strictly to the Detection-as-Code schema."""
        rules = endpoint_rules()
        self.assertEqual(len(rules), 5)

        required_keys = [
            "rule_id",
            "name",
            "description",
            "category",
            "severity",
            "version",
            "status",
            "source",
            "owner",
            "mitre_technique",
            "confidence",
            "false_positive_notes",
            "expected_data_source",
            "enabled",
            "conditions_json",
            "time_window_minutes",
            "threshold",
            "test_cases_json",
        ]

        for rule in rules:
            for key in required_keys:
                self.assertIn(key, rule, f"Rule {rule.get('rule_id')} missing key {key}")
            self.assertTrue(rule["rule_id"].startswith("ENDPOINT-"))
            self.assertEqual(rule["source"], "sysmon")
            self.assertIn("positive", rule["test_cases_json"])
            self.assertIn("negative", rule["test_cases_json"])
            self.assertIsInstance(rule["confidence"], float)
            self.assertGreater(rule["confidence"], 0.70)

    def test_12_endpoint_001_suspicious_process_execution(self):
        """Verify ENDPOINT-001 triggers on encoded command lines and stays quiet on normal executions."""
        db = self.TestingSessionLocal()
        try:
            now = datetime.now(UTC)
            # Positive: Base64 encoded PowerShell
            pos_event = NormalizedEvent(
                timestamp=now,
                source_type="SYSMON",
                hostname="CORP-WKSTN-01",
                process="powershell.exe",
                command_line="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3...",
                event_type="sysmon_process_create",
                event_category="endpoint",
                severity="high",
                message="Process Create: powershell.exe -enc SQBFAFgA...",
            )
            # Negative: Legitimate admin PowerShell
            neg_event = NormalizedEvent(
                timestamp=now,
                source_type="SYSMON",
                hostname="CORP-WKSTN-01",
                process="powershell.exe",
                command_line="powershell.exe Get-Service -Name Spooler",
                event_type="sysmon_process_create",
                event_category="endpoint",
                severity="low",
                message="Process Create: powershell.exe Get-Service",
            )
            db.add_all([pos_event, neg_event])
            db.flush()

            evaluate_rules_for_events(db, [pos_event, neg_event], auto_correlate=False)
            alerts = db.query(Alert).filter(Alert.title == "Suspicious process execution").all()
            self.assertEqual(len(alerts), 1)
        finally:
            db.close()

    def test_13_endpoint_002_parent_child_relationship(self):
        """Verify ENDPOINT-002 triggers when web server w3wp.exe spawns cmd.exe."""
        db = self.TestingSessionLocal()
        try:
            now = datetime.now(UTC)
            pos_event = NormalizedEvent(
                timestamp=now,
                source_type="SYSMON",
                hostname="CORP-WEB-01",
                process="cmd.exe",
                parent_process="w3wp.exe",
                event_type="sysmon_process_create",
                event_category="endpoint",
                severity="critical",
                message="Process Create: cmd.exe by w3wp.exe",
            )
            neg_event = NormalizedEvent(
                timestamp=now,
                source_type="SYSMON",
                hostname="CORP-WKSTN-01",
                process="cmd.exe",
                parent_process="explorer.exe",
                event_type="sysmon_process_create",
                event_category="endpoint",
                severity="low",
                message="Process Create: cmd.exe by explorer.exe",
            )
            db.add_all([pos_event, neg_event])
            db.flush()

            evaluate_rules_for_events(db, [pos_event, neg_event], auto_correlate=False)
            alerts = db.query(Alert).filter(Alert.title == "Suspicious parent-child process relationship").all()
            self.assertEqual(len(alerts), 1)
        finally:
            db.close()

    def test_14_endpoint_003_process_network_connection(self):
        """Verify ENDPOINT-003 triggers on certutil connecting to port 8080."""
        db = self.TestingSessionLocal()
        try:
            now = datetime.now(UTC)
            pos_event = NormalizedEvent(
                timestamp=now,
                source_type="SYSMON",
                hostname="CORP-WKSTN-01",
                process="certutil.exe",
                source_ip="10.0.0.15",
                destination_ip="198.51.100.80",
                source_port=49200,
                destination_port=8080,
                protocol="tcp",
                event_type="sysmon_network_connection",
                event_category="endpoint",
                severity="high",
                message="Network Connection: certutil.exe to 198.51.100.80:8080",
            )
            neg_event = NormalizedEvent(
                timestamp=now,
                source_type="SYSMON",
                hostname="CORP-WKSTN-01",
                process="msedge.exe",
                source_ip="10.0.0.15",
                destination_ip="198.51.100.1",
                source_port=49201,
                destination_port=443,
                protocol="tcp",
                event_type="sysmon_network_connection",
                event_category="endpoint",
                severity="low",
                message="Network Connection: msedge.exe to 198.51.100.1:443",
            )
            db.add_all([pos_event, neg_event])
            db.flush()

            evaluate_rules_for_events(db, [pos_event, neg_event], auto_correlate=False)
            alerts = db.query(Alert).filter(Alert.title == "Suspicious process network connection").all()
            self.assertEqual(len(alerts), 1)
        finally:
            db.close()

    def test_15_endpoint_004_suspicious_dns(self):
        """Verify ENDPOINT-004 triggers on query for duckdns.org dynamic DNS."""
        db = self.TestingSessionLocal()
        try:
            now = datetime.now(UTC)
            pos_event = NormalizedEvent(
                timestamp=now,
                source_type="SYSMON",
                hostname="CORP-WKSTN-01",
                process="powershell.exe",
                dns_query="test-beacon.duckdns.org",
                event_type="sysmon_dns_query",
                event_category="endpoint",
                severity="medium",
                message="DNS Query: test-beacon.duckdns.org by powershell.exe",
            )
            neg_event = NormalizedEvent(
                timestamp=now,
                source_type="SYSMON",
                hostname="CORP-WKSTN-01",
                process="msedge.exe",
                dns_query="www.microsoft.com",
                event_type="sysmon_dns_query",
                event_category="endpoint",
                severity="low",
                message="DNS Query: www.microsoft.com by msedge.exe",
            )
            db.add_all([pos_event, neg_event])
            db.flush()

            evaluate_rules_for_events(db, [pos_event, neg_event], auto_correlate=False)
            alerts = db.query(Alert).filter(Alert.title == "Suspicious DNS activity").all()
            self.assertEqual(len(alerts), 1)
        finally:
            db.close()

    def test_16_endpoint_005_suspicious_file_creation(self):
        """Verify ENDPOINT-005 triggers when PowerShell creates an executable in Temp."""
        db = self.TestingSessionLocal()
        try:
            now = datetime.now(UTC)
            pos_event = NormalizedEvent(
                timestamp=now,
                source_type="SYSMON",
                hostname="CORP-WKSTN-01",
                process="powershell.exe",
                raw_reference="C:\\Users\\jsmith\\AppData\\Local\\Temp\\dropper.exe",
                event_type="sysmon_file_create",
                event_category="endpoint",
                severity="high",
                message="File Create: C:\\Users\\jsmith\\AppData\\Local\\Temp\\dropper.exe by powershell.exe",
            )
            neg_event = NormalizedEvent(
                timestamp=now,
                source_type="SYSMON",
                hostname="CORP-WKSTN-01",
                process="devenv.exe",
                raw_reference="C:\\Program Files\\App\\app.dll",
                event_type="sysmon_file_create",
                event_category="endpoint",
                severity="low",
                message="File Create: C:\\Program Files\\App\\app.dll by devenv.exe",
            )
            db.add_all([pos_event, neg_event])
            db.flush()

            evaluate_rules_for_events(db, [pos_event, neg_event], auto_correlate=False)
            alerts = db.query(Alert).filter(Alert.title == "Suspicious executable/file creation").all()
            self.assertEqual(len(alerts), 1)
        finally:
            db.close()


class TestSysmonApiIntegration(unittest.TestCase):
    """API endpoints and performance metrics tracking tests."""

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

        from app.database.session import get_db

        cls.app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(cls.app)

        login_resp = cls.client.post("/api/auth/login", json={"username": "admin", "password": "AdminPass123!"})
        cls.token = login_resp.json()["access_token"]
        cls.admin_headers = {"Authorization": f"Bearer {cls.token}"}

    def test_17_api_sysmon_replay_endpoint(self):
        """Verify /api/telemetry/sysmon/replay endpoint processes payload with comprehensive metrics."""
        xml_file = FIXTURES_DIR / "event1_process_create.xml"
        raw_xml = xml_file.read_text(encoding="utf-8")

        resp = self.client.post(
            "/api/telemetry/sysmon/replay",
            json={"mode": "REPLAY", "raw_content": raw_xml},
            headers=self.admin_headers,
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertEqual(data["mode"], "REPLAY")
        self.assertEqual(data["source_type"], "SYSMON")
        self.assertEqual(data["events_accepted"], 1)
        self.assertEqual(data["events_processed"], 1)
        self.assertGreater(data["throughput_eps"], 0.0)
        self.assertGreaterEqual(data["average_latency_ms"], 0.0)

    def test_18_api_event_listing_with_sysmon_source_filter(self):
        """Verify /api/events filter by source_type=SYSMON returns only Sysmon telemetry."""
        resp = self.client.get("/api/events?source_type=SYSMON&page_size=50", headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        for item in data.get("items", []):
            self.assertEqual(item["source_type"], "SYSMON")

    def test_19_performance_metrics_distinct(self):
        """Verify parser, ingestion, detection, and total SOC throughput are tracked distinctly."""
        db = self.TestingSessionLocal()
        try:
            jsonl_file = FIXTURES_DIR / "sample_sysmon.jsonl"
            content = jsonl_file.read_text(encoding="utf-8")
            result = ingest_sysmon_telemetry(db, content=content, mode="REPLAY")

            self.assertIn("parser_throughput_eps", result)
            self.assertIn("ingestion_throughput_eps", result)
            self.assertIn("detection_throughput_eps", result)
            self.assertIn("total_soc_throughput_eps", result)
            self.assertIn("parse_time_ms", result)
            self.assertIn("db_persistence_time_ms", result)
            self.assertIn("detection_latency_ms", result)
            self.assertEqual(result["events_accepted"], 6)
        finally:
            db.close()

    def test_20_sysmon_evidence_package_completeness(self):
        """Verify evidence package generated for an endpoint alert includes host/process entity context."""
        db = self.TestingSessionLocal()
        try:
            now = datetime.now(UTC)
            ev = NormalizedEvent(
                timestamp=now,
                source_type="SYSMON",
                hostname="CORP-WKSTN-99",
                process="powershell.exe",
                command_line="powershell.exe -enc SQBFAFgA...",
                event_type="sysmon_process_create",
                event_category="endpoint",
                severity="high",
                message="Suspicious execution test",
            )
            db.add(ev)
            db.flush()

            evaluate_rules_for_events(db, [ev], auto_correlate=False)
            alert = db.query(Alert).filter(Alert.title == "Suspicious process execution").order_by(Alert.id.desc()).first()
            self.assertIsNotNone(alert)

            package = build_evidence_package(db, alert)
            comp_score = calculate_evidence_completeness(package)
            self.assertGreaterEqual(comp_score, 0.70)
            self.assertGreater(len(package), 0)

            # Check that entity context contains the endpoint host
            entity_items = [i for i in package if i.evidence_type == "entity_context"]
            self.assertGreater(len(entity_items), 0)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
