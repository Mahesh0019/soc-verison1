"""
tests/test_zeek_telemetry.py

Phase 3 Test Suite: Multi-Source Telemetry Foundation & Zeek Ingestion.
Verifies:
- conn.log parsing (TSV and JSON)
- http.log parsing (TSV and JSON)
- dns.log parsing (TSV and JSON)
- Multi-source normalization & field extraction
- Missing field handling (-)
- Malformed line safety (non-crashing)
- Duplicate event tracking
- Database persistence & relations
- API replay & source classification endpoints
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AUTO_CREATE_TABLES"] = "true"
os.environ["ENABLE_JUICE_SHOP_CONNECTOR"] = "false"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-phase3-zeek"

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from app.database.base import Base
from app.database.session import get_db
from app.main import create_app
from app.models import NormalizedEvent, RawLog, TelemetrySourceType
from app.parsers.zeek_parser import (
    normalize_zeek_conn,
    normalize_zeek_dns,
    normalize_zeek_http,
    parse_zeek_content,
    parse_zeek_json,
    parse_zeek_tsv,
)
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users
from app.services.zeek_service import ingest_zeek_telemetry


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "zeek"


class TestZeekTelemetry(unittest.TestCase):
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

    def test_01_parse_zeek_conn_tsv(self):
        """Verify parsing and normalization of Zeek conn.log TSV fixture."""
        tsv_path = FIXTURES_DIR / "conn.log"
        content = tsv_path.read_text(encoding="utf-8")

        events, errors, stats = parse_zeek_tsv(content, forced_type="conn")
        self.assertGreaterEqual(stats["processed"], 6)
        self.assertGreaterEqual(stats["accepted"], 5)
        self.assertGreaterEqual(stats["rejected"], 1)  # Malformed row rejected safely
        self.assertGreaterEqual(stats["duplicated"], 1)  # Duplicate C_CONN_001 detected

        # Verify first normalized connection
        ev1 = events[0]
        self.assertEqual(ev1["source_type"], "ZEEK")
        self.assertEqual(ev1["source_name"], "zeek-conn")
        self.assertEqual(ev1["source_ip"], "192.168.1.50")
        self.assertEqual(ev1["destination_ip"], "10.0.0.1")
        self.assertEqual(ev1["source_port"], 49152)
        self.assertEqual(ev1["destination_port"], 80)
        self.assertEqual(ev1["protocol"], "tcp")
        self.assertEqual(ev1["connection_state"], "SF")
        self.assertEqual(ev1["bytes_in"], 152)
        self.assertEqual(ev1["bytes_out"], 1024)
        self.assertIsNotNone(ev1["response_time_ms"])
        self.assertEqual(ev1["raw_reference"], "C_CONN_001")

        # Verify rejected connection
        rej_ev = [e for e in events if e.get("raw_reference") == "C_CONN_003"][0]
        self.assertEqual(rej_ev["connection_state"], "REJ")
        self.assertEqual(rej_ev["event_type"], "zeek_conn_rejected")
        self.assertEqual(rej_ev["severity"], "medium")
        self.assertIsNone(rej_ev["bytes_in"])  # '-' maps to None

    def test_02_parse_zeek_conn_json(self):
        """Verify parsing of Zeek conn.log JSON lines format."""
        json_path = FIXTURES_DIR / "conn.json"
        content = json_path.read_text(encoding="utf-8")

        events, errors, stats = parse_zeek_json(content, forced_type="conn")
        self.assertGreaterEqual(stats["accepted"], 3)
        self.assertGreaterEqual(stats["rejected"], 1)  # Corrupted JSON line handled safely

        ev = events[0]
        self.assertEqual(ev["source_ip"], "192.168.1.50")
        self.assertEqual(ev["protocol"], "tcp")
        self.assertEqual(ev["source_name"], "zeek-conn")

    def test_03_parse_zeek_http_tsv_and_json(self):
        """Verify parsing and normalization of Zeek http.log (TSV and JSON)."""
        tsv_path = FIXTURES_DIR / "http.log"
        content = tsv_path.read_text(encoding="utf-8")
        events_tsv, errors_tsv, stats_tsv = parse_zeek_tsv(content, forced_type="http")

        self.assertGreaterEqual(stats_tsv["accepted"], 4)
        self.assertGreaterEqual(stats_tsv["rejected"], 1)

        ev_http = events_tsv[0]
        self.assertEqual(ev_http["source_type"], "ZEEK")
        self.assertEqual(ev_http["source_name"], "zeek-http")
        self.assertEqual(ev_http["http_method"], "GET")
        self.assertEqual(ev_http["hostname"], "example.com")
        self.assertEqual(ev_http["request_path"], "/index.html")
        self.assertEqual(ev_http["status_code"], 200)

        # Check sensitive path
        ev_admin = [e for e in events_tsv if e.get("request_path") == "/admin/config"][0]
        self.assertEqual(ev_admin["event_type"], "sensitive_path_access")
        self.assertEqual(ev_admin["status_code"], 403)

        # JSON HTTP test
        json_path = FIXTURES_DIR / "http.json"
        events_json, _, stats_json = parse_zeek_json(json_path.read_text(encoding="utf-8"), forced_type="http")
        self.assertEqual(stats_json["accepted"], 3)
        self.assertEqual(events_json[1]["request_path"], "/rest/user/login")
        self.assertEqual(events_json[1]["bytes_in"], 64)

    def test_04_parse_zeek_dns_tsv_and_json(self):
        """Verify parsing and normalization of Zeek dns.log (TSV and JSON)."""
        tsv_path = FIXTURES_DIR / "dns.log"
        events, errors, stats = parse_zeek_tsv(tsv_path.read_text(encoding="utf-8"), forced_type="dns")

        self.assertGreaterEqual(stats["accepted"], 3)
        self.assertGreaterEqual(stats["rejected"], 1)

        ev_dns = events[0]
        self.assertEqual(ev_dns["source_type"], "ZEEK")
        self.assertEqual(ev_dns["source_name"], "zeek-dns")
        self.assertEqual(ev_dns["dns_query"], "api.example.com")
        self.assertIn("93.184.216.34", ev_dns["dns_response"])

        # Check NXDOMAIN
        ev_nx = [e for e in events if e.get("dns_query") == "evil-c2-domain.invalid"][0]
        self.assertEqual(ev_nx["event_type"], "zeek_dns_nxdomain")
        self.assertEqual(ev_nx["severity"], "medium")

        # JSON DNS test
        json_path = FIXTURES_DIR / "dns.json"
        events_json, _, stats_json = parse_zeek_json(json_path.read_text(encoding="utf-8"), forced_type="dns")
        self.assertEqual(stats_json["accepted"], 2)
        self.assertEqual(events_json[0]["dns_query"], "api.example.com")

    def test_05_database_persistence_and_relations(self):
        """Verify ingest_zeek_telemetry persists to database with correct schema fields."""
        db = self.TestingSessionLocal()
        try:
            tsv_path = FIXTURES_DIR / "conn.log"
            content = tsv_path.read_text(encoding="utf-8")

            res = ingest_zeek_telemetry(
                db,
                content=content,
                log_type="conn",
                mode="REPLAY",
                file_name="test_conn.log",
            )
            self.assertIn("raw_log_id", res)
            self.assertGreaterEqual(res["events_accepted"], 5)
            self.assertGreater(res["throughput_eps"], 0.0)

            # Query database records
            raw_log = db.get(RawLog, res["raw_log_id"])
            self.assertIsNotNone(raw_log)
            self.assertEqual(raw_log.source_type, "ZEEK_CONN_REPLAY")

            events = db.query(NormalizedEvent).filter(NormalizedEvent.raw_log_id == raw_log.id).all()
            self.assertEqual(len(events), res["events_accepted"])

            sample = events[0]
            self.assertEqual(sample.source_type, "ZEEK")
            self.assertEqual(sample.source_name, "zeek-conn")
            self.assertIsNotNone(sample.source_port)
            self.assertIsNotNone(sample.destination_port)
            self.assertIsNotNone(sample.protocol)
            self.assertIsNotNone(sample.connection_state)
        finally:
            db.close()

    def test_06_api_telemetry_sources_classification(self):
        """Verify /api/telemetry/sources returns official classification and status."""
        resp = self.client.get("/api/telemetry/sources", headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("ZEEK", data["sources"])
        self.assertIn("SYSMON", data["sources"])
        self.assertEqual(data["status_map"]["ZEEK"], "IMPLEMENTED")
        self.assertEqual(data["status_map"]["SYSMON"], "PLANNED / NOT IMPLEMENTED")
        self.assertIn("ZEEK", data["active_sources"])
        self.assertIn("SYSMON", data["planned_sources"])

    def test_07_api_zeek_replay_endpoint(self):
        """Verify /api/telemetry/zeek/replay endpoint processes payload with metrics."""
        sample_tsv = (
            "#separator \x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\n"
            "1728374400.1\tC_REPLAY_1\t192.168.1.100\t50000\t10.0.0.1\t80\ttcp\thttp\t0.05\t200\t800\tSF\n"
        )
        resp = self.client.post(
            "/api/telemetry/zeek/replay",
            json={"log_type": "conn", "mode": "REPLAY", "raw_content": sample_tsv},
            headers=self.admin_headers,
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertEqual(data["mode"], "REPLAY")
        self.assertEqual(data["events_accepted"], 1)
        self.assertEqual(data["events_processed"], 1)
        self.assertGreater(data["throughput_eps"], 0.0)

    def test_08_api_event_listing_with_source_type_filter(self):
        """Verify /api/events filter by source_type=ZEEK returns only Zeek telemetry."""
        resp = self.client.get("/api/events?source_type=ZEEK&page_size=50", headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        for item in data.get("items", []):
            self.assertEqual(item["source_type"], "ZEEK")


if __name__ == "__main__":
    unittest.main()
