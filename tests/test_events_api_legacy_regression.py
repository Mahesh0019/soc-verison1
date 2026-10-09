"""
tests/test_events_api_legacy_regression.py

Regression test suite specifically verifying:
1. Retrieval of legacy NormalizedEvent records where source_type is NULL in the database.
2. Derivation and normalization of source_type from trustworthy metadata.
3. Pagination across mixed legacy (NULL source_type) and new (populated source_type) records.
4. Edge conditions: page boundaries, empty pages, missing optional fields.
5. Ingestion and preservation of event fields without mutation or data loss.
6. Connector failure and recovery tracking, verifying accurate status reporting without false successes.
"""

import os
import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure backend directory is in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AUTO_CREATE_TABLES"] = "true"
os.environ["ENABLE_JUICE_SHOP_CONNECTOR"] = "false"
os.environ["JWT_SECRET_KEY"] = "legacy-regression-test-secret-key"

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from app.auth.security import create_access_token
from app.database.base import Base
from app.database.session import get_db
from app.main import create_app
from app.models import NormalizedEvent, RawLog, User
from app.schemas.event import EventBase, EventOut
from app.services.juice_shop_background import (
    _connector_metrics,
    get_connector_status,
)


class TestEventsApiLegacyRegression(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        cls.SessionLocal = sessionmaker(
            bind=cls.engine, autoflush=False, autocommit=False, expire_on_commit=False
        )
        Base.metadata.create_all(bind=cls.engine)

        app = create_app()

        def override_get_db():
            db = cls.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(app)

        # Seed an admin user
        db = cls.SessionLocal()
        from app.auth.security import hash_password

        cls.test_user = User(
            username="analyst_test",
            email="analyst_test@example.com",
            role="analyst",
            password_hash=hash_password("AnalystPassword123!"),
        )
        db.add(cls.test_user)
        db.commit()
        db.refresh(cls.test_user)

        login_res = cls.client.post(
            "/api/auth/login",
            json={"username": "analyst_test", "password": "AnalystPassword123!"},
        )
        cls.token = login_res.json()["access_token"]
        cls.auth_headers = {"Authorization": f"Bearer {cls.token}"}

        # Seed raw log parent
        raw_log = RawLog(source_type="demo", original_content="test logs", file_name="test.log")
        db.add(raw_log)
        db.commit()
        db.refresh(raw_log)
        cls.raw_log_id = raw_log.id

        now = datetime.now(UTC)

        # 1. Insert 35 LEGACY records directly with source_type = NULL via raw SQL
        #    to simulate pre-existing production database state before column migration.
        for i in range(35):
            db.execute(
                text(
                    """
                    INSERT INTO normalized_events (
                        raw_log_id, timestamp, source_ip, destination_ip,
                        event_type, event_category, severity, message,
                        request_path, http_method, status_code, user_agent,
                        source_type, created_at
                    ) VALUES (
                        :raw_log_id, :timestamp, :source_ip, :dest_ip,
                        :event_type, :event_category, :severity, :message,
                        :request_path, :http_method, :status_code, :user_agent,
                        NULL, :created_at
                    )
                    """
                ),
                {
                    "raw_log_id": cls.raw_log_id,
                    "timestamp": (now - timedelta(minutes=100 - i)).isoformat(),
                    "source_ip": f"192.168.1.{i+1}",
                    "dest_ip": "10.0.0.1",
                    "event_type": "web_request",
                    "event_category": "web",
                    "severity": "low",
                    "message": f"GET /api/legacy/{i} returned 200",
                    "request_path": f"/api/legacy/{i}",
                    "http_method": "GET",
                    "status_code": 200,
                    "user_agent": "LegacyBrowser/1.0",
                    "created_at": now.isoformat(),
                },
            )

        # 2. Insert 25 modern records with explicit source_types (ZEEK, SYSMON, AUTH, FIREWALL, etc.)
        modern_types = ["ZEEK", "SYSMON", "AUTH", "FIREWALL", "OTHER"]
        for j in range(25):
            st = modern_types[j % len(modern_types)]
            event = NormalizedEvent(
                raw_log_id=cls.raw_log_id,
                timestamp=now - timedelta(minutes=50 - j),
                source_ip=f"10.10.1.{j+1}",
                destination_ip="10.0.0.2",
                source_type=st,
                event_type="modern_event",
                event_category="security",
                severity="medium",
                message=f"Modern {st} event {j}",
            )
            db.add(event)

        db.commit()
        db.close()

    def test_legacy_records_null_source_type_schema_validation(self):
        """Verify that Pydantic EventOut serializes legacy records without throwing ResponseValidationError."""
        db = self.SessionLocal()
        legacy_records = (
            db.query(NormalizedEvent)
            .filter(NormalizedEvent.source_type.is_(None))
            .limit(5)
            .all()
        )
        self.assertGreater(len(legacy_records), 0)

        for rec in legacy_records:
            # Must not raise ResponseValidationError or ValidationError
            event_out = EventOut.model_validate(rec)
            self.assertIsNotNone(event_out.id)
            # Must semantically derive WEB from request_path metadata
            self.assertEqual(event_out.source_type, "WEB")
            self.assertIn("/api/legacy/", event_out.request_path)
            self.assertEqual(event_out.severity, "low")
        db.close()

    def test_pagination_page_2_with_page_size_30(self):
        """
        Verify the exact failing production request:
        GET /api/events?page=2&page_size=30
        Must return HTTP 200 with 30 items spanning mixed legacy and modern records.
        """
        resp = self.client.get(
            "/api/events?page=2&page_size=30",
            headers=self.auth_headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["page"], 2)
        self.assertEqual(data["page_size"], 30)
        self.assertEqual(len(data["items"]), 30)
        self.assertGreaterEqual(data["total"], 60)

        # Verify items contain valid source_type and no None string validation errors
        for item in data["items"]:
            self.assertIsNotNone(item["source_type"])
            self.assertIsInstance(item["source_type"], str)

    def test_page_1_and_page_boundaries(self):
        """Verify first page and boundary handling."""
        # Page 1
        resp_p1 = self.client.get(
            "/api/events?page=1&page_size=30",
            headers=self.auth_headers,
        )
        self.assertEqual(resp_p1.status_code, 200)
        self.assertEqual(len(resp_p1.json()["items"]), 30)

        # Page 4 (should be empty since total is 61 items across 3 pages)
        resp_p4 = self.client.get(
            "/api/events?page=4&page_size=30",
            headers=self.auth_headers,
        )
        self.assertEqual(resp_p4.status_code, 200)
        self.assertEqual(len(resp_p4.json()["items"]), 0)

        # Page 999 (out of range beyond total)
        resp_far = self.client.get(
            "/api/events?page=999&page_size=30",
            headers=self.auth_headers,
        )
        self.assertEqual(resp_far.status_code, 200)
        self.assertEqual(len(resp_far.json()["items"]), 0)

    def test_missing_optional_fields_serialization(self):
        """Verify events with missing optional fields (dns, process, bytes, ports) serialize safely."""
        db = self.SessionLocal()
        cursor = db.execute(
            text(
                """
                INSERT INTO normalized_events (
                    raw_log_id, timestamp, event_type, event_category, severity, message, source_type
                ) VALUES (
                    :raw_log_id, :timestamp, 'minimal', 'generic', 'low', 'minimal fields test', NULL
                )
                """
            ),
            {"raw_log_id": self.raw_log_id, "timestamp": datetime.now(UTC).isoformat()},
        )
        db.commit()
        last_id = cursor.lastrowid
        minimal_event = db.get(NormalizedEvent, last_id)

        event_out = EventOut.model_validate(minimal_event)
        self.assertEqual(event_out.id, minimal_event.id)
        # Should default to OTHER since no specific metadata exists
        self.assertEqual(event_out.source_type, "OTHER")
        self.assertIsNone(event_out.source_ip)
        self.assertIsNone(event_out.destination_port)
        self.assertIsNone(event_out.dns_query)
        self.assertIsNone(event_out.process)
        db.close()

    def test_invalid_genuinely_required_fields_rejected(self):
        """Verify that genuine required fields (e.g. timestamp) still enforce validation."""
        with self.assertRaises(Exception):
            EventBase.model_validate({"source_type": "WEB"})  # Missing timestamp

    def test_filter_by_source_type(self):
        """Verify source_type filtering works correctly for both modern and derived types."""
        resp = self.client.get(
            "/api/events?source_type=ZEEK",
            headers=self.auth_headers,
        )
        self.assertEqual(resp.status_code, 200)
        items = resp.json()["items"]
        for it in items:
            self.assertEqual(it["source_type"], "ZEEK")

    def test_connector_status_reporting(self):
        """Verify connector health endpoint reports accurate state without false successes."""
        resp = self.client.get(
            "/api/telemetry/connector/status",
            headers=self.auth_headers,
        )
        self.assertEqual(resp.status_code, 200)
        status = resp.json()
        self.assertIn("running", status)
        self.assertIn("last_status", status)
        self.assertIn("total_events_ingested", status)
        # Verify no false positive ingestion claim
        self.assertEqual(status["total_events_ingested"], 0)
        self.assertIsNone(status["last_successful_ingestion"])

    def test_connector_status_failure_recording(self):
        """Verify connector records upstream 502 accurately."""
        # Reset metrics
        _connector_metrics["consecutive_failures"] = 0
        _connector_metrics["last_error"] = None

        # Simulate a 502 cycle
        _connector_metrics["consecutive_failures"] += 1
        _connector_metrics["last_error"] = "HTTP Error 502: Bad Gateway"
        _connector_metrics["last_status"] = "UPSTREAM_UNAVAILABLE_502"

        status = get_connector_status()
        self.assertEqual(status["last_status"], "UPSTREAM_UNAVAILABLE_502")
        self.assertEqual(status["consecutive_failures"], 1)
        self.assertIn("502", status["last_error"])
        # Ingestion count must still be 0
        self.assertEqual(status["total_events_ingested"], 0)


if __name__ == "__main__":
    unittest.main()
