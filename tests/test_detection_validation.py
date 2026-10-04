"""
tests/test_detection_validation.py

Comprehensive tests for Phase 10 Detection Validation Engine:
- Positive test case assertion (genuine attack triggers rule)
- Negative test case assertion (benign traffic does NOT trigger rule)
- Single rule validation suite execution
- Full regression test harness execution across all active rules
- Validation summary, pass rate, and rule health status tracking
- Custom dynamic validation scenario assertions
- REST API endpoints (/api/validation/run-all, /run-rule, /results, /summary, /custom-test)
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
from app.models import DetectionRule, User, ValidationTest
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users
from app.services.validation_service import (
    get_validation_summary,
    run_all_validation_tests,
    run_rule_validation_suite,
    run_validation_test,
)


class TestDetectionValidationEngine(unittest.TestCase):

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

    def test_01_single_rule_validation_positive_and_negative(self):
        """Verify positive scenario triggers rule and negative scenario does not."""
        sqli_rule = self.db.query(DetectionRule).filter(DetectionRule.name.ilike("%sql injection%")).first()
        self.assertIsNotNone(sqli_rule)

        # 1. Positive Test Case (Attack payload -> Expected True)
        pos_scenario = {
            "scenario_id": "TEST-SQLI-POS-01",
            "test_name": "SQLi UNION exploit assertion",
            "expected_result": True,
            "events": [
                {
                    "event_type": "web_attack",
                    "severity": "critical",
                    "source_ip": "198.51.100.230",
                    "message": "Probe SELECT 1 FROM users WHERE 'a'='a'",
                    "request_path": "/rest/products/search?q=' OR 1=1--",
                    "status_code": 500,
                }
            ],
        }
        pos_result = run_validation_test(self.db, sqli_rule, pos_scenario)
        self.assertTrue(pos_result.observed_result)
        self.assertTrue(pos_result.passed)
        self.assertGreater(pos_result.execution_time_ms, 0.0)

        # 2. Negative Test Case (Benign query -> Expected False)
        neg_scenario = {
            "scenario_id": "TEST-SQLI-NEG-01",
            "test_name": "Standard product query assertion",
            "expected_result": False,
            "events": [
                {
                    "event_type": "web_request",
                    "severity": "low",
                    "source_ip": "198.51.100.231",
                    "message": "Search apple juice",
                    "request_path": "/rest/products/search?q=apple_juice",
                    "status_code": 200,
                }
            ],
        }
        neg_result = run_validation_test(self.db, sqli_rule, neg_scenario)
        self.assertFalse(neg_result.observed_result)
        self.assertTrue(neg_result.passed)

    def test_02_rule_validation_suite(self):
        """Verify run_rule_validation_suite executes all relevant scenarios for a rule."""
        xss_rule = self.db.query(DetectionRule).filter(DetectionRule.name.ilike("%cross-site scripting%")).first()
        self.assertIsNotNone(xss_rule)

        suite = run_rule_validation_suite(self.db, xss_rule.id)
        self.assertEqual(suite["rule_id"], xss_rule.id)
        self.assertGreaterEqual(suite["total_tests"], 2)
        self.assertEqual(suite["failed_tests"], 0)
        self.assertEqual(suite["pass_rate"], 1.0)

    def test_03_run_all_validation_tests(self):
        """Verify run_all_validation_tests iterates through all active detection rules."""
        run_all = run_all_validation_tests(self.db)
        self.assertGreater(run_all["total_tests"], 5)
        self.assertGreaterEqual(run_all["pass_rate"], 0.80)
        self.assertGreater(run_all["execution_time_ms_total"], 0.0)

    def test_04_validation_summary_metrics(self):
        """Verify get_validation_summary compiles overall health and per-rule status."""
        summary = get_validation_summary(self.db)
        self.assertIn("total_runs", summary)
        self.assertIn("overall_pass_rate", summary)
        self.assertIn("rule_health", summary)
        self.assertGreater(len(summary["rule_health"]), 0)

        # Check health tier
        first_rule = summary["rule_health"][0]
        self.assertIn("rule_name", first_rule)
        self.assertIn(first_rule["status"], ("HEALTHY", "DEGRADED", "REGRESSED"))

    def test_05_custom_validation_assertion(self):
        """Verify dynamic custom assertion execution via custom-test service logic."""
        trav_rule = self.db.query(DetectionRule).filter(DetectionRule.name.ilike("%path traversal%")).first()
        self.assertIsNotNone(trav_rule)

        custom_scenario = {
            "scenario_id": "CUSTOM-DYNAMIC-01",
            "test_name": "Custom probe assertion",
            "expected_result": True,
            "events": [
                {
                    "event_type": "web_attack",
                    "severity": "high",
                    "source_ip": "198.51.100.240",
                    "message": "Access /../../etc/passwd",
                    "request_path": "/../../etc/passwd",
                }
            ],
        }
        res = run_validation_test(self.db, trav_rule, custom_scenario)
        self.assertTrue(res.passed)
        self.assertTrue(res.observed_result)

    def test_06_validation_rest_api_endpoints(self):
        """Verify REST API endpoints for validation execution, detail, summary, and custom test."""
        rule = self.db.query(DetectionRule).first()

        # 1. POST /api/validation/run-rule/{id}
        rule_res = self.client.post(f"/api/validation/run-rule/{rule.id}", headers=self.headers)
        self.assertEqual(rule_res.status_code, 200)
        rule_data = rule_res.json()
        self.assertGreater(rule_data["total_tests"], 0)
        test_id = rule_data["results"][0]["id"]

        # 2. GET /api/validation/results
        list_res = self.client.get("/api/validation/results", headers=self.headers)
        self.assertEqual(list_res.status_code, 200)
        self.assertGreater(list_res.json()["total"], 0)

        # 3. GET /api/validation/results/{id}
        detail_res = self.client.get(f"/api/validation/results/{test_id}", headers=self.headers)
        self.assertEqual(detail_res.status_code, 200)
        self.assertEqual(detail_res.json()["id"], test_id)

        # 4. GET /api/validation/summary
        summary_res = self.client.get("/api/validation/summary", headers=self.headers)
        self.assertEqual(summary_res.status_code, 200)
        self.assertIn("overall_pass_rate", summary_res.json())

        # 5. POST /api/validation/custom-test
        custom_payload = {
            "rule_id": rule.id,
            "test_name": "API dynamic assertion",
            "test_scenario_id": "SCEN-API-CUSTOM-99",
            "expected_result": False,
            "events_data": [
                {
                    "event_type": "benign_ping",
                    "message": "Ping check",
                    "request_path": "/health",
                }
            ],
        }
        custom_res = self.client.post("/api/validation/custom-test", json=custom_payload, headers=self.headers)
        self.assertEqual(custom_res.status_code, 201)
        self.assertTrue(custom_res.json()["passed"])


if __name__ == "__main__":
    unittest.main()
