"""
tests/test_detection_engineering_v2.py

Phase 2 Test Suite:
- Verification of Detection-as-Code metadata for all 14 built-in rules.
- Rule lifecycle state enforcement (ACTIVE vs DRAFT/TESTING/DISABLED/DEPRECATED).
- Rule versioning and schema injection protection.
- Explainable Rule Health Score calculation and persistent RuleHealthRecord storage.
- API endpoints for rule health and lifecycle operations.
"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from pydantic import ValidationError

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AUTO_CREATE_TABLES"] = "true"
os.environ["ENABLE_JUICE_SHOP_CONNECTOR"] = "false"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-phase2-detection"

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from app.database.base import Base
from app.database.session import get_db
from app.main import create_app
from app.models import DetectionRule, NormalizedEvent, RuleHealthRecord, User
from app.rules import builtin_rules
from app.rules.engine import evaluate_rules_for_events
from app.schemas.rule import RuleBase, RuleCreate, RuleUpdate
from app.services.detection_quality_service import (
    calculate_rule_health_score,
    evaluate_rule_health,
    get_all_latest_rule_health,
)
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users


class TestDetectionEngineeringV2(unittest.TestCase):
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

    def test_01_builtin_rules_metadata_completeness(self):
        """Verify all 14 built-in rules possess comprehensive Detection-as-Code metadata."""
        rules = builtin_rules()
        self.assertEqual(len(rules), 14)

        expected_ids = {f"RULE-{i:03d}" for i in range(1, 15)}
        actual_ids = {r["rule_id"] for r in rules}
        self.assertEqual(actual_ids, expected_ids)

        for rule in rules:
            self.assertTrue(rule["rule_id"].startswith("RULE-"))
            self.assertEqual(rule["version"], "1.0")
            self.assertEqual(rule["status"], "ACTIVE")
            self.assertEqual(rule["source"], "builtin")
            self.assertIn(rule["owner"], ("secops-team", "threat-intel-team"))
            self.assertNotEqual(rule["mitre_technique"], "")
            self.assertTrue(0.0 <= rule["confidence"] <= 1.0)
            self.assertIn(rule["expected_data_source"], ("web_telemetry", "auth_telemetry", "network_telemetry", "firewall_telemetry", "threat_intel"))
            self.assertIn("positive", rule["test_cases_json"])
            self.assertIn("negative", rule["test_cases_json"])

    def test_02_rule_lifecycle_gating(self):
        """Verify rules in DRAFT or TESTING do NOT fire alerts in live production evaluation."""
        db = self.TestingSessionLocal()
        try:
            # Active rule
            active_rule = DetectionRule(
                rule_id="RULE-901",
                name="Lifecycle Test Active SQLi",
                description="Active test",
                severity="high",
                status="ACTIVE",
                enabled=True,
                conditions_json={"type": "pattern", "filters": {"event_category": "web"}, "patterns": ["active_pattern_probe"], "match_field": "message"},
                time_window_minutes=10,
                threshold=1,
            )
            # Draft rule
            draft_rule = DetectionRule(
                rule_id="RULE-902",
                name="Lifecycle Test Draft SQLi",
                description="Draft test",
                severity="high",
                status="DRAFT",
                enabled=True,
                conditions_json={"type": "pattern", "filters": {"event_category": "web"}, "patterns": ["draft_pattern_probe"], "match_field": "message"},
                time_window_minutes=10,
                threshold=1,
            )
            # Testing rule
            testing_rule = DetectionRule(
                rule_id="RULE-903",
                name="Lifecycle Test Testing SQLi",
                description="Testing test",
                severity="high",
                status="TESTING",
                enabled=True,
                conditions_json={"type": "pattern", "filters": {"event_category": "web"}, "patterns": ["testing_pattern_probe"], "match_field": "message"},
                time_window_minutes=10,
                threshold=1,
            )
            db.add_all([active_rule, draft_rule, testing_rule])
            db.commit()

            # Trigger event for active rule
            ev_active = NormalizedEvent(
                timestamp=datetime.now(UTC),
                source_ip="198.51.100.31",
                severity="medium",
                message="active_pattern_probe payload",
                event_type="web_request",
                event_category="web",
            )
            # Trigger event for draft rule
            ev_draft = NormalizedEvent(
                timestamp=datetime.now(UTC),
                source_ip="198.51.100.32",
                severity="medium",
                message="draft_pattern_probe payload",
                event_type="web_request",
                event_category="web",
            )
            # Trigger event for testing rule
            ev_test = NormalizedEvent(
                timestamp=datetime.now(UTC),
                source_ip="198.51.100.33",
                severity="medium",
                message="testing_pattern_probe payload",
                event_type="web_request",
                event_category="web",
            )
            db.add_all([ev_active, ev_draft, ev_test])
            db.commit()

            alert_count = evaluate_rules_for_events(db, [ev_active, ev_draft, ev_test], auto_correlate=False)
            db.commit()

            alerts = self.client.get(
                "/api/alerts?page_size=100",
                headers={"Authorization": f"Bearer {self.admin_token}"},
            ).json()
            titles = [a["title"] for a in alerts.get("items", [])]
            self.assertIn("Lifecycle Test Active SQLi", titles)
            self.assertNotIn("Lifecycle Test Draft SQLi", titles)
            self.assertNotIn("Lifecycle Test Testing SQLi", titles)
        finally:
            db.close()

    def test_03_rule_metadata_injection_hardening(self):
        """Verify Pydantic schemas reject malicious input or malformed metadata."""
        # Invalid rule_id with command injection attempt
        with self.assertRaises(ValidationError):
            RuleBase(
                rule_id="RULE-01; rm -rf /",
                name="Injection Test",
                description="Testing injection",
                severity="high",
                conditions_json={"type": "threshold"},
            )

        # Invalid status
        with self.assertRaises(ValidationError):
            RuleBase(
                rule_id="RULE-999",
                name="Status Test",
                description="Testing status",
                severity="high",
                status="INVALID_STATUS",
                conditions_json={"type": "threshold"},
            )

        # Invalid MITRE technique format
        with self.assertRaises(ValidationError):
            RuleBase(
                rule_id="RULE-999",
                name="MITRE Test",
                description="Testing mitre",
                severity="high",
                mitre_technique="MALICIOUS_TAG_123",
                conditions_json={"type": "threshold"},
            )

        # Valid MITRE format passes
        valid = RuleBase(
            rule_id="RULE-999",
            name="Valid Rule",
            description="Valid description",
            severity="high",
            mitre_technique="T1190",
            conditions_json={"type": "threshold"},
        )
        self.assertEqual(valid.mitre_technique, "T1190")

    def test_04_calculate_rule_health_score_explainability(self):
        """Verify health score calculation formula, bounds, and insufficient data handling."""
        # Insufficient data returns None and INSUFFICIENT_DATA
        score, tier, details = calculate_rule_health_score(tp=0, fp=0, fn=0, tn=0)
        self.assertIsNone(score)
        self.assertEqual(tier, "INSUFFICIENT_DATA")
        self.assertEqual(details["status"], "NOT ENOUGH DATA")

        # Perfect rule (TP=10, FP=0, FN=0, TN=10, latency=5ms, confidence=0.9, PASSED)
        score_perf, tier_perf, factors_perf = calculate_rule_health_score(
            tp=10, fp=0, fn=0, tn=10, latency_ms=5.0, confidence=0.90, regression_status="PASSED"
        )
        self.assertIsNotNone(score_perf)
        self.assertGreaterEqual(score_perf, 90.0)
        self.assertEqual(tier_perf, "EXCELLENT")
        self.assertIn("formula", factors_perf)

        # Degraded rule with false positives and failed regression
        score_deg, tier_deg, _ = calculate_rule_health_score(
            tp=5, fp=5, fn=2, tn=5, latency_ms=60.0, confidence=0.70, regression_status="FAILED"
        )
        self.assertIsNotNone(score_deg)
        self.assertLess(score_deg, 65.0)
        self.assertIn(tier_deg, ("DEGRADED", "UNHEALTHY"))

    def test_05_persistent_rule_health_evaluation(self):
        """Verify evaluate_rule_health persists RuleHealthRecord to PostgreSQL/DB."""
        db = self.TestingSessionLocal()
        try:
            rule = db.query(DetectionRule).filter(DetectionRule.rule_id == "RULE-001").first()
            self.assertIsNotNone(rule)

            record = evaluate_rule_health(db, rule, dataset_target="test_suite", persist=True)
            self.assertIsInstance(record, RuleHealthRecord)
            self.assertEqual(record.rule_id, rule.id)
            self.assertEqual(record.rule_name, rule.name)
            self.assertIn(record.regression_status, ("PASSED", "FAILED"))
            self.assertIn(record.health_tier, ("EXCELLENT", "HEALTHY", "DEGRADED", "UNHEALTHY"))

            # Verify persistent query
            saved = db.query(RuleHealthRecord).filter(RuleHealthRecord.rule_id == rule.id).first()
            self.assertIsNotNone(saved)
            self.assertEqual(saved.id, record.id)
            self.assertEqual(saved.health_score, record.health_score)
        finally:
            db.close()

    def test_06_api_rules_health_summary(self):
        """Verify /api/rules/health/summary endpoint returns persistent health metrics."""
        response = self.client.get(
            "/api/rules/health/summary",
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("total_rules", data)
        self.assertIn("tier_distribution", data)
        self.assertIn("rule_records", data)
        self.assertIsInstance(data["rule_records"], list)
        self.assertGreaterEqual(len(data["rule_records"]), 1)

    def test_07_api_rule_versioning_and_update(self):
        """Verify rule patch updates version and lifecycle state safely."""
        db = self.TestingSessionLocal()
        try:
            rule = db.query(DetectionRule).filter(DetectionRule.rule_id == "RULE-002").first()
            rule_id = rule.id
        finally:
            db.close()

        patch_resp = self.client.patch(
            f"/api/rules/{rule_id}",
            json={"version": "1.1", "status": "TESTING"},
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        self.assertEqual(patch_resp.status_code, 200)
        updated = patch_resp.json()
        self.assertEqual(updated["version"], "1.1")
        self.assertEqual(updated["status"], "TESTING")

        # Restore to ACTIVE for consistency
        restore_resp = self.client.patch(
            f"/api/rules/{rule_id}",
            json={"version": "1.0", "status": "ACTIVE"},
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        self.assertEqual(restore_resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
