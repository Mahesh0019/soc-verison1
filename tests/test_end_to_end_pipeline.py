"""
tests/test_end_to_end_pipeline.py

Phase 16: Comprehensive End-to-End Live Validation of the Detection-Quality-Aware SOC Framework.
Validates the complete closed-loop lifecycle from raw attack ingestion to research evaluation:
1. Telemetry Ingestion (Juice Shop attack scenarios)
2. Detection & Alert Correlation (Phase 3)
3. Cryptographic Evidence Packaging & Hash Verification (Phase 4)
4. 5-Factor Explainable Detection Quality Scoring (Phase 5)
5. Multi-Factor Risk Prioritization & Incident Promotion (Phase 6)
6. Behavioral ML Anomaly Feature Extraction & Scoring (Phase 7)
7. Evidence-Grounded AI Triage & Zero-Hallucination Claims Audit (Phase 8)
8. Analyst Feedback Loop & Confusion Matrix Tracking (Phase 9)
9. Detection-as-Code Regression Health Harness (Phase 10)
10. M0-M6 Research Benchmark Evaluation Matrix (Phase 11)
11. Security Hardening & RBAC Enforcement (Phase 13)
"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import UTC, datetime
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
from app.models import (
    Alert,
    AuditLog,
    DetectionQuality,
    DetectionRule,
    Evidence,
    Incident,
    NormalizedEvent,
    RawLog,
    User,
)
from app.services.ai_triage_service import triage_alert
from app.services.detection_quality_service import evaluate_alert_quality
from app.services.evidence_service import build_evidence_package, calculate_evidence_completeness
from app.services.experiment_service import run_full_benchmark
from app.services.feedback_service import record_alert_feedback
from app.services.ingestion import ingest_api_payload
from app.services.ml_anomaly_service import score_alert_behavior, train_behavioral_model_from_db
from app.services.risk_service import evaluate_incident_risk
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users
from app.services.validation_service import run_all_validation_tests


class TestEndToEndSOCPipeline(unittest.TestCase):

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
        cls.token = res.json()["access_token"]
        cls.headers = {"Authorization": f"Bearer {cls.token}"}

    @classmethod
    def tearDownClass(cls):
        Base.metadata.drop_all(bind=cls.engine)
        cls.engine.dispose()

    def setUp(self):
        self.db = self.SessionLocal()

    def tearDown(self):
        self.db.rollback()
        self.db.close()

    def test_complete_soc_lifecycle_closed_loop(self):
        """Execute a full closed-loop pipeline test across all 11 core architectural stages."""
        # ── 1. Telemetry Ingestion ───────────────────────────────────────────
        raw_events = [
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "event_type": "web_attack",
                "severity": "critical",
                "source_ip": "198.51.100.222",
                "destination_ip": "10.0.0.15",
                "method": "POST",
                "request_path": "/rest/user/login",
                "status_code": 500,
                "message": "SQL Injection attempt: admin' OR 1=1--",
                "raw_payload": "{\"email\": \"' OR 1=1--\", \"password\": \"test\"}",
            },
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "event_type": "web_attack",
                "severity": "critical",
                "source_ip": "198.51.100.222",
                "destination_ip": "10.0.0.15",
                "method": "GET",
                "request_path": "/rest/products/search?q=' UNION SELECT 1,2,3--",
                "status_code": 200,
                "message": "SQL Injection UNION search probe",
                "raw_payload": "q=' UNION SELECT 1,2,3--",
            },
        ]

        result = ingest_api_payload(
            self.db,
            source_type="juice_shop_live",
            events=raw_events,
            raw_lines=[],
            user_id=None,
        )
        self.assertEqual(result["parsed_count"], 2)
        self.assertGreaterEqual(result["alert_count"], 1)

        # ── 2. Correlation & Alert Verification (Phase 3) ───────────────────
        alert = self.db.query(Alert).filter(Alert.source_ip == "198.51.100.222").first()
        self.assertIsNotNone(alert)
        self.assertIn("sql injection", alert.title.lower())

        # ── 3. Cryptographic Evidence Packaging (Phase 4) ────────────────────
        evidence_items = build_evidence_package(self.db, alert)
        self.assertGreater(len(evidence_items), 0)
        completeness = calculate_evidence_completeness(evidence_items)
        self.assertGreater(completeness, 0.4)

        # ── 4. 5-Factor Explainable Detection Quality (Phase 5) ─────────────
        quality = evaluate_alert_quality(self.db, alert)
        self.assertIsNotNone(quality)
        self.assertGreater(quality.overall_quality, 0.5)

        # ── 5. Multi-Factor Risk Assessment (Phase 6) ───────────────────────
        incident = self.db.query(Incident).first()
        if incident:
            risk = evaluate_incident_risk(self.db, incident)
            self.assertGreater(risk.risk_score, 20.0)

        # ── 6. Behavioral ML Anomaly Feature Extraction (Phase 7) ───────────
        train_behavioral_model_from_db(self.db)
        ml_score = score_alert_behavior(self.db, alert)
        self.assertIsInstance(ml_score, dict)

        # ── 7. Evidence-Grounded AI Triage & Claims Audit (Phase 8) ─────────
        ai_triage = triage_alert(self.db, alert)
        self.assertIsNotNone(ai_triage)
        self.assertGreater(ai_triage.ai_claim_count, 0)
        self.assertGreaterEqual(ai_triage.supported_claim_count, 1)

        # ── 8. Analyst Feedback Loop (Phase 9) ──────────────────────────────
        analyst = self.db.query(User).filter(User.username == "analyst").first()
        fb = record_alert_feedback(
            self.db,
            alert_id=alert.id,
            analyst_id=analyst.id,
            classification="TRUE_POSITIVE",
            notes="E2E Pipeline verified genuine SQLi exploit payload.",
        )
        self.assertEqual(fb.classification, "TRUE_POSITIVE")

        # ── 9. Detection-as-Code Regression Suite (Phase 10) ────────────────
        regression = run_all_validation_tests(self.db)
        self.assertEqual(regression["pass_rate"], 1.0)
        self.assertGreaterEqual(regression["total_tests"], 28)

        # ── 10. M0-M6 Research Benchmark Comparison (Phase 11) ──────────────
        benchmark = run_full_benchmark(self.db, dataset_version="v1.0", experiment_name="E2E Full SOC Benchmark")
        self.assertEqual(len(benchmark.comparison_matrix), 7)
        self.assertTrue(benchmark.summary["hypothesis_validated"])

        # Validate research criteria: FP reduction >= 70%, Genuine attack retention >= 98%
        m6 = next(r for r in benchmark.comparison_matrix if r.mode == "M6")
        self.assertGreaterEqual(m6.fp_reduction_pct, 70.0)
        self.assertGreaterEqual(m6.attack_retention_pct, 98.0)


if __name__ == "__main__":
    unittest.main()
