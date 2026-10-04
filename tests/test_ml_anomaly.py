"""
tests/test_ml_anomaly.py

Comprehensive tests for Phase 7 Behavioral ML Anomaly Detection (Isolation Forest):
- Shannon entropy computation & feature vector extraction
- Isolation Forest training, baseline derivation, and anomaly scoring
- Graceful heuristic fallback for sparse/bootstrap data
- Feature attribution explainability & primary factor identification
- Integration with Detection Quality Engine (behavioral factor calibration)
- REST API endpoints (/api/behavioral/status, /train, /score/ip, /score/alert, /anomalies)
"""

from __future__ import annotations

import math
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
from app.models import Alert, AlertEvent, NormalizedEvent, User
from app.services.detection_quality_service import calculate_behavioral_confidence, evaluate_alert_quality
from app.services.ml_anomaly_service import (
    BehavioralAnomalyDetector,
    calculate_shannon_entropy,
    extract_features_from_events,
    get_behavioral_detector,
    score_alert_behavior,
    score_ip_behavior,
    train_behavioral_model_from_db,
)
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users


class TestMLAnomalyDetection(unittest.TestCase):

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

    def test_01_shannon_entropy_calculation(self):
        """Verify Shannon entropy accurately reflects path diversity."""
        # Empty paths
        self.assertEqual(calculate_shannon_entropy([]), 0.0)

        # Uniform single path: H = 0.0
        self.assertEqual(calculate_shannon_entropy(["/index.html"] * 10), 0.0)

        # Exactly 2 equally frequent paths: H = 1.0 bit
        entropy_2 = calculate_shannon_entropy(["/a", "/b"] * 5)
        self.assertAlmostEqual(entropy_2, 1.0, places=2)

        # 4 equally frequent paths: H = 2.0 bits
        entropy_4 = calculate_shannon_entropy(["/a", "/b", "/c", "/d"] * 3)
        self.assertAlmostEqual(entropy_4, 2.0, places=2)

    def test_02_feature_vector_extraction(self):
        """Verify extract_features_from_events correctly calculates all 10 features."""
        now = datetime.now(UTC)

        # Normal browsing event sequence
        normal_events = [
            NormalizedEvent(
                timestamp=now - timedelta(minutes=5 - i),
                source_ip="192.168.1.10",
                username="alice",
                event_type="web_request",
                event_category="web",
                severity="low",
                message=f"GET /page_{i}",
                request_path=f"/page_{i}",
                http_method="GET",
                status_code=200,
            )
            for i in range(5)
        ]
        feat_normal = extract_features_from_events(normal_events)
        self.assertEqual(feat_normal["error_ratio_4xx"], 0.0)
        self.assertEqual(feat_normal["error_ratio_5xx"], 0.0)
        self.assertEqual(feat_normal["failed_login_ratio"], 0.0)
        self.assertGreater(feat_normal["request_rate"], 0.0)

        # Anomalous fuzzing/attack event sequence
        attack_events = [
            NormalizedEvent(
                timestamp=now - timedelta(seconds=i * 2),
                source_ip="203.0.113.99",
                username="unknown",
                event_type="web_probe",
                event_category="web",
                severity="high",
                message=f"Failed probe {i}",
                request_path=f"/admin/config_{i}.env",
                http_method="POST",
                status_code=404 if i % 2 == 0 else 401,
            )
            for i in range(10)
        ]
        feat_attack = extract_features_from_events(attack_events)
        self.assertGreaterEqual(feat_attack["error_ratio_4xx"], 0.90)
        self.assertGreater(feat_attack["path_entropy"], 2.0)
        self.assertEqual(feat_attack["sensitive_path_ratio"], 1.0)

    def test_03_detector_fallback_and_fit(self):
        """Verify IsolationForest fit, scoring, and graceful fallback."""
        detector = BehavioralAnomalyDetector(contamination=0.1, n_estimators=30)

        # Scoring before fit uses graceful fallback heuristic
        dummy_attack = {
            "request_rate": 50.0,
            "error_ratio_4xx": 0.85,
            "error_ratio_5xx": 0.05,
            "path_entropy": 3.5,
            "method_diversity": 0.6,
            "status_diversity": 0.5,
            "off_hours_ratio": 0.8,
            "unique_paths_ratio": 0.9,
            "failed_login_ratio": 0.7,
            "sensitive_path_ratio": 0.9,
        }
        res_fallback = detector.score_features(dummy_attack, entity_type="ip", entity_id="10.0.0.1")
        self.assertGreater(res_fallback["anomaly_score"], 0.50)
        self.assertTrue(res_fallback["is_anomaly"])
        self.assertIn("primary_factor", res_fallback)

        # Training with multiple normal samples
        training_data = [
            {
                "request_rate": float(r),
                "error_ratio_4xx": 0.02,
                "error_ratio_5xx": 0.00,
                "path_entropy": 1.0,
                "method_diversity": 0.2,
                "status_diversity": 0.2,
                "off_hours_ratio": 0.0,
                "unique_paths_ratio": 0.2,
                "failed_login_ratio": 0.0,
                "sensitive_path_ratio": 0.01,
            }
            for r in [2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        ]
        fit_result = detector.fit(training_data)
        self.assertTrue(fit_result["success"])
        self.assertTrue(detector.is_fitted)
        self.assertEqual(detector.sample_count, 10)

        # Scoring inlier vs outlier after fit
        normal_sample = {
            "request_rate": 5.0,
            "error_ratio_4xx": 0.02,
            "error_ratio_5xx": 0.00,
            "path_entropy": 1.0,
            "method_diversity": 0.2,
            "status_diversity": 0.2,
            "off_hours_ratio": 0.0,
            "unique_paths_ratio": 0.2,
            "failed_login_ratio": 0.0,
            "sensitive_path_ratio": 0.01,
        }
        res_normal = detector.score_features(normal_sample, entity_type="ip", entity_id="192.168.1.5")
        self.assertLess(res_normal["anomaly_score"], 0.50)

        res_anomaly = detector.score_features(dummy_attack, entity_type="ip", entity_id="203.0.113.99")
        self.assertGreater(res_anomaly["anomaly_score"], 0.60)
        self.assertTrue(res_anomaly["is_anomaly"])

    def test_04_detection_quality_integration(self):
        """Verify Detection Quality Engine integrates ML behavioral confidence."""
        now = datetime.now(UTC)
        alert = Alert(
            title="Brute force login surge",
            description="Testing ML quality integration",
            severity="critical",
            status="open",
            source_ip="198.51.100.88",
            affected_user="victim",
            first_seen=now,
            last_seen=now,
            event_count=5,
        )
        self.db.add(alert)
        self.db.flush()

        # Add anomalous events linked to this alert
        for i in range(5):
            ev = NormalizedEvent(
                timestamp=now - timedelta(seconds=i * 5),
                source_ip="198.51.100.88",
                username="victim",
                event_type="auth_failure",
                event_category="auth",
                severity="critical",
                message=f"Failed login attempt {i}",
                request_path="/api/login",
                status_code=401,
            )
            self.db.add(ev)
            self.db.flush()
            self.db.add(AlertEvent(alert_id=alert.id, event_id=ev.id))

        self.db.commit()

        # Calculate behavioral confidence with DB session
        behav_conf = calculate_behavioral_confidence(alert, db=self.db)
        self.assertGreaterEqual(behav_conf, 0.70)

        # Full Detection Quality evaluation
        dq = evaluate_alert_quality(self.db, alert)
        self.db.commit()

        self.assertIsNotNone(dq)
        self.assertGreaterEqual(dq.behavioral_confidence, 0.70)
        self.assertGreaterEqual(dq.overall_quality, 0.70)

    def test_05_behavioral_rest_api_endpoints(self):
        """Verify REST API endpoints for behavioral ML status, training, and scoring."""
        # 1. Model Status
        status_res = self.client.get("/api/behavioral/status", headers=self.headers)
        self.assertEqual(status_res.status_code, 200)
        status_data = status_res.json()
        self.assertIn("model_name", status_data)
        self.assertIn("feature_names", status_data)
        self.assertEqual(len(status_data["feature_names"]), 10)

        # 2. Train Model
        train_res = self.client.post("/api/behavioral/train", json={"window_minutes": 1440, "contamination": 0.08}, headers=self.headers)
        self.assertEqual(train_res.status_code, 200)
        train_data = train_res.json()
        self.assertTrue(train_data["success"])
        self.assertGreaterEqual(train_data["sample_count"], 4)

        # 3. Score IP
        ip_res = self.client.get("/api/behavioral/score/ip/198.51.100.88", headers=self.headers)
        self.assertEqual(ip_res.status_code, 200)
        ip_data = ip_res.json()
        self.assertEqual(ip_data["entity_type"], "ip")
        self.assertEqual(ip_data["entity_id"], "198.51.100.88")
        self.assertIn("anomaly_score", ip_data)
        self.assertIn("primary_factor", ip_data)

        # 4. List Anomalies
        anomalies_res = self.client.get("/api/behavioral/anomalies", headers=self.headers)
        self.assertEqual(anomalies_res.status_code, 200)
        self.assertIsInstance(anomalies_res.json(), list)


if __name__ == "__main__":
    unittest.main()
