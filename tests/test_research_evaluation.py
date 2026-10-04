"""
tests/test_research_evaluation.py

Comprehensive tests for Phase 11 Research & Evaluation Engine:
- Ground truth evaluation dataset generation and validation
- Operational mode simulations: M0, M1, M2, M3, M4, M5, M6
- Metric calculations (Precision, Recall, F1, FP Workload Reduction, Genuine Attack Retention, MTTI, Evidence Latency)
- Research hypothesis assertions: M4-M6 achieve >= 60-80% FP reduction with >= 98% attack retention
- Full benchmark execution and database persistence (Experiment, ExperimentRun, ExperimentMetric)
- REST API endpoints:
  - POST /api/experiments
  - GET /api/experiments
  - GET /api/experiments/{id}
  - POST /api/experiments/run (ALL and single mode)
  - GET /api/experiments/benchmark/matrix
  - GET /api/experiments/benchmark/latest
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
from app.models import User
from app.models.experiment import Experiment, ExperimentMetric, ExperimentRun
from app.services.experiment_service import (
    compute_relative_metrics,
    get_latest_benchmark,
    get_or_create_benchmark_dataset,
    run_full_benchmark,
    run_single_mode_experiment,
    simulate_mode,
)
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users


class TestResearchEvaluationEngine(unittest.TestCase):

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

    def test_01_benchmark_dataset_generation(self):
        """Verify ground truth benchmark dataset builds clean attack and benign scenarios."""
        dataset = get_or_create_benchmark_dataset("v1.0")
        self.assertGreater(len(dataset), 10)

        attacks = [s for s in dataset if s["is_attack"]]
        benign = [s for s in dataset if not s["is_attack"]]

        self.assertGreater(len(attacks), 5, "Expected multiple genuine attack scenarios")
        self.assertGreater(len(benign), 3, "Expected multiple benign background scenarios")

        # Verify essential fields
        for s in dataset:
            self.assertIn("scenario_id", s)
            self.assertIn("category", s)
            self.assertIn("events", s)
            self.assertGreater(len(s["events"]), 0)

        # Verify lookalike scenarios exist to test false positive resistance
        lookalikes = [s for s in dataset if s.get("difficulty") == "benign_lookalike"]
        self.assertGreater(len(lookalikes), 0)

    def test_02_mode_m0_raw_telemetry(self):
        """Verify M0 baseline collects raw telemetry without generating alerts or incidents."""
        dataset = get_or_create_benchmark_dataset("v1.0")
        res = simulate_mode(self.db, "M0", dataset)

        self.assertEqual(res["mode"], "M0")
        self.assertEqual(res["alerts_generated"], 0)
        self.assertEqual(res["incidents_promoted"], 0)
        self.assertEqual(res["true_positives"], 0)
        self.assertEqual(res["false_positives"], 0)
        self.assertEqual(res["precision"], 0.0)
        self.assertEqual(res["recall"], 0.0)
        self.assertEqual(res["f1_score"], 0.0)
        self.assertGreater(res["mtti_minutes"], 30.0)

    def test_03_mode_m1_static_siem_baseline(self):
        """Verify M1 static SIEM produces high alert volume and false positives from naive patterns."""
        dataset = get_or_create_benchmark_dataset("v1.0")
        res = simulate_mode(self.db, "M1", dataset)

        self.assertEqual(res["mode"], "M1")
        self.assertGreater(res["alerts_generated"], 0)
        self.assertGreater(res["incidents_promoted"], 0)
        self.assertGreater(res["true_positives"], 0)
        self.assertGreater(res["false_positives"], 0, "Static SIEM should trigger on lookalike keywords")
        self.assertGreater(res["recall"], 0.5)

    def test_04_mode_m2_and_m3_correlation_and_evidence(self):
        """Verify M2 consolidates alerts into incidents, and M3 drops evidence retrieval latency."""
        dataset = get_or_create_benchmark_dataset("v1.0")
        res_m1 = simulate_mode(self.db, "M1", dataset)
        res_m2 = simulate_mode(self.db, "M2", dataset)
        res_m3 = simulate_mode(self.db, "M3", dataset)

        # M2 consolidates alerts into fewer incidents
        self.assertLessEqual(res_m2["incidents_promoted"], res_m1["incidents_promoted"])

        # M3 slashes evidence retrieval latency compared to M1 and M2
        self.assertLess(res_m3["evidence_retrieval_ms"], res_m1["evidence_retrieval_ms"])
        self.assertLess(res_m3["evidence_retrieval_ms"], 100.0)
        self.assertLess(res_m3["mtti_minutes"], res_m1["mtti_minutes"])

    def test_05_mode_m4_detection_quality_aware(self):
        """Verify M4 Quality-Aware SOC drastically cuts false positives while retaining attacks."""
        dataset = get_or_create_benchmark_dataset("v1.0")
        res_m1 = simulate_mode(self.db, "M1", dataset)
        res_m4 = simulate_mode(self.db, "M4", dataset)

        matrix = compute_relative_metrics([res_m1, res_m4])
        m4_row = next(r for r in matrix if r.mode == "M4")

        # FP reduction should be substantial (>= 50%)
        self.assertGreaterEqual(m4_row.fp_reduction_pct, 50.0)
        # Genuine attack retention should remain high (>= 98%)
        self.assertGreaterEqual(m4_row.attack_retention_pct, 98.0)
        # Precision should significantly improve over M1
        self.assertGreater(m4_row.precision, res_m1["precision"])

    def test_06_mode_m5_behavioral_ml_anomaly(self):
        """Verify M5 Behavioral ML anomaly detection captures evasive attacks, boosting recall."""
        dataset = get_or_create_benchmark_dataset("v1.0")
        res_m4 = simulate_mode(self.db, "M4", dataset)
        res_m5 = simulate_mode(self.db, "M5", dataset)

        # M5 catches low_and_slow or subtle attacks
        self.assertGreaterEqual(res_m5["true_positives"], res_m4["true_positives"])
        self.assertGreaterEqual(res_m5["recall"], res_m4["recall"])

    def test_07_mode_m6_full_hybrid_soc(self):
        """Verify M6 Full Hybrid SOC achieves maximum FP reduction, fastest MTTI, and high agreement."""
        dataset = get_or_create_benchmark_dataset("v1.0")
        res_m1 = simulate_mode(self.db, "M1", dataset)
        res_m6 = simulate_mode(self.db, "M6", dataset)

        matrix = compute_relative_metrics([res_m1, res_m6])
        m6_row = next(r for r in matrix if r.mode == "M6")

        # Peak FP reduction (>= 75%)
        self.assertGreaterEqual(m6_row.fp_reduction_pct, 75.0)
        # Target >= 98% Genuine attack retention
        self.assertGreaterEqual(m6_row.attack_retention_pct, 98.0)
        # High F1 Score
        self.assertGreaterEqual(m6_row.f1_score, 0.90)
        # Fastest MTTI (< 3.0 minutes)
        self.assertLess(m6_row.mtti_minutes, 3.0)
        # Evidence retrieval latency < 50ms
        self.assertLess(m6_row.evidence_retrieval_ms, 50.0)
        # AI/Analyst agreement metric present
        self.assertIsNotNone(m6_row.ai_analyst_agreement_pct)

    def test_08_run_full_benchmark_persisted(self):
        """Verify run_full_benchmark executes all modes and persists Experiment, Runs, and Metrics."""
        resp = run_full_benchmark(self.db, dataset_version="v1.0", experiment_name="Integration Benchmark")

        self.assertIsNotNone(resp.experiment_id)
        self.assertEqual(len(resp.comparison_matrix), 7)  # M0 to M6
        self.assertTrue(resp.summary["hypothesis_validated"])

        # Check database records
        exp = self.db.query(Experiment).filter(Experiment.id == resp.experiment_id).first()
        self.assertIsNotNone(exp)
        self.assertEqual(exp.status, "COMPLETED")
        self.assertEqual(len(exp.runs), 7)

        # Check metrics attached to runs
        for run in exp.runs:
            self.assertGreater(len(run.metrics), 5)
            metric_names = [m.metric_name for m in run.metrics]
            self.assertIn("precision", metric_names)
            self.assertIn("recall", metric_names)
            self.assertIn("f1_score", metric_names)

    def test_09_api_experiments_crud_and_runs(self):
        """Verify REST API endpoints for experiments and benchmark comparisons."""
        # 1. POST /api/experiments
        create_payload = {
            "name": "API Registered Research Experiment",
            "description": "Evaluating M4 quality vs M1 static SIEM",
            "mode": "BENCHMARK",
            "dataset_version": "v1.0",
        }
        res = self.client.post("/api/experiments", json=create_payload, headers=self.headers)
        self.assertEqual(res.status_code, 201)
        exp_id = res.json()["id"]

        # 2. GET /api/experiments
        res = self.client.get("/api/experiments", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        items = res.json()["items"]
        self.assertTrue(any(i["id"] == exp_id for i in items))

        # 3. GET /api/experiments/{id}
        res = self.client.get(f"/api/experiments/{exp_id}", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["name"], "API Registered Research Experiment")

        # 4. POST /api/experiments/run with specific mode (M4)
        run_payload = {
            "mode": "M4",
            "dataset_version": "v1.0",
            "experiment_name": "API Single M4 Evaluation",
        }
        res = self.client.post("/api/experiments/run", json=run_payload, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("comparison_matrix", data)
        self.assertEqual(len(data["comparison_matrix"]), 1)
        self.assertEqual(data["comparison_matrix"][0]["mode"], "M4")

        # 5. GET /api/experiments/benchmark/matrix
        res = self.client.get("/api/experiments/benchmark/matrix", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        matrix_data = res.json()
        self.assertGreaterEqual(len(matrix_data["comparison_matrix"]), 7)

        # 6. GET /api/experiments/benchmark/latest
        res = self.client.get("/api/experiments/benchmark/latest", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        self.assertIn("summary", res.json())


if __name__ == "__main__":
    unittest.main()
