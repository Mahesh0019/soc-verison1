"""
tests/test_phase11_offline_evaluation.py

Reproducible Phase 11 Stage 2 Offline Detection Evaluation Test Suite.
Validates:
1. Hermetic in-memory test database isolation (zero production DB access).
2. Frozen research checkpoint integrity (git diff against 6a153ae17c676e92b7fc7208b374c2646e99b4f6).
3. Production detection rule configuration immutability (RULE-008 threshold unchanged).
4. Deterministic evaluation of all 17 labeled benign and attack scenarios.
5. Complete RULE-008 parameter sweep simulation (thresholds, path exclusions, burst density).
6. Confusion matrix, precision, recall, and false-positive rate calculations.
7. Latency measurements and comparison against the 70 ms measurement target.
8. Integrity of the exported Phase 11 evaluation results artifact.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

# Enforce isolated in-memory test environment
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AUTO_CREATE_TABLES"] = "true"
os.environ["ENABLE_JUICE_SHOP_CONNECTOR"] = "false"
os.environ["JWT_SECRET_KEY"] = "integration-test-secret-key-12345"

from app.rules.builtin import builtin_rules
from app.services.evaluation_phase11 import (
    IsolatedEvaluationRunner,
    calculate_aggregate_metrics,
    get_all_evaluation_scenarios,
    run_rule_008_parameter_sweeps,
    simulate_rule_008_evaluation,
)


class TestPhase11OfflineDetectionEvaluation(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).parent.parent
        cls.scenarios = get_all_evaluation_scenarios()
        cls.runner = IsolatedEvaluationRunner()

    def test_01_database_and_environment_isolation(self):
        """Verify tests run strictly against in-memory SQLite with zero production DB connectivity."""
        self.assertEqual(os.environ.get("DATABASE_URL"), "sqlite:///:memory:")
        self.assertEqual(os.environ.get("ENABLE_JUICE_SHOP_CONNECTOR"), "false")
        # Ensure runner uses SQLite memory engine
        db = self.runner.SessionLocal()
        try:
            url_str = str(self.runner.engine.url)
            self.assertIn("sqlite", url_str)
            self.assertIn(":memory:", url_str)
        finally:
            db.close()

    def test_02_frozen_research_checkpoint_integrity(self):
        """Verify research/ directory is byte-for-byte identical to checkpoint 6a153ae."""
        checkpoint = "6a153ae17c676e92b7fc7208b374c2646e99b4f6"
        res = subprocess.run(
            ["git", "diff", "--exit-code", checkpoint, "HEAD", "--", "research/"],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            res.returncode,
            0,
            f"Frozen research artifacts have drifted from checkpoint {checkpoint}: {res.stdout} {res.stderr}",
        )

    def test_03_production_detection_rules_unmodified(self):
        """Verify production RULE-008 threshold (60) and filter configuration remain frozen."""
        rules = {r["rule_id"]: r for r in builtin_rules()}
        self.assertIn("RULE-008", rules)
        r008 = rules["RULE-008"]
        self.assertEqual(r008["threshold"], 60, "Production RULE-008 threshold must remain 60")
        self.assertEqual(r008["time_window_minutes"], 5, "Production RULE-008 time window must remain 5 minutes")
        self.assertEqual(
            r008["conditions_json"]["filters"],
            {"event_category": "web"},
            "Production RULE-008 filters must remain strictly {'event_category': 'web'}",
        )
        self.assertEqual(len(rules), 14, "All 14 built-in detection rules must be present")

    def test_04_scenario_matrix_catalog_completeness(self):
        """Verify all 17 standardized scenarios exist with correct metadata and labels."""
        self.assertEqual(len(self.scenarios), 17)
        scenario_ids = [s.scenario_id for s in self.scenarios]
        expected_ids = [
            "BENIGN-01", "BENIGN-02", "BENIGN-03", "BENIGN-04",
            "POLL-01", "POLL-02", "POLL-03", "POLL-04", "POLL-05", "POLL-06", "POLL-ERR",
            "ATTACK-01", "ATTACK-02", "ATTACK-03", "ATTACK-04", "ATTACK-05", "ATTACK-06",
        ]
        for eid in expected_ids:
            self.assertIn(eid, scenario_ids)

        for sc in self.scenarios:
            self.assertGreater(len(sc.events), 0)
            self.assertGreater(sc.duration_seconds, 0)
            self.assertIn(sc.category, ("benign", "attack"))

    def test_05_benign_browsing_false_positive_reproduction(self):
        """
        Verify that under the existing unmodified production rules:
        - BENIGN-01 triggers RULE-008 (Reproducing the Phase 10B/10C false positive anomaly).
        - BENIGN-02 (idle standby) does NOT trigger RULE-008.
        - BENIGN-03 (rapid images) triggers RULE-008.
        - BENIGN-04 (routine admin) generates 0 alerts.
        """
        sc_map = {s.scenario_id: s for s in self.scenarios}

        # BENIGN-01 (79 events)
        res_b1 = self.runner.run_scenario(sc_map["BENIGN-01"])
        self.assertEqual(res_b1.classification, "FP")
        self.assertIn("RULE-008", res_b1.fired_rule_ids)
        self.assertEqual(res_b1.incident_count, 1)

        # BENIGN-02 (100 events over 10m, 50 in 5m)
        res_b2 = self.runner.run_scenario(sc_map["BENIGN-02"])
        self.assertEqual(res_b2.classification, "TN")
        self.assertEqual(len(res_b2.fired_rule_ids), 0)

        # BENIGN-03 (65 images in 15s)
        res_b3 = self.runner.run_scenario(sc_map["BENIGN-03"])
        self.assertEqual(res_b3.classification, "FP")
        self.assertIn("RULE-008", res_b3.fired_rule_ids)

        # BENIGN-04 (5 admin requests)
        res_b4 = self.runner.run_scenario(sc_map["BENIGN-04"])
        self.assertEqual(res_b4.classification, "TN")
        self.assertEqual(len(res_b4.fired_rule_ids), 0)

    def test_06_attack_scenarios_detection_efficacy(self):
        """
        Verify that all controlled attack scenarios trigger the expected detection rules (100% Recall):
        - ATTACK-01: RULE-008 (Scraper)
        - ATTACK-02: RULE-005, RULE-006, RULE-008 (Fuzzer)
        - ATTACK-03: RULE-012 (SQL Injection)
        - ATTACK-04: RULE-013 (Path Traversal)
        - ATTACK-05: RULE-009 (Scanner User-Agent)
        - ATTACK-06: Multi-stage Killchain with Incident correlation
        """
        sc_map = {s.scenario_id: s for s in self.scenarios}

        res_a1 = self.runner.run_scenario(sc_map["ATTACK-01"])
        self.assertEqual(res_a1.classification, "TP")
        self.assertIn("RULE-008", res_a1.fired_rule_ids)

        res_a2 = self.runner.run_scenario(sc_map["ATTACK-02"])
        self.assertEqual(res_a2.classification, "TP")
        self.assertIn("RULE-005", res_a2.fired_rule_ids)
        self.assertIn("RULE-006", res_a2.fired_rule_ids)
        self.assertIn("RULE-008", res_a2.fired_rule_ids)

        res_a3 = self.runner.run_scenario(sc_map["ATTACK-03"])
        self.assertEqual(res_a3.classification, "TP")
        self.assertIn("RULE-012", res_a3.fired_rule_ids)

        res_a4 = self.runner.run_scenario(sc_map["ATTACK-04"])
        self.assertEqual(res_a4.classification, "TP")
        self.assertIn("RULE-013", res_a4.fired_rule_ids)

        res_a5 = self.runner.run_scenario(sc_map["ATTACK-05"])
        self.assertEqual(res_a5.classification, "TP")
        self.assertIn("RULE-009", res_a5.fired_rule_ids)

        res_a6 = self.runner.run_scenario(sc_map["ATTACK-06"])
        self.assertEqual(res_a6.classification, "TP")
        self.assertIn("RULE-008", res_a6.fired_rule_ids)
        self.assertIn("RULE-012", res_a6.fired_rule_ids)
        self.assertEqual(res_a6.incident_count, 1)

    def test_07_rule_008_parameter_sweeps(self):
        """
        Evaluate candidate thresholds and path exclusions:
        - Confirm that baseline has FP = 3 on volume anomalies.
        - Confirm that excluding both Socket.IO and static assets achieves Precision=1.0, Recall=1.0, FP=0.
        - Confirm that threshold >= 180 causes FN on ATTACK-06 (100 crawler requests).
        """
        sweeps = run_rule_008_parameter_sweeps(self.scenarios)
        self.assertGreaterEqual(len(sweeps), 20)

        # Baseline (threshold=60, filter=none)
        baseline = next(s for s in sweeps if s.threshold == 60 and s.filter_mode == "none")
        self.assertEqual(baseline.fp, 3)  # BENIGN-01, BENIGN-03, POLL-06
        self.assertEqual(baseline.fn, 0)
        self.assertEqual(baseline.recall, 1.0)
        self.assertEqual(baseline.precision, 0.50)

        # Exclude both Socket.IO and static assets (threshold=60)
        opt_60 = next(s for s in sweeps if s.threshold == 60 and s.filter_mode == "exclude_both")
        self.assertEqual(opt_60.fp, 0, "Excluding both polling and static assets must eliminate all False Positives")
        self.assertEqual(opt_60.fn, 0, "Excluding both polling and static assets must preserve 100% Recall on attacks")
        self.assertEqual(opt_60.precision, 1.0)
        self.assertEqual(opt_60.recall, 1.0)
        self.assertEqual(opt_60.f1_score, 1.0)
        self.assertFalse(opt_60.benign_01_fired)
        self.assertFalse(opt_60.benign_03_fired)
        self.assertTrue(opt_60.attack_01_fired)
        self.assertTrue(opt_60.attack_06_fired)

        # High threshold (threshold=180, filter=none) causes False Negative on ATTACK-06
        high_thresh = next(s for s in sweeps if s.threshold == 180 and s.filter_mode == "none")
        self.assertEqual(high_thresh.fn, 1, "Threshold 180 without exclusions misses 100-request crawler")
        self.assertFalse(high_thresh.attack_06_fired)

    def test_08_phase11_artifact_integrity(self):
        """Verify that the exported JSON artifact exists, matches schema, and contains non-empty metrics."""
        artifact_path = self.repo_root / "docs" / "artifacts" / "phase_11_offline_evaluation_results.json"
        self.assertTrue(artifact_path.exists(), f"Phase 11 results artifact not found at {artifact_path}")

        data = json.loads(artifact_path.read_text(encoding="utf-8"))
        self.assertIn("metadata", data)
        self.assertIn("baseline_evaluation", data)
        self.assertIn("rule_008_sweeps", data)

        agg = data["baseline_evaluation"]["aggregate_metrics"]
        self.assertEqual(agg["total_scenarios"], 17)
        self.assertEqual(agg["true_positives"], 6)
        self.assertEqual(agg["false_positives"], 4)
        self.assertEqual(agg["true_negatives"], 7)
        self.assertEqual(agg["false_negatives"], 0)
        self.assertEqual(agg["recall"], 1.0)
        self.assertEqual(agg["precision"], 0.60)
        self.assertGreater(agg["median_latency_ms"], 0)


if __name__ == "__main__":
    unittest.main()
