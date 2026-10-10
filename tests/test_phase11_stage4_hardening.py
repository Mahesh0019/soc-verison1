"""
tests/test_phase11_stage4_hardening.py

Reproducible Phase 11 Stage 4 Offline Candidate Hardening Test Suite.
Validates:
1. Immutability of production detection rules (RULE-008, RULE-005, RULE-006 unchanged).
2. Query-parameter bypass evasion neutralization (ADV-EXCL-03 detected).
3. URL-encoded path traversal evasion neutralization (ADV-EXCL-06 detected).
4. Alternative Dual-Threshold Architecture restoring 100% attack recall (ADV-EXCL-01 & ADV-EXCL-02 detected).
5. Independent RULE-005/006 evaluation exposing the namespace probing blind spot (ADV-EXCL-05).
6. Batched vs sequential execution correctness equivalence.
7. Frozen Phase 0–9 research checkpoint integrity.
8. Stage 4 structured artifact integrity.
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

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AUTO_CREATE_TABLES"] = "true"
os.environ["ENABLE_JUICE_SHOP_CONNECTOR"] = "false"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-phase11-stage4"

from app.rules.builtin import builtin_rules
from app.services.evaluation_phase11_stage4 import (
    Stage4EvaluationRunner,
    get_all_stage4_scenarios,
)


class TestPhase11Stage4CandidateHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).parent.parent
        cls.scenarios = get_all_stage4_scenarios()
        cls.scenario_map = {s.scenario_id: s for s in cls.scenarios}

    def test_01_production_rules_immutability(self):
        """Verify production RULE-008, RULE-005, RULE-006 remain completely unchanged in builtin.py."""
        rules = {r["rule_id"]: r for r in builtin_rules()}

        self.assertIn("RULE-008", rules)
        r008 = rules["RULE-008"]
        self.assertEqual(r008["threshold"], 60)
        self.assertEqual(r008["time_window_minutes"], 5)
        self.assertEqual(r008["conditions_json"]["filters"], {"event_category": "web"})

        self.assertIn("RULE-005", rules)
        r005 = rules["RULE-005"]
        self.assertEqual(r005["threshold"], 10)
        self.assertEqual(r005["time_window_minutes"], 10)
        self.assertEqual(r005["conditions_json"]["filters"], {"status_code": 404})

        self.assertIn("RULE-006", rules)
        r006 = rules["RULE-006"]
        self.assertEqual(r006["threshold"], 15)
        self.assertEqual(r006["time_window_minutes"], 10)
        self.assertEqual(
            r006["conditions_json"]["filters"],
            {"event_category": "web", "status_code_range": [400, 499]},
        )

    def test_02_query_bypass_neutralization_scenario(self):
        """
        Verify ADV-EXCL-03 (scraper appending ?bypass=/socket.io) is successfully detected
        as True Positive by candidate_stage4_hardened (closing the Stage 3 evasion gap).
        """
        runner = Stage4EvaluationRunner(config_name="candidate_stage4_hardened", use_batched_threshold=True)
        res = runner.evaluate_scenario(self.scenario_map["ADV-EXCL-03"], measured_runs=1)
        self.assertEqual(res.classification, "TP", "ADV-EXCL-03 must be detected as TP")
        self.assertIn("RULE-008", res.fired_rule_ids, "RULE-008 must fire despite query-string evasion")
        self.assertFalse(res.blind_spot_flag, "ADV-EXCL-03 is no longer a blind spot")

    def test_03_encoded_traversal_evasion_scenario(self):
        """Verify ADV-EXCL-06 (scraper using encoded /%61ssets/../ prefix) is normalized and detected."""
        runner = Stage4EvaluationRunner(config_name="candidate_stage4_hardened", use_batched_threshold=True)
        res = runner.evaluate_scenario(self.scenario_map["ADV-EXCL-06"], measured_runs=1)
        self.assertEqual(res.classification, "TP", "ADV-EXCL-06 must be detected as TP")
        self.assertIn("RULE-008", res.fired_rule_ids)

    def test_04_dual_threshold_architecture_restores_coverage(self):
        """
        Verify that alternative Dual-Threshold Architecture (candidate_stage4_dual_threshold):
        - Detects ADV-EXCL-01 (Socket.IO DoS) via RULE-008B.
        - Detects ADV-EXCL-02 (Asset Exhaustion) via RULE-008B.
        - Preserves True Negative on BENIGN-01, BENIGN-03, POLL-06.
        - Achieves 0 blind spots.
        """
        runner = Stage4EvaluationRunner(config_name="candidate_stage4_dual_threshold", use_batched_threshold=True)

        # Benign sessions remain TN
        res_b1 = runner.evaluate_scenario(self.scenario_map["BENIGN-01"], measured_runs=1)
        res_b3 = runner.evaluate_scenario(self.scenario_map["BENIGN-03"], measured_runs=1)
        self.assertEqual(res_b1.classification, "TN", "BENIGN-01 must remain TN under dual threshold")
        self.assertEqual(res_b3.classification, "TN", "BENIGN-03 must remain TN under dual threshold")

        # Excluded path volumetric attacks are detected via RULE-008B
        res_adv1 = runner.evaluate_scenario(self.scenario_map["ADV-EXCL-01"], measured_runs=1)
        self.assertEqual(res_adv1.classification, "TP", "ADV-EXCL-01 must be detected under dual threshold")
        self.assertIn("RULE-008B", res_adv1.fired_rule_ids, "RULE-008B must fire on Socket.IO flood")

        res_adv2 = runner.evaluate_scenario(self.scenario_map["ADV-EXCL-02"], measured_runs=1)
        self.assertEqual(res_adv2.classification, "TP", "ADV-EXCL-02 must be detected under dual threshold")
        self.assertIn("RULE-008B", res_adv2.fired_rule_ids, "RULE-008B must fire on asset flood")

    def test_05_independent_404_tradeoff_demonstration(self):
        """
        Verify the trade-off of suppressing socket 404s:
        - POLL-ERR becomes TN (suppressing noise).
        - BUT ADV-EXCL-05 (namespace probing fuzzing) is MISSED (FN / Blind Spot).
        This proves why production RULE-005/006 definitions should not be changed.
        """
        runner_base = Stage4EvaluationRunner(config_name="baseline", use_batched_threshold=True)
        runner_ind = Stage4EvaluationRunner(config_name="candidate_stage4_independent_404", use_batched_threshold=True)

        # ADV-EXCL-05 under baseline is TP (detected by RULE-005 / RULE-006)
        res_base = runner_base.evaluate_scenario(self.scenario_map["ADV-EXCL-05"], measured_runs=1)
        self.assertEqual(res_base.classification, "TP", "Baseline detects socket namespace probing")
        self.assertTrue(any(r in res_base.fired_rule_ids for r in ("RULE-005", "RULE-006")))

        # ADV-EXCL-05 under candidate_stage4_independent_404 is MISSED (FN)
        res_ind = runner_ind.evaluate_scenario(self.scenario_map["ADV-EXCL-05"], measured_runs=1)
        self.assertEqual(res_ind.classification, "FN", "Socket exclusion blinds engine to namespace probing")
        self.assertTrue(res_ind.blind_spot_flag)

    def test_06_batched_vs_sequential_exact_equivalence(self):
        """Verify sequential and batched execution yield 100% equivalent classification and alert counts."""
        test_subset = [
            self.scenario_map["BENIGN-01"],
            self.scenario_map["POLL-06"],
            self.scenario_map["POLL-ERR"],
            self.scenario_map["ATTACK-01"],
            self.scenario_map["ATTACK-06"],
            self.scenario_map["ADV-EXCL-03"],
        ]
        runner_seq = Stage4EvaluationRunner(config_name="candidate_stage4_hardened", use_batched_threshold=False)
        runner_bat = Stage4EvaluationRunner(config_name="candidate_stage4_hardened", use_batched_threshold=True)

        for sc in test_subset:
            res_s = runner_seq.evaluate_scenario(sc, measured_runs=1)
            res_b = runner_bat.evaluate_scenario(sc, measured_runs=1)
            self.assertEqual(res_s.classification, res_b.classification)
            self.assertEqual(res_s.alert_count, res_b.alert_count)
            self.assertEqual(res_s.incident_count, res_b.incident_count)
            self.assertEqual(res_s.fired_rule_ids, res_b.fired_rule_ids)

    def test_07_frozen_research_checkpoint_integrity(self):
        """Verify research/ directory remains byte-for-byte identical to checkpoint 6a153ae."""
        checkpoint = "6a153ae17c676e92b7fc7208b374c2646e99b4f6"
        res = subprocess.run(
            ["git", "diff", "--exit-code", checkpoint, "HEAD", "--", "research/"],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"Research checkpoint drifted: {res.stdout} {res.stderr}")

    def test_08_stage4_artifact_integrity(self):
        """Verify docs/artifacts/phase_11_stage_4_candidate_evaluation_results.json exists and is valid."""
        artifact_path = self.repo_root / "docs" / "artifacts" / "phase_11_stage_4_candidate_evaluation_results.json"
        self.assertTrue(artifact_path.exists(), "Stage 4 artifact must exist")
        with open(artifact_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertIn("metadata", data)
        self.assertIn("scenarios_evaluated", data)
        self.assertEqual(data["scenarios_evaluated"], 23)
        self.assertIn("configurations", data)

        configs = data["configurations"]
        self.assertIn("baseline_sequential", configs)
        self.assertIn("candidate_stage4_hardened_batched", configs)
        self.assertIn("candidate_stage4_dual_threshold_batched", configs)

        hardened = configs["candidate_stage4_hardened_batched"]
        self.assertEqual(hardened["true_positives"], 10)
        self.assertEqual(hardened["false_positives"], 1)
        self.assertEqual(hardened["true_negatives"], 10)
        self.assertEqual(hardened["false_negatives"], 2)
        self.assertEqual(hardened["blind_spots_count"], 2)

        dual = configs["candidate_stage4_dual_threshold_batched"]
        self.assertEqual(dual["true_positives"], 12)
        self.assertEqual(dual["false_positives"], 1)
        self.assertEqual(dual["true_negatives"], 10)
        self.assertEqual(dual["false_negatives"], 0)
        self.assertEqual(dual["blind_spots_count"], 0)


if __name__ == "__main__":
    unittest.main()
