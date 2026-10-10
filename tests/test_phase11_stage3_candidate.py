"""
tests/test_phase11_stage3_candidate.py

Reproducible Phase 11 Stage 3 Offline Candidate Detection Rule Test Suite.
Validates:
1. Immutability of production detection rules (RULE-008, RULE-005, RULE-006 configurations frozen).
2. Rule-filter engine request_path_not_contains_any correctness.
3. Candidate RULE-008 precision improvement and false-positive reduction on standard scenarios.
4. Correctness equivalence and latency reduction of candidate query batching optimization.
5. Detection blind spots and evasion risks under adversarial excluded-path scenarios.
6. Independent evaluation of RULE-005 and RULE-006 on reverse-proxy socket 404 noise.
7. Frozen research checkpoint integrity against 6a153ae17c676e92b7fc7208b374c2646e99b4f6.
8. Integrity and completeness of the versioned Stage 3 candidate results artifact.
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
os.environ["JWT_SECRET_KEY"] = "test-secret-key-phase11-stage3"

from app.models import NormalizedEvent
from app.rules.builtin import builtin_rules
from app.rules.engine import event_matches_filters
from app.services.evaluation_phase11_stage3 import (
    Stage3EvaluationRunner,
    build_candidate_rules_definitions,
    evaluate_configuration,
    generate_adv_excl_01,
    generate_adv_excl_02,
    generate_adv_excl_03,
    generate_adv_excl_04,
    get_all_stage3_scenarios,
)


class TestPhase11Stage3CandidateEvaluation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).parent.parent
        cls.all_scenarios = get_all_stage3_scenarios()
        cls.scenario_map = {s.scenario_id: s for s in cls.all_scenarios}

    def test_01_production_detection_rules_frozen(self):
        """Verify production RULE-008, RULE-005, RULE-006 remain completely unchanged in builtin.py."""
        rules = {r["rule_id"]: r for r in builtin_rules()}

        # RULE-008
        self.assertIn("RULE-008", rules)
        r008 = rules["RULE-008"]
        self.assertEqual(r008["threshold"], 60, "Production RULE-008 threshold must remain 60")
        self.assertEqual(r008["time_window_minutes"], 5, "Production RULE-008 window must remain 5 minutes")
        self.assertEqual(
            r008["conditions_json"]["filters"],
            {"event_category": "web"},
            "Production RULE-008 filters must remain strictly {'event_category': 'web'}",
        )

        # RULE-005
        self.assertIn("RULE-005", rules)
        r005 = rules["RULE-005"]
        self.assertEqual(r005["threshold"], 10)
        self.assertEqual(r005["time_window_minutes"], 10)
        self.assertEqual(r005["conditions_json"]["filters"], {"status_code": 404})

        # RULE-006
        self.assertIn("RULE-006", rules)
        r006 = rules["RULE-006"]
        self.assertEqual(r006["threshold"], 15)
        self.assertEqual(r006["time_window_minutes"], 10)
        self.assertEqual(
            r006["conditions_json"]["filters"],
            {"event_category": "web", "status_code_range": [400, 499]},
        )

    def test_02_filter_engine_request_path_not_contains_any(self):
        """Verify request_path_not_contains_any matching, exclusion, missing, and empty lists."""
        filters = {
            "event_category": "web",
            "request_path_not_contains_any": ["/socket.io", "/assets/", "/media/"],
        }
        # Matching
        ev_ok = NormalizedEvent(event_category="web", request_path="/rest/products/1")
        self.assertTrue(event_matches_filters(ev_ok, filters))

        # Exclusion
        ev_sock = NormalizedEvent(event_category="web", request_path="/health/socket.io/?EIO=4")
        self.assertFalse(event_matches_filters(ev_sock, filters))
        ev_asset = NormalizedEvent(event_category="web", request_path="/assets/main.js")
        self.assertFalse(event_matches_filters(ev_asset, filters))

        # Missing path
        ev_none = NormalizedEvent(event_category="web", request_path=None)
        self.assertTrue(event_matches_filters(ev_none, filters))
        ev_empty = NormalizedEvent(event_category="web", request_path="")
        self.assertTrue(event_matches_filters(ev_empty, filters))

        # Empty exclusion list
        ev_any = NormalizedEvent(event_category="web", request_path="/socket.io/poll")
        self.assertTrue(event_matches_filters(ev_any, {"event_category": "web", "request_path_not_contains_any": []}))

    def test_03_candidate_rule_008_suppresses_benign_false_positives(self):
        """
        Verify candidate RULE-008 eliminates false positives on BENIGN-01, BENIGN-03, and POLL-06
        while maintaining 100% recall on all attack scenarios.
        """
        runner = Stage3EvaluationRunner(config_name="candidate_rule_008")

        # BENIGN-01 (Browsing + Polling)
        res_b1 = runner.evaluate_scenario(self.scenario_map["BENIGN-01"], measured_runs=1)
        self.assertEqual(res_b1.classification, "TN", "BENIGN-01 must be True Negative under candidate RULE-008")
        self.assertNotIn("RULE-008", res_b1.fired_rule_ids)

        # BENIGN-03 (Rapid Asset Bursts)
        res_b3 = runner.evaluate_scenario(self.scenario_map["BENIGN-03"], measured_runs=1)
        self.assertEqual(res_b3.classification, "TN", "BENIGN-03 must be True Negative under candidate RULE-008")
        self.assertNotIn("RULE-008", res_b3.fired_rule_ids)

        # POLL-06 (Light Browsing + Polling)
        res_p6 = runner.evaluate_scenario(self.scenario_map["POLL-06"], measured_runs=1)
        self.assertEqual(res_p6.classification, "TN", "POLL-06 must be True Negative under candidate RULE-008")
        self.assertNotIn("RULE-008", res_p6.fired_rule_ids)

        # ATTACK-01 (Content Scraper)
        res_a1 = runner.evaluate_scenario(self.scenario_map["ATTACK-01"], measured_runs=1)
        self.assertEqual(res_a1.classification, "TP", "ATTACK-01 must remain True Positive")
        self.assertIn("RULE-008", res_a1.fired_rule_ids)

        # ATTACK-06 (Multi-Stage Killchain)
        res_a6 = runner.evaluate_scenario(self.scenario_map["ATTACK-06"], measured_runs=1)
        self.assertEqual(res_a6.classification, "TP", "ATTACK-06 must remain True Positive")
        self.assertIn("RULE-008", res_a6.fired_rule_ids)

    def test_04_query_batching_equivalence_and_correctness(self):
        """Verify batched query execution produces exact same classification and alert counts as sequential."""
        scenarios_subset = [
            self.scenario_map["BENIGN-01"],
            self.scenario_map["POLL-ERR"],
            self.scenario_map["ATTACK-01"],
            self.scenario_map["ATTACK-06"],
        ]
        runner_seq = Stage3EvaluationRunner(config_name="candidate_rule_008", use_batched_threshold=False)
        runner_batch = Stage3EvaluationRunner(config_name="candidate_rule_008", use_batched_threshold=True)

        for sc in scenarios_subset:
            res_s = runner_seq.evaluate_scenario(sc, measured_runs=1)
            res_b = runner_batch.evaluate_scenario(sc, measured_runs=1)
            self.assertEqual(res_s.classification, res_b.classification, f"Classification mismatch for {sc.scenario_id}")
            self.assertEqual(res_s.alert_count, res_b.alert_count, f"Alert count mismatch for {sc.scenario_id}")
            self.assertEqual(res_s.incident_count, res_b.incident_count, f"Incident count mismatch for {sc.scenario_id}")
            self.assertEqual(res_s.fired_rule_ids, res_b.fired_rule_ids, f"Fired rules mismatch for {sc.scenario_id}")

    def test_05_adversarial_excluded_path_blind_spots(self):
        """
        Verify detection blind spots under adversarial conditions targeting excluded paths:
        - ADV-EXCL-01 (Socket.IO DoS) is missed by candidate RULE-008 but caught by baseline.
        - ADV-EXCL-02 (Asset exhaustion) is missed by candidate RULE-008 but caught by baseline.
        - ADV-EXCL-03 (Scraper query parameter evasion) is missed by candidate RULE-008 but caught by baseline.
        - ADV-EXCL-04 (Sensitive files in asset path) is caught by RULE-005/006/007 (Defense in depth).
        """
        runner_base = Stage3EvaluationRunner(config_name="baseline")
        runner_cand = Stage3EvaluationRunner(config_name="candidate_rule_008")

        # ADV-EXCL-01
        adv1 = self.scenario_map["ADV-EXCL-01"]
        base1 = runner_base.evaluate_scenario(adv1, measured_runs=1)
        cand1 = runner_cand.evaluate_scenario(adv1, measured_runs=1)
        self.assertIn("RULE-008", base1.fired_rule_ids, "Baseline detects Socket.IO flood")
        self.assertNotIn("RULE-008", cand1.fired_rule_ids, "Candidate is blind to Socket.IO flood (Blind Spot)")

        # ADV-EXCL-02
        adv2 = self.scenario_map["ADV-EXCL-02"]
        base2 = runner_base.evaluate_scenario(adv2, measured_runs=1)
        cand2 = runner_cand.evaluate_scenario(adv2, measured_runs=1)
        self.assertIn("RULE-008", base2.fired_rule_ids, "Baseline detects asset flood")
        self.assertNotIn("RULE-008", cand2.fired_rule_ids, "Candidate is blind to asset flood (Blind Spot)")

        # ADV-EXCL-03: Under hardened path normalization, query smuggling is neutralized
        adv3 = self.scenario_map["ADV-EXCL-03"]
        base3 = runner_base.evaluate_scenario(adv3, measured_runs=1)
        cand3 = runner_cand.evaluate_scenario(adv3, measured_runs=1)
        self.assertIn("RULE-008", base3.fired_rule_ids, "Baseline detects query-smuggled scraper")
        self.assertIn("RULE-008", cand3.fired_rule_ids, "Hardened candidate detects query-smuggled scraper")

        # ADV-EXCL-04
        adv4 = self.scenario_map["ADV-EXCL-04"]
        cand4 = runner_cand.evaluate_scenario(adv4, measured_runs=1)
        self.assertEqual(cand4.classification, "TP", "ADV-EXCL-04 is caught via defense-in-depth")
        self.assertTrue(
            any(r in cand4.fired_rule_ids for r in ("RULE-005", "RULE-006", "RULE-007")),
            "Caught by sensitive path or 404 rules despite asset path prefix",
        )

    def test_06_independent_socket_404_mitigation(self):
        """
        Verify that POLL-ERR generates FP under candidate_rule_008 (due to RULE-005/006)
        but achieves TN when evaluated with candidate_all (socket.io excluded from 404 rules).
        """
        runner_r008 = Stage3EvaluationRunner(config_name="candidate_rule_008")
        runner_all = Stage3EvaluationRunner(config_name="candidate_all")

        poll_err = self.scenario_map["POLL-ERR"]
        res_r008 = runner_r008.evaluate_scenario(poll_err, measured_runs=1)
        self.assertEqual(res_r008.classification, "FP", "POLL-ERR remains FP when only RULE-008 is modified")

        res_all = runner_all.evaluate_scenario(poll_err, measured_runs=1)
        self.assertEqual(res_all.classification, "TN", "POLL-ERR becomes TN when RULE-005/006 also exclude socket.io")

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

    def test_08_stage3_artifact_integrity(self):
        """Verify docs/artifacts/phase_11_stage_3_candidate_evaluation_results.json exists and is valid."""
        artifact_path = self.repo_root / "docs" / "artifacts" / "phase_11_stage_3_candidate_evaluation_results.json"
        self.assertTrue(artifact_path.exists(), "Stage 3 artifact must exist")
        with open(artifact_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertIn("metadata", data)
        self.assertIn("standard_17_scenarios", data)
        self.assertIn("full_21_scenarios_including_adversarial", data)

        std = data["standard_17_scenarios"]
        self.assertIn("baseline_sequential", std)
        self.assertIn("candidate_rule008_sequential", std)
        self.assertIn("candidate_rule008_batched", std)

        cand = std["candidate_rule008_sequential"]
        self.assertEqual(cand["true_positives"], 6)
        self.assertEqual(cand["false_positives"], 1)  # Only POLL-ERR remains
        self.assertEqual(cand["true_negatives"], 10)
        self.assertEqual(cand["false_negatives"], 0)
        self.assertAlmostEqual(cand["recall"], 1.0, places=2)
        self.assertGreater(cand["precision"], 0.85)


if __name__ == "__main__":
    unittest.main()
