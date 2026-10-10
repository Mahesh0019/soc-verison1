"""
tests/test_phase11_stage5_audit.py

Phase 11 Stage 5: Independent Robustness and Reproducibility Audit Test Suite.
Validates:
1. Production rules immutability (zero drift).
2. Threshold boundary sweep: immediately below (59), exact (60), above (61).
3. Companion boundary sweep: immediately below (109), exact (110).
4. Sliding window boundary (305s) and out-of-order telemetry stream arrival.
5. NAT shared IP traffic (FP trade-off) and distributed scraper fleet (FN blind spot).
6. HTTP methods (POST flood, POST 403) and URL fragment smuggling (#).
7. Batched vs. Sequential exact equivalence across 35 scenarios (zero discrepancies).
8. Stage 5 machine-readable artifact integrity and mathematical validity.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import List

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

import pytest

from app.rules.builtin import builtin_rules
from app.services.evaluation_phase11_stage5 import (
    Stage5AuditRunner,
    evaluate_stage5_configuration,
    generate_stg5_bound_01,
    generate_stg5_bound_02,
    generate_stg5_bound_03,
    generate_stg5_bound_04,
    generate_stg5_bound_05,
    generate_stg5_dist_01,
    generate_stg5_frag_01,
    generate_stg5_nat_01,
    generate_stg5_ooo_01,
    generate_stg5_post_01,
    generate_stg5_post_02,
    generate_stg5_window_01,
    get_all_stage5_scenarios,
)


class TestPhase11Stage5Audit:

    def test_01_production_rules_immutability(self):
        """Verify production builtin rules remain completely unmodified."""
        rules = builtin_rules()
        assert len(rules) == 14, f"Expected 14 builtin rules, got {len(rules)}"

        rule_008 = next((r for r in rules if r["rule_id"] == "RULE-008"), None)
        assert rule_008 is not None
        assert rule_008["threshold"] == 60
        assert rule_008["time_window_minutes"] == 5
        filters = rule_008["conditions_json"]["filters"]
        assert filters == {"event_category": "web"}
        assert "request_path_not_contains_any" not in filters

        rule_005 = next((r for r in rules if r["rule_id"] == "RULE-005"), None)
        assert rule_005 is not None
        assert rule_005["threshold"] == 10
        assert "request_path_not_contains_any" not in rule_005["conditions_json"]["filters"]

        rule_006 = next((r for r in rules if r["rule_id"] == "RULE-006"), None)
        assert rule_006 is not None
        assert rule_006["threshold"] == 15
        assert "request_path_not_contains_any" not in rule_006["conditions_json"]["filters"]

    def test_02_threshold_boundary_sweep_below_exact_above(self):
        """Verify boundary behavior at 59, 60, and 61 requests in 5 minutes."""
        runner = Stage5AuditRunner(config_name="candidate_dual_threshold", use_batched_threshold=True)

        # 59 requests: below threshold -> MUST NOT alert
        sc_59 = generate_stg5_bound_01()
        res_59 = runner.evaluate_scenario(sc_59, measured_runs=1)
        assert res_59.alert_count == 0
        assert res_59.classification == "TN"

        # 60 requests: exactly at threshold -> MUST alert on RULE-008
        sc_60 = generate_stg5_bound_02()
        res_60 = runner.evaluate_scenario(sc_60, measured_runs=1)
        assert res_60.alert_count >= 1
        assert "RULE-008" in res_60.fired_rule_ids
        assert res_60.classification == "TP"

        # 61 requests: immediately above threshold -> MUST alert on RULE-008
        sc_61 = generate_stg5_bound_03()
        res_61 = runner.evaluate_scenario(sc_61, measured_runs=1)
        assert res_61.alert_count >= 1
        assert "RULE-008" in res_61.fired_rule_ids
        assert res_61.classification == "TP"

    def test_03_companion_boundary_sweep_below_exact(self):
        """Verify companion boundary behavior at 109 and 110 socket requests in 5 minutes."""
        runner = Stage5AuditRunner(config_name="candidate_dual_threshold", use_batched_threshold=True)

        # 109 socket requests: below threshold 110 -> MUST NOT alert
        sc_109 = generate_stg5_bound_04()
        res_109 = runner.evaluate_scenario(sc_109, measured_runs=1)
        assert res_109.alert_count == 0
        assert res_109.classification == "TN"

        # 110 socket requests: exactly at threshold 110 -> MUST alert on RULE-008B
        sc_110 = generate_stg5_bound_05()
        res_110 = runner.evaluate_scenario(sc_110, measured_runs=1)
        assert res_110.alert_count >= 1
        assert "RULE-008B" in res_110.fired_rule_ids
        assert res_110.classification == "TP"

    def test_04_sliding_window_boundary_and_out_of_order_stream(self):
        """Verify 5-minute sliding window boundary (305s) and out-of-order stream arrival."""
        runner = Stage5AuditRunner(config_name="candidate_dual_threshold", use_batched_threshold=True)

        # Window boundary: 60 requests spread across 305s (max in any 300s window is 59)
        sc_win = generate_stg5_window_01()
        res_win = runner.evaluate_scenario(sc_win, measured_runs=1)
        assert res_win.alert_count == 0
        assert res_win.classification == "TN"

        # Out-of-order arrival: 65 requests within 120s arriving scrambled
        sc_ooo = generate_stg5_ooo_01()
        res_ooo = runner.evaluate_scenario(sc_ooo, measured_runs=1)
        assert res_ooo.alert_count >= 1
        assert "RULE-008" in res_ooo.fired_rule_ids
        assert res_ooo.classification == "TP"

    def test_05_nat_and_distributed_traffic_stress(self):
        """Verify NAT multi-user traffic (FP trade-off) and distributed botnet traffic (FN blind spot)."""
        runner = Stage5AuditRunner(config_name="candidate_dual_threshold", use_batched_threshold=True)

        # NAT scenario: 2 users, 35 reqs each = 70 total reqs from single gateway IP in 5m
        sc_nat = generate_stg5_nat_01()
        res_nat = runner.evaluate_scenario(sc_nat, measured_runs=1)
        # IP-only thresholding groups by IP, so 70 > 60 triggers RULE-008 (FP)
        assert res_nat.alert_count >= 1
        assert "RULE-008" in res_nat.fired_rule_ids
        assert res_nat.classification == "FP"

        # Distributed scraper scenario: 5 IPs, 25 reqs each = 125 total reqs in 5m
        sc_dist = generate_stg5_dist_01()
        res_dist = runner.evaluate_scenario(sc_dist, measured_runs=1)
        # Each IP sends 25 (<60), so single-IP thresholding does NOT trigger (FN blind spot)
        assert res_dist.alert_count == 0
        assert res_dist.classification == "FN"

    def test_06_http_methods_and_fragment_smuggling(self):
        """Verify HTTP POST flood, suspicious POST to assets (403), and URL fragment smuggling (#)."""
        runner = Stage5AuditRunner(config_name="candidate_dual_threshold", use_batched_threshold=True)

        # POST flood to Socket.IO (120 POSTs in 2m)
        sc_post_flood = generate_stg5_post_01()
        res_post_flood = runner.evaluate_scenario(sc_post_flood, measured_runs=1)
        assert "RULE-008B" in res_post_flood.fired_rule_ids
        assert res_post_flood.classification == "TP"

        # Suspicious POST to static asset returning 403 (20 POSTs)
        sc_post_asset = generate_stg5_post_02()
        res_post_asset = runner.evaluate_scenario(sc_post_asset, measured_runs=1)
        assert "RULE-006" in res_post_asset.fired_rule_ids
        assert res_post_asset.classification == "TP"

        # URL fragment smuggling: /rest/products/search#bypass=/socket.io (90 reqs)
        sc_frag = generate_stg5_frag_01()
        res_frag = runner.evaluate_scenario(sc_frag, measured_runs=1)
        assert "RULE-008" in res_frag.fired_rule_ids
        assert res_frag.classification == "TP"

    def test_07_batched_vs_sequential_exact_equivalence_35_scenarios(self):
        """Verify batched and sequential query engines produce identical results across all 35 scenarios."""
        repo_root = Path(__file__).resolve().parent.parent
        artifact_path = repo_root / "docs" / "artifacts" / "phase_11_stage_5_audit_results.json"
        assert artifact_path.exists(), f"Artifact not found at {artifact_path}"

        with open(artifact_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        seq_card = data["configurations"]["candidate_dual_threshold_sequential"]
        bat_card = data["configurations"]["candidate_dual_threshold_batched"]

        # 1. Verify exact metric equivalence across full 35-scenario benchmark
        assert seq_card["true_positives"] == bat_card["true_positives"] == 19
        assert seq_card["false_positives"] == bat_card["false_positives"] == 2
        assert seq_card["true_negatives"] == bat_card["true_negatives"] == 13
        assert seq_card["false_negatives"] == bat_card["false_negatives"] == 1
        assert seq_card["precision"] == bat_card["precision"] == 0.9048
        assert seq_card["recall"] == bat_card["recall"] == 0.9500
        assert seq_card["false_positive_rate"] == bat_card["false_positive_rate"] == 0.1333
        assert seq_card["f1_score"] == bat_card["f1_score"] == 0.9268

        # 2. Verify per-scenario exact equivalence across all 35 scenarios
        for seq_res, bat_res in zip(seq_card["scenario_results"], bat_card["scenario_results"]):
            assert seq_res["scenario_id"] == bat_res["scenario_id"]
            assert seq_res["classification"] == bat_res["classification"]
            assert seq_res["fired_rule_ids"] == bat_res["fired_rule_ids"]
            assert seq_res["alert_count"] == bat_res["alert_count"]

        # 3. Live dynamic equivalence test on representative challenge subset
        sample_scenarios = [
            generate_stg5_bound_01(),
            generate_stg5_bound_02(),
            generate_stg5_frag_01(),
            generate_stg5_nat_01(),
            generate_stg5_dist_01(),
        ]
        live_seq = evaluate_stage5_configuration(
            config_name="candidate_dual_threshold",
            description="Live Seq",
            scenarios=sample_scenarios,
            use_batched_threshold=False,
            measured_runs=1,
        )
        live_bat = evaluate_stage5_configuration(
            config_name="candidate_dual_threshold",
            description="Live Bat",
            scenarios=sample_scenarios,
            use_batched_threshold=True,
            measured_runs=1,
        )
        assert live_seq.true_positives == live_bat.true_positives
        assert live_seq.false_positives == live_bat.false_positives
        assert live_seq.true_negatives == live_bat.true_negatives
        assert live_seq.false_negatives == live_bat.false_negatives

    def test_08_stage5_artifact_schema_and_reproducibility(self):
        """Verify machine-readable Stage 5 artifact exists and passes all validation checks."""
        repo_root = Path(__file__).resolve().parent.parent
        artifact_path = repo_root / "docs" / "artifacts" / "phase_11_stage_5_audit_results.json"
        assert artifact_path.exists(), f"Artifact not found at {artifact_path}"

        with open(artifact_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert "metadata" in data
        assert "configurations" in data
        assert data["total_scenarios"] == 35

        configs = data["configurations"]
        assert "baseline_sequential" in configs
        assert "candidate_dual_threshold_sequential" in configs
        assert "candidate_dual_threshold_batched" in configs

        for name, card in configs.items():
            tp = card["true_positives"]
            fp = card["false_positives"]
            tn = card["true_negatives"]
            fn = card["false_negatives"]
            assert tp + fp + tn + fn == 35, f"{name}: confusion matrix does not sum to 35"
            assert card["overall_median_latency_ms"] > 0
            assert card["small_batch_median_ms"] > 0
            assert card["burst_median_ms"] > 0
            assert len(card["scenario_results"]) == 35
