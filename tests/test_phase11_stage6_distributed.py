"""
tests/test_phase11_stage6_distributed.py

Phase 11 Stage 6: Offline Distributed-Activity and Identity-Aware Detection Test Suite.
Validates:
1. Immutability of production detection rules (zero drift).
2. Telemetry & identity field audit: behavior when identity is None vs authenticated.
3. Corporate NAT multi-user resolution under identity-aware candidate.
4. Noisy attacker behind corporate NAT isolated and detected.
5. Distributed botnet detection via endpoint-level aggregation (closing Stage 5 FN blind spot).
6. Untrusted identity fallback and spoofed User-Agent resilience.
7. Strict partition separation: Dev (8), Val (8), Held-Out Test (8).
8. Stage 6 structured artifact integrity and mathematical validity.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

import pytest

from app.models import NormalizedEvent
from app.rules.builtin import builtin_rules
from app.rules.engine import event_matches_filters
from app.services.evaluation_phase11_stage6 import (
    Stage6AuditRunner,
    generate_stg6_dev_01,
    generate_stg6_dev_02,
    generate_stg6_dev_03,
    generate_stg6_dev_06,
    generate_stg6_test_01,
    generate_stg6_test_02,
    generate_stg6_test_03,
    generate_stg6_val_06,
    get_stage6_dev_scenarios,
    get_stage6_test_scenarios,
    get_stage6_val_scenarios,
)


class TestPhase11Stage6Distributed:

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

        # Verify no experimental rules (RULE-008B, RULE-008-USER, RULE-015) in production
        prod_ids = {r["rule_id"] for r in rules}
        assert "RULE-008B" not in prod_ids
        assert "RULE-008-USER" not in prod_ids
        assert "RULE-015" not in prod_ids

    def test_02_identity_field_telemetry_audit(self):
        """Verify NormalizedEvent identity fields and drop-on-null behavior."""
        event_auth = NormalizedEvent(
            source_ip="198.51.100.10",
            username="alice",
            request_path="/rest/products",
            event_category="web",
        )
        event_unauth = NormalizedEvent(
            source_ip="198.51.100.10",
            username=None,
            request_path="/rest/products",
            event_category="web",
        )

        assert event_auth.username == "alice"
        assert event_unauth.username is None
        assert not hasattr(event_auth, "session_id"), "NormalizedEvent should not possess a session_id column"

        # Verify naive group_by: ["source_ip", "username"] drops unauthenticated events
        group_by = ["source_ip", "username"]
        group_auth = tuple((field, getattr(event_auth, field, None)) for field in group_by)
        group_unauth = tuple((field, getattr(event_unauth, field, None)) for field in group_by)

        assert not any(val in (None, "") for _, val in group_auth)
        assert any(val in (None, "") for _, val in group_unauth), "Unauthenticated event must have None in group_by"

    def test_03_nat_multi_user_resolution_identity_aware(self):
        """Verify identity-aware candidate resolves shared NAT false positives."""
        runner_ip = Stage6AuditRunner(config_name="candidate_source_ip_dual", use_batched_threshold=True)
        runner_ident = Stage6AuditRunner(config_name="candidate_identity_aware", use_batched_threshold=True)

        sc_dev01 = generate_stg6_dev_01()  # 3 users, 25 reqs each = 75 total from single IP

        # Source-IP grouping alerts because 75 > 60 (FP)
        res_ip = runner_ip.evaluate_scenario(sc_dev01, measured_runs=1)
        assert res_ip.alert_count >= 1
        assert res_ip.classification == "FP"

        # Identity-aware grouping evaluates per user (25 < 60 each) -> No alert (TN)
        res_ident = runner_ident.evaluate_scenario(sc_dev01, measured_runs=1)
        assert res_ident.alert_count == 0
        assert res_ident.classification == "TN"

    def test_04_noisy_client_behind_nat_isolated(self):
        """Verify malicious user behind NAT is detected under identity-aware candidate."""
        runner_ident = Stage6AuditRunner(config_name="candidate_identity_aware", use_batched_threshold=True)

        sc_dev02 = generate_stg6_dev_02()  # mallory sends 75 reqs behind NAT
        res_ident = runner_ident.evaluate_scenario(sc_dev02, measured_runs=1)

        assert res_ident.alert_count >= 1
        assert res_ident.classification == "TP"
        assert "RULE-008-USER" in res_ident.fired_rule_ids or "RULE-008" in res_ident.fired_rule_ids

    def test_05_distributed_botnet_detection_endpoint_aggregation(self):
        """Verify endpoint-level aggregation detects distributed scraping missed by single-IP rules."""
        runner_ip = Stage6AuditRunner(config_name="candidate_source_ip_dual", use_batched_threshold=True)
        runner_ep = Stage6AuditRunner(config_name="candidate_endpoint_aggregate", use_batched_threshold=True)

        sc_dev03 = generate_stg6_dev_03()  # 5 IPs, 25 reqs each = 125 total to /rest/products

        # Single-IP candidate suffers False Negative (each IP sends 25 < 60)
        res_ip = runner_ip.evaluate_scenario(sc_dev03, measured_runs=1)
        assert res_ip.alert_count == 0
        assert res_ip.classification == "FN"

        # Endpoint-aggregate candidate detects coordinated spike (125 > 100) -> True Positive
        res_ep = runner_ep.evaluate_scenario(sc_dev03, measured_runs=1)
        assert res_ep.alert_count >= 1
        assert "RULE-015" in res_ep.fired_rule_ids
        assert res_ep.classification == "TP"

    def test_06_untrusted_and_spoofed_identity_fallback(self):
        """Verify source-IP fallback handles forged rotating usernames and randomized User-Agents."""
        runner_hybrid = Stage6AuditRunner(config_name="candidate_hybrid_integrated", use_batched_threshold=True)

        # Rotated username headers: attacker sends 75 reqs with fake_user_x
        sc_val06 = generate_stg6_val_06()
        res_val06 = runner_hybrid.evaluate_scenario(sc_val06, measured_runs=1)
        assert res_val06.alert_count >= 1
        assert "RULE-008" in res_val06.fired_rule_ids
        assert res_val06.classification == "TP"

        # Randomized User-Agents: attacker rotates Chrome, Safari, curl across 80 reqs
        sc_dev06 = generate_stg6_dev_06()
        res_dev06 = runner_hybrid.evaluate_scenario(sc_dev06, measured_runs=1)
        assert res_dev06.alert_count >= 1
        assert "RULE-008" in res_dev06.fired_rule_ids
        assert res_dev06.classification == "TP"

    def test_07_dev_val_test_partition_independence(self):
        """Verify strict partition independence: Dev (8), Val (8), Held-Out Test (8)."""
        dev_scenarios = get_stage6_dev_scenarios()
        val_scenarios = get_stage6_val_scenarios()
        test_scenarios = get_stage6_test_scenarios()

        assert len(dev_scenarios) == 8
        assert len(val_scenarios) == 8
        assert len(test_scenarios) == 8

        dev_ids = {s.scenario_id for s in dev_scenarios}
        val_ids = {s.scenario_id for s in val_scenarios}
        test_ids = {s.scenario_id for s in test_scenarios}

        # Assert no overlap
        assert len(dev_ids.intersection(val_ids)) == 0, "Dev and Val partitions must be disjoint"
        assert len(val_ids.intersection(test_ids)) == 0, "Val and Test partitions must be disjoint"
        assert len(dev_ids.intersection(test_ids)) == 0, "Dev and Test partitions must be disjoint"

        # Assert partition counts
        dev_benign = sum(1 for s in dev_scenarios if s.category == "benign")
        dev_attack = sum(1 for s in dev_scenarios if s.category == "attack")
        assert dev_benign == 4 and dev_attack == 4, "Dev set must have 4 benign and 4 attack scenarios"

        val_benign = sum(1 for s in val_scenarios if s.category == "benign")
        val_attack = sum(1 for s in val_scenarios if s.category == "attack")
        assert val_benign == 3 and val_attack == 5, "Val set must have 3 benign and 5 attack scenarios"

        test_benign = sum(1 for s in test_scenarios if s.category == "benign")
        test_attack = sum(1 for s in test_scenarios if s.category == "attack")
        assert test_benign == 3 and test_attack == 5, "Test set must have 3 benign and 5 attack scenarios"

    def test_08_stage6_held_out_validation_scenario_outcomes(self):
        """Verify held-out test scenarios on identity and endpoint architectures."""
        runner_ident = Stage6AuditRunner(config_name="candidate_identity_aware", use_batched_threshold=True)
        runner_hybrid = Stage6AuditRunner(config_name="candidate_hybrid_integrated", use_batched_threshold=True)

        # Held-out Test 01: Enterprise gateway 5 users (110 reqs) -> TN under identity-aware candidate
        sc_t01 = generate_stg6_test_01()
        res_t01_ident = runner_ident.evaluate_scenario(sc_t01, measured_runs=1)
        assert res_t01_ident.classification == "TN"
        assert res_t01_ident.alert_count == 0

        # Held-out Test 02: Rogue insider behind NAT (85 reqs) -> MUST be TP under identity-aware candidate
        sc_t02 = generate_stg6_test_02()
        res_t02 = runner_ident.evaluate_scenario(sc_t02, measured_runs=1)
        assert res_t02.classification == "TP"
        assert "RULE-008" in res_t02.fired_rule_ids

        # Held-out Test 03: Distributed low-and-slow botnet 10 IPs (180 reqs) -> MUST be TP under hybrid/endpoint
        sc_t03 = generate_stg6_test_03()
        res_t03 = runner_hybrid.evaluate_scenario(sc_t03, measured_runs=1)
        assert res_t03.classification == "TP"
        assert "RULE-015" in res_t03.fired_rule_ids
