"""
scripts/run_phase11_stage7_evaluation.py

Executes Phase 11 Stage 7: Offline Baseline Calibration and Hybrid-Value Evaluation Benchmark.
Evaluates 24 versioned scenarios across 4 configurations:
1. Baseline Sequential (Production Builtin Rules unmodified)
2. Candidate Fixed Endpoint (Threshold 100)
3. Candidate Dynamic Baseline (Rolling SMA 30m, mu + 2*sigma)
4. Candidate Hybrid Integrated (Multi-Layer Fusion + Correlation)

Exports machine-readable artifact to docs/artifacts/phase_11_stage_7_baseline_evaluation_results.json.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# Add backend directory to path
backend_path = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_path))

from app.services.evaluation_phase11_stage7 import run_full_stage7_evaluation_suite


def print_scorecard(card_name: str, configs: dict):
    print(f"\n--- {card_name.upper()} PARTITION SCORECARD ---")
    header = f"{'Configuration':<35} | {'TP':<3} | {'FP':<3} | {'TN':<3} | {'FN':<3} | {'Prec':<7} | {'Rec':<7} | {'FPR':<7} | {'FNR':<7} | {'F1':<7} | {'Med ms':<7}"
    print(header)
    print("-" * len(header))
    for cfg_name, cfg_data in configs.items():
        sub = cfg_data[card_name] if card_name in cfg_data else cfg_data
        line = (
            f"{cfg_name:<35} | "
            f"{sub['true_positives']:<3} | "
            f"{sub['false_positives']:<3} | "
            f"{sub['true_negatives']:<3} | "
            f"{sub['false_negatives']:<3} | "
            f"{sub['precision']*100:>6.1f}% | "
            f"{sub['recall']*100:>6.1f}% | "
            f"{sub['false_positive_rate']*100:>6.1f}% | "
            f"{sub['false_negative_rate']*100:>6.1f}% | "
            f"{sub['f1_score']:>7.4f} | "
            f"{sub['median_latency_ms']:>7.2f}"
        )
        print(line)


def print_calibration_matrix(matrix: list):
    print("\n--- DYNAMIC-BASELINE CALIBRATION MATRIX ---")
    header = f"{'Window':<8} | {'Strategy':<12} | {'Sigma':<5} | {'Floor':<5} | {'Cold-Start':<25} | {'Poisoning Ramp':<28} | {'Flash Crowd':<25} | {'Low-Rate Botnet':<25}"
    print(header)
    print("-" * len(header))
    for c in matrix:
        line = (
            f"{c['window_minutes']}m{'':<6} | "
            f"{c['update_strategy']:<12} | "
            f"{c['sigma_multiplier']:<5.1f} | "
            f"{c['min_floor']:<5} | "
            f"{c['cold_start_outcome'][:24]:<25} | "
            f"{c['poisoning_outcome'][:27]:<28} | "
            f"{c['flash_crowd_outcome'][:24]:<25} | "
            f"{c['low_rate_outcome'][:24]:<25}"
        )
        print(line)


def main():
    print("=" * 90)
    print("PHASE 11 STAGE 7: OFFLINE BASELINE CALIBRATION & HYBRID-VALUE EVALUATION BENCHMARK")
    print("Evaluating 24 Scenarios (8 Dev, 8 Val, 8 Held-Out Test) across 4 Configurations")
    print("=" * 90)

    t0 = time.time()
    results = run_full_stage7_evaluation_suite()
    elapsed = time.time() - t0

    repo_root = Path(__file__).resolve().parent.parent
    artifact_path = repo_root / "docs" / "artifacts" / "phase_11_stage_7_baseline_evaluation_results.json"
    artifact_path.parent.mkdir(parents=True, exist_ok=True)

    with open(artifact_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\n[OK] Benchmark execution completed in {elapsed:.2f} seconds.")
    print(f"[OK] Machine-readable artifact exported to: {artifact_path}")

    print_calibration_matrix(results["baseline_calibration_matrix"])

    configs = results["configurations"]
    print_scorecard("overall", configs)
    print_scorecard("dev_set", configs)
    print_scorecard("val_set", configs)
    print_scorecard("test_set", configs)

    print("\n" + "=" * 90)
    print("DIRECT COMPARISON: HYBRID INTEGRATED vs FIXED ENDPOINT AGGREGATION")
    print("=" * 90)
    comp = results["direct_comparison_hybrid_vs_endpoint"]
    print(f"  Additional Detections by Hybrid: {comp['additional_detections_count']}")
    for d in comp["additional_detections"]:
        print(f"    + {d['scenario_id']}: {d['name']} (Hybrid={d['hybrid_classification']}, Endpoint={d['endpoint_classification']})")
    print(f"  False Positive Reductions by Hybrid: {comp['false_positive_reductions_count']}")
    for d in comp["false_positive_reductions"]:
        print(f"    - {d['scenario_id']}: {d['name']} (Hybrid={d['hybrid_classification']}, Endpoint={d['endpoint_classification']})")

    cq = comp["correlation_quality"]
    print(f"\n  Correlation Quality:")
    print(f"    Endpoint Alone:   {cq['endpoint_alone']['total_alerts']} alerts -> {cq['endpoint_alone']['total_incidents']} incidents (ratio {cq['endpoint_alone']['incident_to_alert_ratio']})")
    print(f"    Hybrid Integrated:{cq['hybrid_integrated']['total_alerts']} alerts -> {cq['hybrid_integrated']['total_incidents']} incidents (ratio {cq['hybrid_integrated']['incident_to_alert_ratio']})")
    print(f"    Multi-Stage Note: {cq['hybrid_integrated']['multi_stage_correlation_benefit']}")

    lo = comp["latency_overhead"]
    print(f"\n  Latency Overhead:")
    print(f"    Endpoint Alone Median:    {lo['endpoint_alone_median_ms']:.2f} ms")
    print(f"    Hybrid Integrated Median: {lo['hybrid_integrated_median_ms']:.2f} ms")
    print(f"    Overhead:                 +{lo['overhead_ms']:.2f} ms (+{lo['overhead_percentage']:.1f}%)")
    print(f"    Verdict:                  {lo['overhead_verdict']}")
    print("=" * 90)


if __name__ == "__main__":
    main()
