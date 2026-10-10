"""
scripts/run_phase11_stage6_evaluation.py

Executes Phase 11 Stage 6: Offline Distributed-Activity and Identity-Aware Detection Evaluation.
Evaluates 24 versioned scenarios across 5 configurations:
1. Baseline Sequential
2. Candidate Source-IP Dual-Threshold
3. Candidate Identity-Aware
4. Candidate Endpoint-Aggregate
5. Candidate Hybrid Integrated

Exports machine-readable artifact to docs/artifacts/phase_11_stage_6_distributed_evaluation_results.json.
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

from app.services.evaluation_phase11_stage6 import run_full_stage6_audit_suite


def print_scorecard(card_name: str, card: dict):
    print(f"\n--- {card_name.upper()} ---")
    header = f"{'Configuration':<35} | {'TP':<3} | {'FP':<3} | {'TN':<3} | {'FN':<3} | {'Prec':<7} | {'Rec':<7} | {'FPR':<7} | {'F1':<7} | {'Med ms':<7}"
    print(header)
    print("-" * len(header))
    for cfg_name, cfg_data in card.items():
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
            f"{sub['f1_score']:>7.4f} | "
            f"{sub['median_latency_ms']:>7.2f}"
        )
        print(line)


def main():
    print("=" * 80)
    print("PHASE 11 STAGE 6: DISTRIBUTED-ACTIVITY & IDENTITY-AWARE DETECTION BENCHMARK")
    print("Evaluating 24 Scenarios (8 Dev, 8 Val, 8 Held-Out Test) across 5 Configurations")
    print("=" * 80)

    t0 = time.time()
    results = run_full_stage6_audit_suite()
    elapsed = time.time() - t0

    repo_root = Path(__file__).resolve().parent.parent
    artifact_path = repo_root / "docs" / "artifacts" / "phase_11_stage_6_distributed_evaluation_results.json"
    artifact_path.parent.mkdir(parents=True, exist_ok=True)

    with open(artifact_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\n[OK] Evaluation completed in {elapsed:.2f} seconds.")
    print(f"[OK] Machine-readable artifact exported to: {artifact_path}")

    configs = results["configurations"]
    print_scorecard("overall", configs)
    print_scorecard("dev_set", configs)
    print_scorecard("val_set", configs)
    print_scorecard("test_set", configs)

    print("\n" + "=" * 80)
    print("LATENCY PROFILES (SMALL BATCH vs BURST):")
    print("=" * 80)
    for key, data in configs.items():
        print(
            f"  {key:<35}: Overall Med={data['overall']['median_latency_ms']:.2f}ms, "
            f"Small-Batch (<=25 ev) Med={data['small_batch_median_ms']:.2f}ms, "
            f"Burst (>=80 ev) Med={data['burst_median_ms']:.2f}ms, "
            f"P95={data['overall_p95_latency_ms']:.2f}ms, "
            f"Max={data['overall_max_latency_ms']:.2f}ms"
        )
    print("=" * 80)


if __name__ == "__main__":
    main()
