"""
scripts/run_phase11_stage5_audit.py

Executes Phase 11 Stage 5: Independent Robustness and Reproducibility Audit Suite.
Evaluates 35 standardized scenarios (23 existing + 12 new Stage 5 challenges)
across Baseline Sequential, Candidate Dual-Threshold Sequential, Candidate Dual-Threshold Batched,
Candidate Hardened Single Batched, and Candidate Independent 404 Batched.

Exports machine-readable artifact to docs/artifacts/phase_11_stage_5_audit_results.json.
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

from app.services.evaluation_phase11_stage5 import run_full_stage5_audit_suite


def main():
    print("=" * 80)
    print("PHASE 11 STAGE 5: INDEPENDENT ROBUSTNESS & REPRODUCIBILITY AUDIT")
    print("Evaluating 35 Scenarios across 5 Configurations with repeated measurements")
    print("=" * 80)

    t0 = time.time()
    results = run_full_stage5_audit_suite()
    elapsed = time.time() - t0

    # Destination artifact path
    repo_root = Path(__file__).resolve().parent.parent
    artifact_path = repo_root / "docs" / "artifacts" / "phase_11_stage_5_audit_results.json"
    artifact_path.parent.mkdir(parents=True, exist_ok=True)

    with open(artifact_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\n[OK] Audit execution completed in {elapsed:.2f} seconds.")
    print(f"[OK] Machine-readable artifact exported to: {artifact_path}")
    print("\n" + "=" * 80)
    print("CONFIGURATION SUMMARY TABLE (35 SCENARIOS)")
    print("=" * 80)
    header = f"{'Configuration':<38} | {'TP':<3} | {'FP':<3} | {'TN':<3} | {'FN':<3} | {'Prec':<7} | {'Rec':<7} | {'FPR':<7} | {'F1':<7} | {'Med ms':<7} | {'P95 ms':<7}"
    print(header)
    print("-" * len(header))

    configs = results["configurations"]
    for key, data in configs.items():
        line = (
            f"{key:<38} | "
            f"{data['true_positives']:<3} | "
            f"{data['false_positives']:<3} | "
            f"{data['true_negatives']:<3} | "
            f"{data['false_negatives']:<3} | "
            f"{data['precision']*100:>6.1f}% | "
            f"{data['recall']*100:>6.1f}% | "
            f"{data['false_positive_rate']*100:>6.1f}% | "
            f"{data['f1_score']:>7.4f} | "
            f"{data['overall_median_latency_ms']:>7.2f} | "
            f"{data['overall_p95_latency_ms']:>7.2f}"
        )
        print(line)

    print("=" * 80)
    print("\nLATENCY PROFILES (SMALL BATCH vs BURST):")
    for key, data in configs.items():
        print(
            f"  {key:<38}: Overall Med={data['overall_median_latency_ms']:.2f}ms, "
            f"Small-Batch (<=10 ev) Med={data['small_batch_median_ms']:.2f}ms, "
            f"Burst (>=100 ev) Med={data['burst_median_ms']:.2f}ms, "
            f"Max={data['overall_max_latency_ms']:.2f}ms"
        )
    print("=" * 80)


if __name__ == "__main__":
    main()
