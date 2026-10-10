"""
scripts/run_phase11_stage4_evaluation.py

Offline CLI runner for Phase 11 Stage 4 Detection Evaluation.
Executes the hardened candidate evaluation across all 23 scenarios,
measures multi-run latency (1 warmup + 5 measured runs per scenario),
computes scorecards, and persists docs/artifacts/phase_11_stage_4_candidate_evaluation_results.json.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

repo_root = Path(__file__).parent.parent
sys.path.insert(0, str(repo_root / "backend"))

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AUTO_CREATE_TABLES"] = "true"
os.environ["ENABLE_JUICE_SHOP_CONNECTOR"] = "false"
os.environ["JWT_SECRET_KEY"] = "stage4-evaluation-secret-key-12345"

from app.services.evaluation_phase11_stage4 import run_full_stage4_suite


def main():
    print("=" * 85)
    print("PHASE 11 — STAGE 4: OFFLINE CANDIDATE HARDENING & ADVERSARIAL RE-EVALUATION")
    print("=" * 85)
    print("Executing hermetic in-memory multi-run benchmarking (1 warmup + 5 measured runs)...")

    results = run_full_stage4_suite()

    artifacts_dir = repo_root / "docs" / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    out_file = artifacts_dir / "phase_11_stage_4_candidate_evaluation_results.json"

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\n[SUCCESS] Stage 4 evaluation artifact saved to: {out_file}")

    print("\n--- STAGE 4 SCORECARD SUMMARY (23 SCENARIOS) ---")
    configs = results["configurations"]
    for key, card in configs.items():
        print(
            f"Config: {key:<40} | TP={card['true_positives']} FP={card['false_positives']} TN={card['true_negatives']} FN={card['false_negatives']} | "
            f"Prec={card['precision']*100:6.2f}% Rec={card['recall']*100:6.2f}% F1={card['f1_score']:0.4f} | "
            f"BlindSpots={card['blind_spots_count']} | MedianLat={card['overall_median_latency_ms']:6.2f}ms P95={card['overall_p95_latency_ms']:8.2f}ms Max={card['overall_max_latency_ms']:8.2f}ms"
        )
    print("=" * 85)


if __name__ == "__main__":
    main()
