"""
scripts/run_phase11_stage3_evaluation.py

Offline CLI runner for Phase 11 Stage 3 Detection Evaluation.
Executes the evaluation hermetically against in-memory SQLite, performs 5 measured runs per scenario,
computes confusion matrices and latency statistics, and persists the structured artifact.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Set up paths and isolated environment
repo_root = Path(__file__).parent.parent
sys.path.insert(0, str(repo_root / "backend"))

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AUTO_CREATE_TABLES"] = "true"
os.environ["ENABLE_JUICE_SHOP_CONNECTOR"] = "false"
os.environ["JWT_SECRET_KEY"] = "stage3-evaluation-secret-key-12345"

from app.services.evaluation_phase11_stage3 import run_full_stage3_suite


def main():
    print("=" * 80)
    print("PHASE 11 — STAGE 3: OFFLINE DETECTION CANDIDATE EVALUATION")
    print("=" * 80)
    print("Executing hermetic in-memory multi-run benchmarking (1 warmup + 5 measured runs)...")

    results = run_full_stage3_suite()

    # Destination artifact
    artifacts_dir = repo_root / "docs" / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    out_file = artifacts_dir / "phase_11_stage_3_candidate_evaluation_results.json"

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\n[SUCCESS] Candidate evaluation results saved to: {out_file}")

    # Print summary scorecards
    print("\n--- STANDARD 17 SCENARIOS SCORECARD ---")
    std = results["standard_17_scenarios"]
    for key, card in std.items():
        print(
            f"Config: {key:<30} | TP={card['true_positives']} FP={card['false_positives']} TN={card['true_negatives']} FN={card['false_negatives']} | "
            f"Prec={card['precision']*100:6.2f}% Rec={card['recall']*100:6.2f}% F1={card['f1_score']:0.4f} | "
            f"MedianLat={card['overall_median_latency_ms']:6.2f}ms P95={card['overall_p95_latency_ms']:8.2f}ms Max={card['overall_max_latency_ms']:8.2f}ms | Dups={card['total_duplicate_alerts']}"
        )

    print("\n--- FULL 21 SCENARIOS (INCLUDING ADVERSARIAL CASES) SCORECARD ---")
    full = results["full_21_scenarios_including_adversarial"]
    for key, card in full.items():
        print(
            f"Config: {key:<30} | TP={card['true_positives']} FP={card['false_positives']} TN={card['true_negatives']} FN={card['false_negatives']} | "
            f"Prec={card['precision']*100:6.2f}% Rec={card['recall']*100:6.2f}% F1={card['f1_score']:0.4f} | "
            f"BlindSpots={card['blind_spots_count']} | MedianLat={card['overall_median_latency_ms']:6.2f}ms P95={card['overall_p95_latency_ms']:8.2f}ms"
        )

    print("=" * 80)


if __name__ == "__main__":
    main()
