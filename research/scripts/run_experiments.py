"""
research/scripts/run_experiments.py

Reproducible Research Experiment Runner:
Executes M0 through M6 benchmark evaluation pipeline against controlled ground truth datasets,
calculates research metrics (Precision, Recall, F1, FPR, Genuine Attack Retention, Latency),
and persists raw run artifacts to research/runs/ and summary results to research/results/.
"""

import csv
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import sys

# Ensure backend directory is in sys.path
root_dir = Path(__file__).resolve().parents[2]
backend_dir = root_dir / "backend"
sys.path.insert(0, str(backend_dir))

# Configure test database environment
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AUTO_CREATE_TABLES"] = "true"
os.environ["ENABLE_JUICE_SHOP_CONNECTOR"] = "false"

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.services.experiment_service import run_full_benchmark
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users


def main():
    print("=" * 70)
    print("REPRODUCIBLE RESEARCH EXPERIMENT RUNNER (M0 - M6)")
    print("=" * 70)

    # 1. Setup isolated database
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        ensure_users(db)
        ensure_builtin_rules(db)
        ensure_indicators(db)

        print("[+] Environment initialized. Executing M0-M6 benchmark suite...")
        start_time = datetime.now(UTC)
        result = run_full_benchmark(db)

        matrix = result.comparison_matrix
        print(f"[+] Benchmark execution completed. Evaluated {len(matrix)} operational modes.\n")

        # Create output directories
        runs_dir = root_dir / "research" / "runs"
        results_dir = root_dir / "research" / "results"
        runs_dir.mkdir(parents=True, exist_ok=True)
        results_dir.mkdir(parents=True, exist_ok=True)

        timestamp_str = start_time.strftime("%Y%m%d_%H%M%S")

        # 2. Persist raw run artifacts
        raw_artifacts = []
        for row in matrix:
            run_data = {
                "experiment_id": result.experiment_id,
                "mode": row.mode,
                "name": row.name,
                "description": row.description,
                "timestamp": timestamp_str,
                "dataset_version": result.dataset_version,
                "total_events": row.total_events,
                "alerts_generated": row.alerts_generated,
                "incidents_promoted": row.incidents_promoted,
                "true_positives": row.true_positives,
                "false_positives": row.false_positives,
                "false_negatives": row.false_negatives,
                "true_negatives": row.true_negatives,
                "precision": row.precision,
                "recall": row.recall,
                "f1_score": row.f1_score,
                "false_positive_reduction_pct": row.fp_reduction_pct,
                "genuine_attack_retention_pct": row.attack_retention_pct,
                "mtti_minutes": row.mtti_minutes,
                "evidence_retrieval_ms": row.evidence_retrieval_ms,
                "ai_analyst_agreement_pct": row.ai_analyst_agreement_pct,
            }
            raw_artifacts.append(run_data)

            run_file = runs_dir / f"run_{timestamp_str}_{row.mode}.json"
            with open(run_file, "w", encoding="utf-8") as f:
                json.dump(run_data, f, indent=2)

        # 3. Persist summary JSON & CSV matrix
        results_json_file = results_dir / "benchmark_matrix.json"
        with open(results_json_file, "w", encoding="utf-8") as f:
            json.dump({
                "experiment_id": result.experiment_id,
                "timestamp": timestamp_str,
                "dataset_version": result.dataset_version,
                "comparison_matrix": raw_artifacts,
                "summary": result.summary,
            }, f, indent=2)

        results_csv_file = results_dir / "benchmark_matrix.csv"
        headers = [
            "mode", "name", "precision", "recall", "f1_score",
            "false_positives", "fp_reduction_pct", "attack_retention_pct",
            "mtti_minutes", "evidence_retrieval_ms"
        ]
        with open(results_csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
            writer.writeheader()
            for r in raw_artifacts:
                writer.writerow(r)

        # 4. Print benchmark report table
        print(f"{'Mode':<6} | {'Architecture':<35} | {'Prec':<6} | {'Rec':<6} | {'F1':<6} | {'FP Red':<8} | {'Retention':<10} | {'MTTI':<8} | {'Evid Latency'}")
        print("-" * 110)
        for r in raw_artifacts:
            print(
                f"{r['mode']:<6} | "
                f"{r['name']:<35} | "
                f"{r['precision']:<6.2f} | "
                f"{r['recall']:<6.2f} | "
                f"{r['f1_score']:<6.2f} | "
                f"{r['false_positive_reduction_pct']:<7.1f}% | "
                f"{r['genuine_attack_retention_pct']:<9.1f}% | "
                f"{r['mtti_minutes']:<7.1f}m | "
                f"{r['evidence_retrieval_ms']}ms"
            )
        print("-" * 110)
        print(f"[+] Results saved to {results_csv_file} and {results_json_file}")

    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


if __name__ == "__main__":
    main()
