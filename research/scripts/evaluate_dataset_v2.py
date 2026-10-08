#!/usr/bin/env python3
"""
research/scripts/evaluate_dataset_v2.py

Evaluates the SIEM Detection Engine against Dataset V2 Development and Validation splits.

CRITICAL RESEARCH INTEGRITY CONSTRAINTS:
- Held-out TEST SET (60 scenarios) is STRICTLY PROHIBITED from evaluation in Phase 2.
- Only DEV SET (100 scenarios) and VALIDATION SET (40 scenarios) are evaluated.
- Does NOT alter Dataset V1 or historical M0-M6 records.
- Outputs reproducible, mathematically verified metrics.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Ensure backend modules can be imported
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.base import Base
from app.models import DetectionRule, NormalizedEvent, Alert, ThreatIndicator
from app.rules import builtin_rules
from app.rules.engine import evaluate_rules_for_events


DATASET_DIR = PROJECT_ROOT / "research" / "datasets" / "dataset_v2"
DEV_SET_PATH = DATASET_DIR / "dev_set.json"
VAL_SET_PATH = DATASET_DIR / "val_set.json"
OUTPUT_REPORT_PATH = PROJECT_ROOT / "research" / "results" / "dataset_v2_evaluation_report.json"


def init_eval_db():
    """Creates an isolated in-memory SQLite database populated with all 14 active rules."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    # Seed all active built-in detection rules
    for r_data in builtin_rules():
        db.add(DetectionRule(**r_data))

    # Seed required TI indicators (e.g., blacklisted IP)
    db.add(ThreatIndicator(type="ip", value="203.0.113.66", description="Known botnet C2 IP", severity="high"))
    db.add(ThreatIndicator(type="ip", value="198.51.100.99", description="Malicious source IP", severity="high"))
    db.commit()

    return db, Session


def evaluate_split(split_name: str, split_path: Path) -> dict[str, Any]:
    """Evaluates detection performance on a specific split without tuning or leakage."""
    if not split_path.exists():
        raise FileNotFoundError(f"Split file not found: {split_path}")

    with open(split_path, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    print(f"\n=======================================================")
    print(f"Evaluating {split_name.upper()} ({len(scenarios)} scenarios)")
    print(f"Path: {split_path}")
    print(f"=======================================================")

    tp = 0
    fp = 0
    fn = 0
    tn = 0
    total_alerts = 0
    latencies: list[float] = []

    category_stats: dict[str, dict[str, int]] = {}
    rule_detections: dict[str, int] = {}

    for idx, sc in enumerate(scenarios):
        sc_id = sc["scenario_id"]
        cat = sc.get("attack_category", "Unknown")
        ground_truth = sc["ground_truth"]  # "ATTACK" or "BENIGN"
        expected = bool(sc.get("expected_detection", ground_truth == "ATTACK"))

        if cat not in category_stats:
            category_stats[cat] = {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "total": 0}
        category_stats[cat]["total"] += 1

        # Use an isolated evaluation session for each scenario to prevent state leakage
        db, _ = init_eval_db()

        # Parse & persist scenario events
        events_to_eval = []
        for ev_raw in sc.get("events", []):
            ts_str = ev_raw.get("timestamp")
            if ts_str:
                ts = datetime.fromisoformat(ts_str)
            else:
                ts = datetime.now(UTC)

            ev = NormalizedEvent(
                timestamp=ts,
                source_ip=ev_raw.get("source_ip"),
                destination_ip=ev_raw.get("destination_ip"),
                username=ev_raw.get("username"),
                event_type=ev_raw.get("event_type", "web_request"),
                event_category=ev_raw.get("event_category", "web"),
                severity=ev_raw.get("severity", "medium"),
                message=ev_raw.get("message", "Dataset V2 event"),
                request_path=ev_raw.get("request_path"),
                http_method=ev_raw.get("http_method", "GET"),
                status_code=ev_raw.get("status_code", 200),
                user_agent=ev_raw.get("user_agent"),
                geo_country=ev_raw.get("geo_country"),
            )
            db.add(ev)
            db.flush()
            events_to_eval.append(ev)

        # Measure detection execution latency
        t0 = time.perf_counter()
        alert_count = evaluate_rules_for_events(db, events_to_eval, auto_correlate=False)
        lat_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(lat_ms)

        total_alerts += alert_count
        fired = (alert_count > 0)

        # Track triggered rules
        alerts = db.query(Alert).all()
        for a in alerts:
            rule_name = a.title
            rule_detections[rule_name] = rule_detections.get(rule_name, 0) + 1

        # Classify confusion matrix
        if expected and fired:
            tp += 1
            category_stats[cat]["tp"] += 1
        elif not expected and fired:
            fp += 1
            category_stats[cat]["fp"] += 1
        elif expected and not fired:
            fn += 1
            category_stats[cat]["fn"] += 1
        else:
            tn += 1
            category_stats[cat]["tn"] += 1

        db.close()

    # Calculate metrics
    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) > 0 else 0.0
    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0.0

    print(f"Results for {split_name.upper()}:")
    print(f"  Scenarios: {len(scenarios)} (TP={tp}, FP={fp}, FN={fn}, TN={tn})")
    print(f"  Precision: {precision:.4f} | Recall: {recall:.4f} | F1: {f1:.4f} | FPR: {fpr:.4f}")
    print(f"  Avg Latency: {avg_latency:.2f} ms | Alert Volume: {total_alerts}")

    return {
        "split": split_name,
        "scenarios_evaluated": len(scenarios),
        "confusion_matrix": {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
        },
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "false_positive_rate": fpr,
            "average_latency_ms": avg_latency,
            "total_alerts": total_alerts,
        },
        "category_breakdown": category_stats,
        "rule_detections": rule_detections,
    }


def main():
    print("==================================================================")
    print("PHASE 2 — DATASET V2 EVALUATION (DEV + VALIDATION SETS ONLY)")
    print("CRITICAL: Held-out TEST SET remains strictly UNTOUCHED and unparsed.")
    print("==================================================================")

    dev_results = evaluate_split("development", DEV_SET_PATH)
    val_results = evaluate_split("validation", VAL_SET_PATH)

    report = {
        "evaluation_name": "Dataset V2 Detection Engine Evaluation",
        "evaluated_at": datetime.now(UTC).isoformat(),
        "phase": "PHASE_2",
        "benchmark_rules_evaluated": 14,
        "test_set_status": "UNTOUCHED_AND_HELD_OUT",
        "splits": {
            "dev_set": dev_results,
            "val_set": val_results,
        },
    }

    OUTPUT_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\n[OK] Report saved successfully to: {OUTPUT_REPORT_PATH}")


if __name__ == "__main__":
    main()
