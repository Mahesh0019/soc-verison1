"""
research/evaluate_sysmon_detection.py

Phase 5 Endpoint Detection Evaluation:
- Evaluates Windows Sysmon endpoint detection rules (ENDPOINT-001 through ENDPOINT-005)
  against the controlled Sysmon Benchmark Dataset V1 (DEV and VALIDATION splits ONLY).
- The HELD-OUT TEST split is STRICTLY UNTOUCHED and NOT evaluated.
- Measures: TP, FP, FN, TN, Precision, Recall, F1, FPR, Detection Latency, Alert Volume.
- Computes per-rule evaluation breakdowns and false-positive resistance analysis.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

# Set sqlite memory db before backend imports
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AUTO_CREATE_TABLES"] = "true"

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.base import Base
from app.models import Alert, DetectionRule, NormalizedEvent, RuleHealthRecord
from app.rules import evaluate_rules_for_events
from app.services.detection_quality_service import evaluate_rule_health
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users


def evaluate_split(db, scenarios: list[dict], split_name: str) -> dict:
    tp = 0
    fp = 0
    fn = 0
    tn = 0
    latencies = []
    total_alerts = 0
    rule_detections: dict[str, dict] = {}

    rules = db.query(DetectionRule).filter(DetectionRule.enabled.is_(True)).all()
    for r in rules:
        rule_detections[r.name] = {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "alerts": 0}

    for scen in scenarios:
        # Clear previous transient events/alerts between scenario tests
        db.query(Alert).delete()
        db.query(NormalizedEvent).delete()
        db.flush()

        events = []
        for raw in scen.get("events", []):
            ts = datetime.fromisoformat(raw["timestamp"]) if "timestamp" in raw else datetime.now(UTC)
            ev = NormalizedEvent(
                timestamp=ts,
                source_type=raw.get("source_type", "SYSMON"),
                source_name=raw.get("source_name", "Microsoft-Windows-Sysmon"),
                hostname=raw.get("hostname"),
                username=raw.get("username"),
                process=raw.get("process"),
                parent_process=raw.get("parent_process"),
                process_id=raw.get("process_id"),
                parent_process_id=raw.get("parent_process_id"),
                command_line=raw.get("command_line"),
                image_path=raw.get("image_path"),
                file_hash=raw.get("file_hash"),
                source_ip=raw.get("source_ip"),
                destination_ip=raw.get("destination_ip"),
                source_port=raw.get("source_port"),
                destination_port=raw.get("destination_port"),
                protocol=raw.get("protocol"),
                dns_query=raw.get("dns_query"),
                dns_response=raw.get("dns_response"),
                event_type=raw.get("event_type", "sysmon_process_create"),
                event_category=raw.get("event_category", "endpoint"),
                severity=raw.get("severity", "low"),
                message=raw.get("message", "Sysmon test event"),
                raw_reference=raw.get("raw_reference"),
                raw_log=raw.get("raw_log"),
            )
            db.add(ev)
            events.append(ev)
        db.flush()

        t0 = time.perf_counter()
        # Evaluate rules without cross-source correlation (strictly preserving Phase 5 boundary)
        alert_count = evaluate_rules_for_events(db, events, auto_correlate=False)
        dur_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(dur_ms)
        total_alerts += alert_count

        fired_alerts = db.query(Alert).all()
        fired_titles = {a.title for a in fired_alerts}

        is_attack = scen["ground_truth"] == "ATTACK"
        detected = len(fired_alerts) > 0

        if is_attack and detected:
            tp += 1
        elif is_attack and not detected:
            fn += 1
            print(f"  [DEBUG FN] {scen['id']}: {scen['desc']} (Expected: {scen.get('expected_rule')})")
        elif not is_attack and detected:
            fp += 1
            print(f"  [DEBUG FP] {scen['id']}: {scen['desc']}")
        else:
            tn += 1

        for r in rules:
            rfired = r.name in fired_titles
            if is_attack and rfired:
                rule_detections[r.name]["tp"] += 1
            elif is_attack and not rfired:
                rule_detections[r.name]["fn"] += 1
            elif not is_attack and rfired:
                rule_detections[r.name]["fp"] += 1
            else:
                rule_detections[r.name]["tn"] += 1
            if rfired:
                rule_detections[r.name]["alerts"] += 1

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) > 0 else 0.0
    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
    avg_lat = round(sum(latencies) / len(latencies), 3) if latencies else 0.0
    max_lat = round(max(latencies), 3) if latencies else 0.0

    return {
        "split": split_name,
        "scenarios_evaluated": len(scenarios),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": fpr,
        "total_alerts": total_alerts,
        "avg_detection_latency_ms": avg_lat,
        "max_detection_latency_ms": max_lat,
        "rule_detections": rule_detections,
    }


def main():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    db = SessionLocal()

    try:
        ensure_users(db)
        ensure_builtin_rules(db)
        ensure_indicators(db)

        dataset_path = Path(__file__).resolve().parent / "datasets" / "sysmon_v1"
        dev_file = dataset_path / "dev_set.json"
        val_file = dataset_path / "val_set.json"
        manifest_file = dataset_path / "sysmon_v1_manifest.json"

        if not dev_file.exists() or not val_file.exists():
            print("Error: Sysmon V1 dataset not found. Run generate_sysmon_v1.py first.")
            return

        with open(dev_file, "r", encoding="utf-8") as f:
            dev_scenarios = json.load(f)
        with open(val_file, "r", encoding="utf-8") as f:
            val_scenarios = json.load(f)
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        print("=" * 65)
        print("PHASE 5 — SYSMON ENDPOINT DETECTION BENCHMARK EVALUATION")
        print("=" * 65)
        print(f"Dataset: {manifest['dataset_name']} ({manifest['dataset_version']})")
        print(f"Total Scenarios: {manifest['total_scenarios']}")
        print("Partitions:")
        print(f"  - Development: {manifest['split_distribution']['development']['total']} scenarios")
        print(f"  - Validation:  {manifest['split_distribution']['validation']['total']} scenarios")
        print(f"  - Test:        {manifest['split_distribution']['test']['total']} scenarios [STRICTLY HELD OUT]")
        print("=" * 65)

        # 1. Evaluate Development Set
        dev_res = evaluate_split(db, dev_scenarios, "development")
        print(f"\n[DEV SET RESULTS]")
        print(f"Scenarios: {dev_res['scenarios_evaluated']} | TP: {dev_res['tp']} | FP: {dev_res['fp']} | FN: {dev_res['fn']} | TN: {dev_res['tn']}")
        print(f"Precision: {dev_res['precision']:.4f} | Recall: {dev_res['recall']:.4f} | F1: {dev_res['f1_score']:.4f} | FPR: {dev_res['false_positive_rate']:.4f}")
        print(f"Avg Latency: {dev_res['avg_detection_latency_ms']} ms | Max Latency: {dev_res['max_detection_latency_ms']} ms")

        # 2. Evaluate Validation Set
        val_res = evaluate_split(db, val_scenarios, "validation")
        print(f"\n[VALIDATION SET RESULTS]")
        print(f"Scenarios: {val_res['scenarios_evaluated']} | TP: {val_res['tp']} | FP: {val_res['fp']} | FN: {val_res['fn']} | TN: {val_res['tn']}")
        print(f"Precision: {val_res['precision']:.4f} | Recall: {val_res['recall']:.4f} | F1: {val_res['f1_score']:.4f} | FPR: {val_res['false_positive_rate']:.4f}")
        print(f"Avg Latency: {val_res['avg_detection_latency_ms']} ms | Max Latency: {val_res['max_detection_latency_ms']} ms")

        # Combined Dev + Val Metrics
        combined_tp = dev_res["tp"] + val_res["tp"]
        combined_fp = dev_res["fp"] + val_res["fp"]
        combined_fn = dev_res["fn"] + val_res["fn"]
        combined_tn = dev_res["tn"] + val_res["tn"]
        comb_prec = round(combined_tp / (combined_tp + combined_fp), 4) if (combined_tp + combined_fp) > 0 else 0.0
        comb_rec = round(combined_tp / (combined_tp + combined_fn), 4) if (combined_tp + combined_fn) > 0 else 0.0
        comb_f1 = round(2 * comb_prec * comb_rec / (comb_prec + comb_rec), 4) if (comb_prec + comb_rec) > 0 else 0.0
        comb_fpr = round(combined_fp / (combined_fp + combined_tn), 4) if (combined_fp + combined_tn) > 0 else 0.0

        print(f"\n[COMBINED DEV + VAL METRICS]")
        print(f"Scenarios: {len(dev_scenarios) + len(val_scenarios)} | TP: {combined_tp} | FP: {combined_fp} | FN: {combined_fn} | TN: {combined_tn}")
        print(f"Precision: {comb_prec:.4f} | Recall: {comb_rec:.4f} | F1: {comb_f1:.4f} | FPR: {comb_fpr:.4f}")

        # Per-Rule Health Evaluation
        print("\n[PER-RULE ENDPOINT BREAKDOWN]")
        endpoint_rule_names = [
            "Suspicious process execution",
            "Suspicious parent-child process relationship",
            "Suspicious process network connection",
            "Suspicious DNS activity",
            "Suspicious executable/file creation",
        ]

        per_rule_report = {}
        for rname in endpoint_rule_names:
            rule_obj = db.query(DetectionRule).filter(DetectionRule.name == rname).first()
            if not rule_obj:
                continue
            d_stat = dev_res["rule_detections"].get(rname, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
            v_stat = val_res["rule_detections"].get(rname, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
            r_tp = d_stat["tp"] + v_stat["tp"]
            r_fp = d_stat["fp"] + v_stat["fp"]
            r_fn = d_stat["fn"] + v_stat["fn"]
            r_tn = d_stat["tn"] + v_stat["tn"]
            p = round(r_tp / (r_tp + r_fp), 4) if (r_tp + r_fp) > 0 else 0.0
            r = round(r_tp / (r_tp + r_fn), 4) if (r_tp + r_fn) > 0 else 0.0
            f = round(2 * p * r / (p + r), 4) if (p + r) > 0 else 0.0
            health = evaluate_rule_health(db, rule_obj)

            per_rule_report[rule_obj.rule_id] = {
                "name": rname,
                "rule_id": rule_obj.rule_id,
                "category": rule_obj.category,
                "severity": rule_obj.severity,
                "tp": r_tp,
                "fp": r_fp,
                "fn": r_fn,
                "tn": r_tn,
                "precision": p,
                "recall": r,
                "f1_score": f,
                "health_score": health.health_score,
                "health_status": health.health_tier,
            }
            print(f"  * {rule_obj.rule_id} ({rname[:38]}): TP={r_tp}, FP={r_fp}, P={p:.2f}, R={r:.2f}, F1={f:.2f}, Health={health.health_score}/100 ({health.health_tier})")

        # Persist results
        res_dir = Path(__file__).resolve().parent / "results"
        res_dir.mkdir(parents=True, exist_ok=True)
        evaluation_payload = {
            "evaluation_timestamp": datetime.now(UTC).isoformat(),
            "benchmark_dataset": "RESEARCH_SYSMON_DATASET_V1",
            "development_split": dev_res,
            "validation_split": val_res,
            "combined_dev_val": {
                "scenarios": len(dev_scenarios) + len(val_scenarios),
                "tp": combined_tp,
                "fp": combined_fp,
                "fn": combined_fn,
                "tn": combined_tn,
                "precision": comb_prec,
                "recall": comb_rec,
                "f1_score": comb_f1,
                "false_positive_rate": comb_fpr,
            },
            "per_rule_report": per_rule_report,
            "test_split_status": {
                "scenarios": manifest["split_distribution"]["test"]["total"],
                "status": "HELD_OUT_UNTOUCHED",
                "sha256": manifest["split_distribution"]["test"]["sha256"],
                "note": "Per strict research protocol, test split is held out and was not accessed during development or tuning.",
            },
        }

        with open(res_dir / "sysmon_v1_evaluation.json", "w", encoding="utf-8") as f:
            json.dump(evaluation_payload, f, indent=2)

        print(f"\nEvaluation output written to {res_dir / 'sysmon_v1_evaluation.json'}")
        print("=" * 65)

    finally:
        db.close()


if __name__ == "__main__":
    main()
