"""
research/evaluate_network_detection.py

Phase 4 Network Detection Evaluation:
- Evaluates Zeek network detection rules (NETWORK-001 through NETWORK-006)
  against the controlled Network Benchmark Dataset V1 (DEV and VALIDATION splits ONLY).
- The HELD-OUT TEST split is STRICTLY UNTOUCHED and NOT evaluated.
- Measures: TP, FP, FN, TN, Precision, Recall, F1, FPR, Detection Latency, Alert Volume.
- Computes per-rule evaluation breakdowns and persists Rule Health records.
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
                source_type=raw.get("source_type", "ZEEK"),
                source_name=raw.get("source_name", "zeek-conn"),
                source_ip=raw.get("source_ip"),
                destination_ip=raw.get("destination_ip"),
                source_port=raw.get("source_port"),
                destination_port=raw.get("destination_port"),
                protocol=raw.get("protocol"),
                connection_state=raw.get("connection_state"),
                bytes_in=raw.get("bytes_in"),
                bytes_out=raw.get("bytes_out"),
                response_time_ms=raw.get("response_time_ms"),
                dns_query=raw.get("dns_query"),
                dns_response=raw.get("dns_response"),
                raw_reference=raw.get("raw_reference"),
                username=raw.get("username"),
                event_type=raw.get("event_type", "zeek_connection"),
                event_category=raw.get("event_category", "network"),
                severity=raw.get("severity", "low"),
                message=raw.get("message", "Network event"),
                request_path=raw.get("request_path"),
                http_method=raw.get("http_method"),
                status_code=raw.get("status_code"),
                user_agent=raw.get("user_agent"),
            )
            db.add(ev)
            events.append(ev)

        db.flush()

        # Evaluate rules and measure latency
        t0 = time.perf_counter()
        alert_count = evaluate_rules_for_events(db, events, auto_correlate=False)
        dt_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(dt_ms)
        total_alerts += alert_count

        fired_alerts = db.query(Alert).all()
        detected = (len(fired_alerts) > 0)
        is_attack = (scen["ground_truth"] == "ATTACK")

        if is_attack and detected:
            tp += 1
        elif not is_attack and detected:
            fp += 1
        elif is_attack and not detected:
            fn += 1
        else:
            tn += 1

        # Track per-rule contributions
        fired_rule_names = {a.title for a in fired_alerts}
        for r_name in rule_detections:
            r_fired = (r_name in fired_rule_names)
            if is_attack and r_fired:
                rule_detections[r_name]["tp"] += 1
            elif not is_attack and r_fired:
                rule_detections[r_name]["fp"] += 1
            elif is_attack and not r_fired:
                rule_detections[r_name]["fn"] += 1
            else:
                rule_detections[r_name]["tn"] += 1
            if r_fired:
                rule_detections[r_name]["alerts"] += 1

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) > 0 else 0.0
    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
    avg_latency = round(sum(latencies) / len(latencies), 3) if latencies else 0.0

    return {
        "split": split_name,
        "scenarios_evaluated": len(scenarios),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "average_detection_latency_ms": avg_latency,
        "total_alerts": total_alerts,
        "rule_detections": rule_detections,
    }


def run_network_evaluation():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    db = SessionLocal()

    ensure_users(db)
    ensure_builtin_rules(db)
    ensure_indicators(db)

    datasets_dir = Path(__file__).resolve().parent / "datasets" / "network_v1"
    dev_path = datasets_dir / "dev_set.json"
    val_path = datasets_dir / "val_set.json"

    with open(dev_path, encoding="utf-8") as f:
        dev_scenarios = json.load(f)
    with open(val_path, encoding="utf-8") as f:
        val_scenarios = json.load(f)

    print("=================================================================")
    print("PHASE 4 NETWORK TELEMETRY & ZEEK DETECTION EVALUATION")
    print("Dataset: Network V1 (Held-out Test Set Untouched)")
    print("=================================================================")

    dev_results = evaluate_split(db, dev_scenarios, "DEVELOPMENT")
    print(f"\n--- DEV SET RESULTS ({dev_results['scenarios_evaluated']} Scenarios) ---")
    print(f"TP: {dev_results['tp']} | FP: {dev_results['fp']} | FN: {dev_results['fn']} | TN: {dev_results['tn']}")
    print(f"Precision: {dev_results['precision']:.4f} | Recall: {dev_results['recall']:.4f} | F1: {dev_results['f1']:.4f} | FPR: {dev_results['fpr']:.4f}")
    print(f"Avg Detection Latency: {dev_results['average_detection_latency_ms']} ms | Alert Volume: {dev_results['total_alerts']}")

    val_results = evaluate_split(db, val_scenarios, "VALIDATION")
    print(f"\n--- VALIDATION SET RESULTS ({val_results['scenarios_evaluated']} Scenarios) ---")
    print(f"TP: {val_results['tp']} | FP: {val_results['fp']} | FN: {val_results['fn']} | TN: {val_results['tn']}")
    print(f"Precision: {val_results['precision']:.4f} | Recall: {val_results['recall']:.4f} | F1: {val_results['f1']:.4f} | FPR: {val_results['fpr']:.4f}")
    print(f"Avg Detection Latency: {val_results['average_detection_latency_ms']} ms | Alert Volume: {val_results['total_alerts']}")

    # Combined DEV + VAL metrics
    comb_tp = dev_results['tp'] + val_results['tp']
    comb_fp = dev_results['fp'] + val_results['fp']
    comb_fn = dev_results['fn'] + val_results['fn']
    comb_tn = dev_results['tn'] + val_results['tn']
    comb_prec = round(comb_tp / (comb_tp + comb_fp), 4) if (comb_tp + comb_fp) > 0 else 0.0
    comb_rec = round(comb_tp / (comb_tp + comb_fn), 4) if (comb_tp + comb_fn) > 0 else 0.0
    comb_f1 = round(2 * comb_prec * comb_rec / (comb_prec + comb_rec), 4) if (comb_prec + comb_rec) > 0 else 0.0
    comb_fpr = round(comb_fp / (comb_fp + comb_tn), 4) if (comb_fp + comb_tn) > 0 else 0.0

    print(f"\n--- COMBINED DEV + VAL SUMMARY (42 Scenarios) ---")
    print(f"TP: {comb_tp} | FP: {comb_fp} | FN: {comb_fn} | TN: {comb_tn}")
    print(f"Precision: {comb_prec:.4f} | Recall: {comb_rec:.4f} | F1: {comb_f1:.4f} | FPR: {comb_fpr:.4f}")

    # Evaluate Rule Health for all 6 Zeek network rules
    print("\n--- PERSISTING DETECTION QUALITY & RULE HEALTH SCORES ---")
    network_rules_db = db.query(DetectionRule).filter(DetectionRule.rule_id.like("NETWORK-%")).all()
    for rule in network_rules_db:
        health_rec = evaluate_rule_health(db, rule, dataset_target="network_v1_validation", persist=True)
        print(f"Rule: {rule.rule_id} ({rule.name})")
        print(f"  Health Score: {health_rec.health_score} | Tier: {health_rec.health_tier}")
        print(f"  Precision: {health_rec.precision} | Recall: {health_rec.recall} | F1: {health_rec.f1_score} | FPR: {health_rec.false_positive_rate}")

    db.commit()
    db.close()


if __name__ == "__main__":
    run_network_evaluation()
