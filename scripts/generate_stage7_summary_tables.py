"""
scripts/generate_stage7_summary_tables.py

Reads docs/artifacts/phase_11_stage_7_baseline_evaluation_results.json and prints markdown tables
for inclusion in docs/PHASE_11_STAGE_7_CALIBRATION_REPORT.md.
"""

import json
from pathlib import Path

repo_root = Path(__file__).parent.parent
json_path = repo_root / "docs" / "artifacts" / "phase_11_stage_7_baseline_evaluation_results.json"

if not json_path.exists():
    print(f"Artifact {json_path} does not exist yet.")
    exit(0)

with open(json_path, "r", encoding="utf-8") as f:
    data = json.load(f)

configs = data["configurations"]
matrix = data["baseline_calibration_matrix"]
comp = data["direct_comparison_hybrid_vs_endpoint"]

print("### 1. Summary Performance Comparison Across All 24 Scenarios (Stage 7)\n")
print("| Configuration | TP | FP | TN | FN | Precision | Recall | FPR | FNR | F1-Score | Median Latency |")
print("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")

for name, c in configs.items():
    o = c["overall"]
    print(
        f"| **{name}** | {o['true_positives']} | {o['false_positives']} | {o['true_negatives']} | {o['false_negatives']} | "
        f"{o['precision']*100:.1f}% | {o['recall']*100:.1f}% | {o['false_positive_rate']*100:.1f}% | {o['false_negative_rate']*100:.1f}% | **{o['f1_score']:.4f}** | {o['median_latency_ms']:.2f} ms |"
    )

print("\n### 2. Performance Breakdown by Dataset Partition (Dev vs Val vs Held-Out Test)\n")
print("| Configuration | Partition | Scenarios | TP | FP | TN | FN | Precision | Recall | FPR | F1-Score |")
print("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")

for name, c in configs.items():
    for p_name in ["dev_set", "val_set", "test_set"]:
        p = c[p_name]
        label = p_name.replace("_set", "").title()
        print(
            f"| **{name}** | {label} | {p['total_scenarios']} | {p['true_positives']} | {p['false_positives']} | {p['true_negatives']} | {p['false_negatives']} | "
            f"{p['precision']*100:.1f}% | {p['recall']*100:.1f}% | {p['false_positive_rate']*100:.1f}% | **{p['f1_score']:.4f}** |"
        )

print("\n### 3. Dynamic-Baseline Calibration Matrix (Windows & Update Strategies)\n")
print("| Window | Strategy | Sigma | Floor | Cold-Start (DEV-01) | Poisoning Ramp (DEV-05) | Flash Crowd (DEV-02) | Botnet (DEV-06) | Notes |")
print("| :---: | :--- | :---: | :---: | :--- | :--- | :--- | :--- | :--- |")

for c in matrix:
    print(
        f"| **{c['window_minutes']}m** | `{c['update_strategy']}` | {c['sigma_multiplier']} | {c['min_floor']} | "
        f"{c['cold_start_outcome']} | {c['poisoning_outcome']} | {c['flash_crowd_outcome']} | {c['low_rate_outcome']} | {c['notes'][:45]}... |"
    )

print("\n### 4. Direct Comparison: Hybrid Fusion vs Endpoint Aggregation Alone\n")
print(f"- **Additional Detections by Hybrid Fusion**: {comp['additional_detections_count']}")
for d in comp["additional_detections"]:
    print(f"  * `{d['scenario_id']}`: {d['name']} (Hybrid: **{d['hybrid_classification']}**, Endpoint: **{d['endpoint_classification']}**)")

print(f"- **False Positive Reductions by Hybrid Fusion**: {comp['false_positive_reductions_count']}")
for d in comp["false_positive_reductions"]:
    print(f"  * `{d['scenario_id']}`: {d['name']} (Hybrid: **{d['hybrid_classification']}**, Endpoint: **{d['endpoint_classification']}**)")

cq = comp["correlation_quality"]
print(f"\n- **Incident Correlation Quality**:")
print(f"  * Endpoint Alone: {cq['endpoint_alone']['total_alerts']} alerts across scenarios formed {cq['endpoint_alone']['total_incidents']} isolated incidents (ratio {cq['endpoint_alone']['incident_to_alert_ratio']}). Zero multi-stage kill-chain linking.")
print(f"  * Hybrid Integrated: {cq['hybrid_integrated']['total_alerts']} alerts formed {cq['hybrid_integrated']['total_incidents']} correlated incidents (ratio {cq['hybrid_integrated']['incident_to_alert_ratio']}). Cross-source correlation fuses Recon, SQLi, and Exfiltration into unified incident files.")

lo = comp["latency_overhead"]
print(f"\n- **Latency Overhead**:")
print(f"  * Endpoint Alone Median: {lo['endpoint_alone_median_ms']:.2f} ms")
print(f"  * Hybrid Integrated Median: {lo['hybrid_integrated_median_ms']:.2f} ms")
print(f"  * Measured Overhead: +{lo['overhead_ms']:.2f} ms (+{lo['overhead_percentage']:.1f}%) — {lo['overhead_verdict']}")

print("\n### 5. Latency Profiles Across Workloads (Small-Batch vs Burst)\n")
print("| Configuration | Small-Batch Median (<=35 ev) | Burst Median (>=80 ev) | P95 Latency | Max Latency |")
print("| :--- | :---: | :---: | :---: | :---: |")

for name, c in configs.items():
    print(
        f"| **{name}** | {c['small_batch_median_ms']:.2f} ms | {c['burst_median_ms']:.2f} ms | {c['overall_p95_latency_ms']:.2f} ms | {c['overall_max_latency_ms']:.2f} ms |"
    )

print("\n### 6. Detailed Scenario Breakdown for Candidate Hybrid Integrated\n")
hybrid_scenarios = configs["candidate_hybrid_integrated"]["scenario_results"]
print("| Scenario ID | Name | Partition | Category | Events | Fired Rules | Alerts | Incidents | Classification | Median Latency |")
print("| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
for s in hybrid_scenarios:
    fired = ", ".join(s["fired_rule_ids"]) if s["fired_rule_ids"] else "None"
    print(
        f"| `{s['scenario_id']}` | {s['name'][:32]} | {s['partition'].upper()} | {s['category']} | {s['event_count']} | `{fired}` | {s['alert_count']} | {s['incident_count']} | **{s['classification']}** | {s['median_latency_ms']:.2f} ms |"
    )
