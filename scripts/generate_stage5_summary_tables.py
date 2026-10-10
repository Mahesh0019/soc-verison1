"""
scripts/generate_stage5_summary_tables.py

Reads docs/artifacts/phase_11_stage_5_audit_results.json and prints markdown tables
for inclusion in docs/PHASE_11_STAGE_5_ROBUSTNESS_AUDIT_REPORT.md.
"""

import json
from pathlib import Path

repo_root = Path(__file__).parent.parent
json_path = repo_root / "docs" / "artifacts" / "phase_11_stage_5_audit_results.json"

with open(json_path, "r", encoding="utf-8") as f:
    data = json.load(f)

configs = data["configurations"]

print("### Summary Performance & Detection Metric Comparison Across 35 Scenarios\n")
print("| Configuration | TP | FP | TN | FN | Precision | Recall | FPR | FNR | F1-Score |")
print("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")

for name, c in configs.items():
    print(
        f"| **{name}** | {c['true_positives']} | {c['false_positives']} | {c['true_negatives']} | {c['false_negatives']} | "
        f"{c['precision']*100:.2f}% | {c['recall']*100:.2f}% | {c['false_positive_rate']*100:.2f}% | {c['false_negative_rate']*100:.2f}% | **{c['f1_score']:.4f}** |"
    )

print("\n### Latency & Computational Efficiency Profile Across 35 Scenarios\n")
print("| Configuration | Execution Mode | Overall Median | Small-Batch Median (<=10) | Burst Median (>=100) | P95 Latency | Max Latency |")
print("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |")

for name, c in configs.items():
    mode = "Batched SQL" if "batched" in name else "Sequential SQL"
    print(
        f"| **{name}** | {mode} | {c['overall_median_latency_ms']:.2f} ms | {c['small_batch_median_ms']:.2f} ms | {c['burst_median_ms']:.2f} ms | {c['overall_p95_latency_ms']:.2f} ms | {c['overall_max_latency_ms']:.2f} ms |"
    )

print("\n### Detailed Scenario Breakdown for Candidate Dual-Threshold (Batched)\n")
dual = configs["candidate_dual_threshold_batched"]["scenario_results"]
print("| Scenario ID | Category | Events | Expected | Fired Rules | Alerts | Classification | Median Latency | Per-Event Cost |")
print("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
for s in dual:
    fired = ", ".join(s["fired_rule_ids"]) if s["fired_rule_ids"] else "None"
    print(
        f"| `{s['scenario_id']}` | {s['category']} | {s['event_count']} | {s['scenario_id']} | `{fired}` | {s['alert_count']} | **{s['classification']}** | {s['median_latency_ms']:.2f} ms | {s['per_event_median_ms']:.3f} ms |"
    )
