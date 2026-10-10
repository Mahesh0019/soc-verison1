"""
scripts/generate_stage6_summary_tables.py

Reads docs/artifacts/phase_11_stage_6_distributed_evaluation_results.json and prints markdown tables
for inclusion in docs/PHASE_11_STAGE_6_DISTRIBUTED_DETECTION_REPORT.md.
"""

import json
from pathlib import Path

repo_root = Path(__file__).parent.parent
json_path = repo_root / "docs" / "artifacts" / "phase_11_stage_6_distributed_evaluation_results.json"

if not json_path.exists():
    print(f"Artifact {json_path} does not exist yet.")
    exit(0)

with open(json_path, "r", encoding="utf-8") as f:
    data = json.load(f)

configs = data["configurations"]

print("### Summary Performance Comparison Across All 24 Scenarios (Stage 6)\n")
print("| Configuration | TP | FP | TN | FN | Precision | Recall | FPR | FNR | F1-Score | Median Latency |")
print("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")

for name, c in configs.items():
    o = c["overall"]
    print(
        f"| **{name}** | {o['true_positives']} | {o['false_positives']} | {o['true_negatives']} | {o['false_negatives']} | "
        f"{o['precision']*100:.1f}% | {o['recall']*100:.1f}% | {o['false_positive_rate']*100:.1f}% | {o['false_negative_rate']*100:.1f}% | **{o['f1_score']:.4f}** | {o['median_latency_ms']:.2f} ms |"
    )

print("\n### Performance Breakdown by Dataset Partition (Dev vs Val vs Held-Out Test)\n")
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

print("\n### Latency Profiles Across Workloads (Small-Batch vs Burst)\n")
print("| Configuration | Small-Batch Median (<=25 ev) | Burst Median (>=80 ev) | P95 Latency | Max Latency |")
print("| :--- | :---: | :---: | :---: | :---: |")

for name, c in configs.items():
    print(
        f"| **{name}** | {c['small_batch_median_ms']:.2f} ms | {c['burst_median_ms']:.2f} ms | {c['overall_p95_latency_ms']:.2f} ms | {c['overall_max_latency_ms']:.2f} ms |"
    )

print("\n### Detailed Scenario Breakdown for Candidate Hybrid Integrated\n")
hybrid_scenarios = configs["candidate_hybrid_integrated"]["scenario_results"]
print("| Scenario ID | Name | Partition | Category | Events | Fired Rules | Alerts | Classification | Median Latency |")
print("| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
for s in hybrid_scenarios:
    fired = ", ".join(s["fired_rule_ids"]) if s["fired_rule_ids"] else "None"
    print(
        f"| `{s['scenario_id']}` | {s['name'][:35]} | {s['partition'].upper()} | {s['category']} | {s['event_count']} | `{fired}` | {s['alert_count']} | **{s['classification']}** | {s['median_latency_ms']:.2f} ms |"
    )
