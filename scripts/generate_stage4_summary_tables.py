"""
scripts/generate_stage4_summary_tables.py

Outputs formatted markdown tables from docs/artifacts/phase_11_stage_4_candidate_evaluation_results.json
"""

import json
from pathlib import Path

repo_root = Path(__file__).parent.parent
json_path = repo_root / "docs" / "artifacts" / "phase_11_stage_4_candidate_evaluation_results.json"
data = json.load(open(json_path, encoding="utf-8"))

print("=== STAGE 4 SCORECARD SUMMARY ===")
configs = data["configurations"]
print("| Configuration | TP | FP | TN | FN | Precision | Recall | F1-Score | FPR | Blind Spots | Median Latency | P95 Latency | Dups |")
print("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
for name, c in configs.items():
    print(f"| {name} | {c['true_positives']} | {c['false_positives']} | {c['true_negatives']} | {c['false_negatives']} | {c['precision']*100:.2f}% | {c['recall']*100:.2f}% | {c['f1_score']:.4f} | {c['false_positive_rate']*100:.2f}% | {c['blind_spots_count']} | {c['overall_median_latency_ms']:.2f} ms | {c['overall_p95_latency_ms']:.2f} ms | {c['total_duplicate_alerts']} |")

print("\n=== STAGE 4 SCENARIOS EXECUTION MATRIX ===")
base = configs["baseline_sequential"]["scenario_results"]
hard = configs["candidate_stage4_hardened_batched"]["scenario_results"]
dual = configs["candidate_stage4_dual_threshold_batched"]["scenario_results"]

print("| Scenario ID | Events | Category | Baseline Fired | Base Cl. | Hardened Fired | Hard Cl. | Dual-Thresh Fired | Dual Cl. | Dual Blind? |")
print("|---|---|---|---|---|---|---|---|---|---|")
for b_sc, h_sc, d_sc in zip(base, hard, dual):
    sid = b_sc["scenario_id"]
    ev = b_sc["event_count"]
    cat = b_sc["category"]
    b_fired = ",".join(b_sc["fired_rule_ids"]) or "None"
    h_fired = ",".join(h_sc["fired_rule_ids"]) or "None"
    d_fired = ",".join(d_sc["fired_rule_ids"]) or "None"
    b_cl = b_sc["classification"]
    h_cl = h_sc["classification"]
    d_cl = d_sc["classification"]
    d_blind = d_sc["blind_spot_flag"]
    print(f"| {sid} | {ev} | {cat} | {b_fired} | {b_cl} | {h_fired} | {h_cl} | {d_fired} | {d_cl} | {d_blind} |")

print("\n=== LATENCY COMPARISON (SEQUENTIAL VS BATCHED HARDENED) ===")
seq = configs["candidate_stage4_hardened_sequential"]["scenario_results"]
bat = configs["candidate_stage4_hardened_batched"]["scenario_results"]
print("| Scenario ID | Events | Seq Med (ms) | Bat Med (ms) | Seq P95 (ms) | Bat P95 (ms) | Per-Event Med (ms) |")
print("|---|---|---|---|---|---|---|")
for s, b in zip(seq, bat):
    sid = s["scenario_id"]
    ev = s["event_count"]
    s_med = s["benchmark"]["median_ms"]
    b_med = b["benchmark"]["median_ms"]
    s_p95 = s["benchmark"]["p95_ms"]
    b_p95 = b["benchmark"]["p95_ms"]
    per_ev = b["benchmark"]["per_event_median_ms"]
    print(f"| {sid} | {ev} | {s_med:.2f} ms | {b_med:.2f} ms | {s_p95:.2f} ms | {b_p95:.2f} ms | {per_ev:.3f} ms |")
