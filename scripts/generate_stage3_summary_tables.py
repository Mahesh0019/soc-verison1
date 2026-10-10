"""
scripts/generate_stage3_summary_tables.py

Outputs formatted markdown tables from docs/artifacts/phase_11_stage_3_candidate_evaluation_results.json
"""

import json
from pathlib import Path

repo_root = Path(__file__).parent.parent
json_path = repo_root / "docs" / "artifacts" / "phase_11_stage_3_candidate_evaluation_results.json"
data = json.load(open(json_path, encoding="utf-8"))

print("=== LATENCY COMPARISON TABLE ===")
cand_seq = data["standard_17_scenarios"]["candidate_rule008_sequential"]["scenario_results"]
cand_bat = data["standard_17_scenarios"]["candidate_rule008_batched"]["scenario_results"]

print("| Scenario ID | Events | Class | Sequential Med (ms) | Batched Med (ms) | Sequential P95 (ms) | Batched P95 (ms) | Batched Max (ms) | Per-Event Med (ms) |")
print("|---|---|---|---|---|---|---|---|---|")
for s, b in zip(cand_seq, cand_bat):
    sid = s["scenario_id"]
    ev = s["event_count"]
    cls_name = s["classification"]
    s_med = s["benchmark"]["median_ms"]
    b_med = b["benchmark"]["median_ms"]
    s_p95 = s["benchmark"]["p95_ms"]
    b_p95 = b["benchmark"]["p95_ms"]
    b_max = b["benchmark"]["max_ms"]
    per_ev = b["benchmark"]["per_event_median_ms"]
    print(f"| {sid} | {ev} | {cls_name} | {s_med:.2f} ms | {b_med:.2f} ms | {s_p95:.2f} ms | {b_p95:.2f} ms | {b_max:.2f} ms | {per_ev:.3f} ms |")

print("\n=== SCENARIO EXECUTION MATRIX (BASELINE vs CANDIDATE) ===")
base = data["standard_17_scenarios"]["baseline_sequential"]["scenario_results"]
for b_sc, c_sc in zip(base, cand_bat):
    sid = b_sc["scenario_id"]
    ev = b_sc["event_count"]
    b_cls = b_sc["classification"]
    c_cls = c_sc["classification"]
    b_fired = ",".join(b_sc["fired_rule_ids"]) or "None"
    c_fired = ",".join(c_sc["fired_rule_ids"]) or "None"
    b_inc = b_sc["incident_count"]
    c_inc = c_sc["incident_count"]
    print(f"| {sid} | {ev} | {b_fired} | {b_inc} | {b_cls} | {c_fired} | {c_inc} | {c_cls} |")

print("\n=== ADVERSARIAL CASES (FULL 21) ===")
full_base = data["full_21_scenarios_including_adversarial"]["baseline_sequential"]["scenario_results"]
full_cand = data["full_21_scenarios_including_adversarial"]["candidate_rule008_batched"]["scenario_results"]
for b_sc, c_sc in zip(full_base[17:], full_cand[17:]):
    sid = b_sc["scenario_id"]
    ev = b_sc["event_count"]
    b_cls = b_sc["classification"]
    c_cls = c_sc["classification"]
    b_fired = ",".join(b_sc["fired_rule_ids"]) or "None"
    c_fired = ",".join(c_sc["fired_rule_ids"]) or "None"
    blind = c_sc["blind_spot_flag"]
    print(f"| {sid} | {ev} | {b_fired} ({b_cls}) | {c_fired} ({c_cls}) | BlindSpot={blind} |")
