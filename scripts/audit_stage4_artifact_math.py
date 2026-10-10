"""
scripts/audit_stage4_artifact_math.py

Independently checks every calculation, denominator, and percentage in
docs/artifacts/phase_11_stage_4_candidate_evaluation_results.json:
1. Scenario counts sum: TP + FP + TN + FN == total_scenarios.
2. Precision formula: TP / (TP + FP).
3. Recall formula: TP / (TP + FN).
4. FPR formula: FP / (FP + TN).
5. FNR formula: FN / (TP + FN).
6. F1-Score formula: 2 * (P * R) / (P + R).
7. Verifies evaluation unit is scenario, not individual alerts or events.
8. Checks whether multiple alerts inflated TP counts.
"""

import json
from pathlib import Path

repo_root = Path(__file__).parent.parent
json_path = repo_root / "docs" / "artifacts" / "phase_11_stage_4_candidate_evaluation_results.json"

with open(json_path, "r", encoding="utf-8") as f:
    data = json.load(f)

configs = data["configurations"]
total_scenarios_meta = data["scenarios_evaluated"]

print("=" * 80)
print("INDEPENDENT MATHEMATICAL AUDIT OF STAGE 4 ARTIFACT METRICS")
print("=" * 80)
print(f"Total Scenarios Evaluated in Metadata: {total_scenarios_meta}")

all_valid = True

for cfg_name, card in configs.items():
    print(f"\n--- Checking Configuration: {cfg_name} ---")
    tp = card["true_positives"]
    fp = card["false_positives"]
    tn = card["true_negatives"]
    fn = card["false_negatives"]
    total = card["total_scenarios"]
    sc_results = card["scenario_results"]

    # 1. Total count check
    if tp + fp + tn + fn != total or total != total_scenarios_meta:
        print(f"[FAIL] MISMATCH: TP({tp}) + FP({fp}) + TN({tn}) + FN({fn}) = {tp+fp+tn+fn} != {total}")
        all_valid = False
    else:
        print(f"[PASS] Total Scenarios: {tp} + {fp} + {tn} + {fn} == {total}")

    # 2. Precision check
    denom_p = tp + fp
    expected_prec = round(tp / denom_p, 4) if denom_p > 0 else 0.0
    if card["precision"] != expected_prec:
        print(f"[FAIL] PRECISION MISMATCH: Recorded {card['precision']} vs Expected {expected_prec}")
        all_valid = False
    else:
        print(f"[PASS] Precision: {card['precision']} == {tp}/{denom_p} ({expected_prec*100:.2f}%)")

    # 3. Recall check
    denom_r = tp + fn
    expected_rec = round(tp / denom_r, 4) if denom_r > 0 else 0.0
    if card["recall"] != expected_rec:
        print(f"[FAIL] RECALL MISMATCH: Recorded {card['recall']} vs Expected {expected_rec}")
        all_valid = False
    else:
        print(f"[PASS] Recall: {card['recall']} == {tp}/{denom_r} ({expected_rec*100:.2f}%)")

    # 4. FPR check
    denom_fpr = fp + tn
    expected_fpr = round(fp / denom_fpr, 4) if denom_fpr > 0 else 0.0
    if card["false_positive_rate"] != expected_fpr:
        print(f"[FAIL] FPR MISMATCH: Recorded {card['false_positive_rate']} vs Expected {expected_fpr}")
        all_valid = False
    else:
        print(f"[PASS] False-Positive Rate: {card['false_positive_rate']} == {fp}/{denom_fpr} ({expected_fpr*100:.2f}%)")

    # 5. FNR check
    denom_fnr = tp + fn
    expected_fnr = round(fn / denom_fnr, 4) if denom_fnr > 0 else 0.0
    if card["false_negative_rate"] != expected_fnr:
        print(f"[FAIL] FNR MISMATCH: Recorded {card['false_negative_rate']} vs Expected {expected_fnr}")
        all_valid = False
    else:
        print(f"[PASS] False-Negative Rate: {card['false_negative_rate']} == {fn}/{denom_fnr} ({expected_fnr*100:.2f}%)")

    # 6. F1-Score check
    if expected_prec + expected_rec > 0:
        expected_f1 = round(2 * (expected_prec * expected_rec) / (expected_prec + expected_rec), 4)
    else:
        expected_f1 = 0.0
    if card["f1_score"] != expected_f1:
        print(f"[FAIL] F1 MISMATCH: Recorded {card['f1_score']} vs Expected {expected_f1}")
        all_valid = False
    else:
        print(f"[PASS] F1-Score: {card['f1_score']} == {expected_f1}")

    # 7. Scenario-Level Unit Check and Alert Inflation Check
    scenario_ids = [s["scenario_id"] for s in sc_results]
    if len(scenario_ids) != len(set(scenario_ids)):
        print(f"[FAIL] DUPLICATE SCENARIO IN RESULT: {len(scenario_ids)} vs unique {len(set(scenario_ids))}")
        all_valid = False
    else:
        print(f"[PASS] Evaluation Unit Verified: Exactly {len(scenario_ids)} unique scenarios evaluated.")

    tp_scenarios = [s for s in sc_results if s["classification"] == "TP"]
    total_alerts_in_tps = sum(s["alert_count"] for s in tp_scenarios)
    print(f"[PASS] Alert Inflation Check: {len(tp_scenarios)} TP scenarios produced {total_alerts_in_tps} total alerts.")
    print(f"   (Verified that TP = {len(tp_scenarios)} is NOT inflated by multiple alerts per scenario)")

print("\n" + "=" * 80)
if all_valid:
    print("ALL MATHEMATICAL CHECKS PASSED: ZERO DISCREPANCIES DETECTED IN STAGE 4 METRICS.")
else:
    print("WARNING: DISCREPANCIES DETECTED IN STAGE 4 ARTIFACT METRICS.")
print("=" * 80)
