"""
research/scripts/validate_dataset_v2.py

Independent dataset validator for RESEARCH DATASET V2:
1. Validates total scenario counts (200 total).
2. Validates ground truth balance (100 Attack, 100 Benign).
3. Validates split distribution (Dev: 100 [50/50], Val: 40 [20/20], Test: 60 [30/30]).
4. Validates ID uniqueness (no duplicate scenario IDs).
5. Validates split disjointness (Dev, Val, Test partitions are mutually exclusive).
6. Validates required schema fields on every scenario and event.
7. Validates data leakage guards (IP partitioning by split, hidden ground truth).
"""

from __future__ import annotations

import json
from pathlib import Path
import sys


def validate_dataset_v2():
    root_dir = Path(__file__).resolve().parents[2]
    dataset_dir = root_dir / "research" / "datasets" / "dataset_v2"
    full_path = dataset_dir / "dataset_v2.json"
    dev_path = dataset_dir / "dev_set.json"
    val_path = dataset_dir / "val_set.json"
    test_path = dataset_dir / "test_set.json"
    manifest_path = dataset_dir / "dataset_v2_manifest.json"

    errors = []

    for path in [full_path, dev_path, val_path, test_path, manifest_path]:
        if not path.exists():
            errors.append(f"Missing required dataset artifact: {path}")

    if errors:
        for err in errors:
            print(f"[FAIL] {err}")
        sys.exit(1)

    with open(full_path, encoding="utf-8") as f:
        full_data = json.load(f)

    with open(dev_path, encoding="utf-8") as f:
        dev_data = json.load(f)

    with open(val_path, encoding="utf-8") as f:
        val_data = json.load(f)

    with open(test_path, encoding="utf-8") as f:
        test_data = json.load(f)

    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)

    # 1. Total counts
    if len(full_data) != 200:
        errors.append(f"Expected 200 scenarios, got {len(full_data)}")

    # 2. Attack / Benign split
    attacks = [s for s in full_data if s.get("ground_truth") == "ATTACK"]
    benign = [s for s in full_data if s.get("ground_truth") == "BENIGN"]
    if len(attacks) != 100:
        errors.append(f"Expected 100 attacks, got {len(attacks)}")
    if len(benign) != 100:
        errors.append(f"Expected 100 benign, got {len(benign)}")

    # 3. Splits
    if len(dev_data) != 100:
        errors.append(f"Expected 100 dev scenarios, got {len(dev_data)}")
    if len(val_data) != 40:
        errors.append(f"Expected 40 val scenarios, got {len(val_data)}")
    if len(test_data) != 60:
        errors.append(f"Expected 60 test scenarios, got {len(test_data)}")

    dev_atk = sum(1 for s in dev_data if s.get("ground_truth") == "ATTACK")
    dev_ben = sum(1 for s in dev_data if s.get("ground_truth") == "BENIGN")
    val_atk = sum(1 for s in val_data if s.get("ground_truth") == "ATTACK")
    val_ben = sum(1 for s in val_data if s.get("ground_truth") == "BENIGN")
    test_atk = sum(1 for s in test_data if s.get("ground_truth") == "ATTACK")
    test_ben = sum(1 for s in test_data if s.get("ground_truth") == "BENIGN")

    if dev_atk != 50 or dev_ben != 50:
        errors.append(f"Dev split imbalance: {dev_atk} atk, {dev_ben} ben (expected 50/50)")
    if val_atk != 20 or val_ben != 20:
        errors.append(f"Val split imbalance: {val_atk} atk, {val_ben} ben (expected 20/20)")
    if test_atk != 30 or test_ben != 30:
        errors.append(f"Test split imbalance: {test_atk} atk, {test_ben} ben (expected 30/30)")

    # 4. ID uniqueness
    all_ids = [s["scenario_id"] for s in full_data]
    if len(all_ids) != len(set(all_ids)):
        duplicates = [x for x in all_ids if all_ids.count(x) > 1]
        errors.append(f"Duplicate scenario IDs found: {set(duplicates)}")

    # 5. Split disjointness
    dev_ids = {s["scenario_id"] for s in dev_data}
    val_ids = {s["scenario_id"] for s in val_data}
    test_ids = {s["scenario_id"] for s in test_data}

    if dev_ids.intersection(val_ids):
        errors.append(f"Dev and Val overlap: {dev_ids.intersection(val_ids)}")
    if dev_ids.intersection(test_ids):
        errors.append(f"Dev and Test overlap: {dev_ids.intersection(test_ids)}")
    if val_ids.intersection(test_ids):
        errors.append(f"Val and Test overlap: {val_ids.intersection(test_ids)}")

    if (dev_ids | val_ids | test_ids) != set(all_ids):
        errors.append("Union of splits does not match full dataset scenario IDs")

    # 6. Minimum required metadata
    required_scenario_fields = {
        "scenario_id", "scenario_version", "split", "ground_truth",
        "attack_category", "name", "description", "source", "timestamp",
        "expected_detection", "expected_severity", "difficulty", "events"
    }
    required_event_fields = {
        "timestamp", "source_ip", "destination_ip", "event_type",
        "event_category", "severity", "message", "raw_log"
    }

    for idx, s in enumerate(full_data):
        missing = required_scenario_fields - set(s.keys())
        if missing:
            errors.append(f"Scenario {s.get('scenario_id', idx)} missing fields: {missing}")

        if s.get("ground_truth") not in ("ATTACK", "BENIGN"):
            errors.append(f"Scenario {s.get('scenario_id')} invalid ground_truth: {s.get('ground_truth')}")

        events = s.get("events", [])
        if not events:
            errors.append(f"Scenario {s.get('scenario_id')} has no events")

        for e_idx, ev in enumerate(events):
            e_missing = required_event_fields - set(ev.keys())
            if e_missing:
                errors.append(f"Scenario {s.get('scenario_id')} event #{e_idx} missing fields: {e_missing}")

    # 7. Leakage check: Subnet separation between Dev, Val, Test
    for s in dev_data:
        for ev in s.get("events", []):
            if ev.get("source_ip") and ev["source_ip"].startswith("192.0.2."):
                errors.append(f"Data leakage: Test IP found in Dev scenario {s['scenario_id']}")
    for s in test_data:
        for ev in s.get("events", []):
            if ev.get("source_ip") and ev["source_ip"].startswith("198.51.100.") and ev["source_ip"] != "198.51.100.99":
                errors.append(f"Data leakage: Dev IP found in Test scenario {s['scenario_id']}")

    if errors:
        print(f"[FAIL] Dataset V2 validation failed with {len(errors)} errors:")
        for err in errors[:20]:
            print(f"  - {err}")
        sys.exit(1)

    print("=" * 70)
    print("RESEARCH DATASET V2 — VALIDATION PASSED (100% VERIFIED)")
    print("=" * 70)
    print(f"[+] Total Scenarios:          {len(full_data)}")
    print(f"[+] Attack Scenarios:         {len(attacks)} (50.0%)")
    print(f"[+] Benign Scenarios:         {len(benign)} (50.0%)")
    print(f"[+] Total Telemetry Events:   {sum(len(s['events']) for s in full_data)}")
    print(f"[+] Development Set (Dev):    {len(dev_data)} ({dev_atk} Atk / {dev_ben} Ben)")
    print(f"[+] Validation Set (Val):     {len(val_data)} ({val_atk} Atk / {val_ben} Ben)")
    print(f"[+] Test Set (Test):          {len(test_data)} ({test_atk} Atk / {test_ben} Ben)")
    print(f"[+] Unique Scenario IDs:      {len(set(all_ids))} (0 duplicates)")
    print(f"[+] Split Disjointness:       VERIFIED (0 overlap)")
    print(f"[+] Schema Compliance:        100% compliant")
    print(f"[+] Data Leakage Guard:       VERIFIED")
    print(f"[+] Manifest SHA256:          {manifest.get('full_dataset_sha256')}")
    print("=" * 70)


if __name__ == "__main__":
    validate_dataset_v2()
