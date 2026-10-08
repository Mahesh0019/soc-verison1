"""
research/generate_adversarial_v1.py

Phase 7: Adversarial Telemetry & Robustness Benchmark Generator (Adversarial V1)
Synthesizes deterministic scenario classes A through Z:
  A. Missing Web Event
  B. Missing Zeek Event
  C. Missing Sysmon Event
  D. Missing multiple telemetry sources
  E. Delayed telemetry
  F. Reordered telemetry
  G. Duplicate telemetry
  H. Timestamp drift
  I. Shared NAT / Proxy IP
  J. Shared hostname
  K. Shared username
  L. Same destination used by unrelated activities
  M. Benign PowerShell
  N. Benign administrative tools
  O. High-volume legitimate network activity
  P. Near-match process names
  Q. Case variation
  R. Path encoding variation
  S. SQL/XSS payload mutation
  T. DNS mutation
  U. Port variation
  V. Multi-stage attack with partial telemetry
  W. Concurrent unrelated attacks
  X. Long temporal separation
  Y. Boundary-window correlation
  Z. Completely unrelated multi-source events

Outputs:
  - research/datasets/adversarial_v1/dev_scenarios.json (40 scenarios)
  - research/datasets/adversarial_v1/validation_scenarios.json (18 scenarios)
  - research/datasets/adversarial_v1/held_out_test_scenarios.json (20 scenarios)
  - research/datasets/adversarial_v1/manifest.json (SHA-256 integrity manifest)
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from perturbation_engine import TelemetryPerturbationEngine


def make_base_events(t0: datetime, base_ip: str = "203.0.113.10", host: str = "web-prod-01") -> list[dict]:
    """Generates a canonical 3-stage multi-source attack sequence."""
    ev_web = {
        "source_type": "WEB",
        "source_name": "nginx_access",
        "source_ip": base_ip,
        "destination_ip": "10.0.0.10",
        "destination_port": 80,
        "protocol": "tcp",
        "hostname": host,
        "event_type": "web_access",
        "event_category": "security",
        "severity": "high",
        "message": f"GET /rest/products/search?q=' OR 1=1 -- on {host}",
        "request_path": "/rest/products/search?q=' OR 1=1 --",
        "http_method": "GET",
        "status_code": 200,
        "timestamp": t0.isoformat(),
        "raw_reference": f"base_web_{base_ip}",
    }
    ev_zeek = {
        "source_type": "ZEEK",
        "source_name": "zeek_conn",
        "source_ip": base_ip,
        "destination_ip": "10.0.0.10",
        "destination_port": 4444,
        "protocol": "tcp",
        "connection_state": "SF",
        "bytes_in": 1024,
        "bytes_out": 4096,
        "event_type": "conn",
        "event_category": "network",
        "severity": "high",
        "message": f"Outbound connection on unauthorized port 4444 from {base_ip}",
        "timestamp": (t0 + timedelta(seconds=20)).isoformat(),
        "raw_reference": f"base_zeek_{base_ip}",
    }
    ev_sys = {
        "source_type": "SYSMON",
        "source_name": "sysmon_win",
        "source_ip": "10.0.0.10",
        "destination_ip": base_ip,
        "hostname": host,
        "username": "SYSTEM",
        "process": "powershell.exe",
        "parent_process": "w3wp.exe",
        "command_line": "powershell.exe -enc aW52b2tlLW1pbWlrYXR6",
        "event_type": "sysmon_process_create",
        "event_category": "endpoint",
        "severity": "critical",
        "message": f"Suspicious child powershell spawned under w3wp on {host}",
        "timestamp": (t0 + timedelta(seconds=45)).isoformat(),
        "raw_reference": f"base_sys_{base_ip}",
    }
    return [ev_web, ev_zeek, ev_sys]


def build_adversarial_scenario(
    scenario_id: str,
    scenario_class: str,
    title: str,
    description: str,
    ground_truth: str,
    expected_detection: bool,
    expected_correlation: bool,
    expected_correlation_rules: list[str],
    expected_failure_mode: str,
    events: list[dict],
    perturbation_meta: dict | None = None,
) -> dict:
    return {
        "scenario_id": scenario_id,
        "scenario_class": scenario_class,
        "title": title,
        "description": description,
        "ground_truth": ground_truth,
        "expected_detection": expected_detection,
        "expected_correlation": expected_correlation,
        "expected_correlation_rules": expected_correlation_rules,
        "expected_failure_mode": expected_failure_mode,
        "perturbation": perturbation_meta or {"type": "none"},
        "events": events,
    }


def generate_scenarios_for_split(split_name: str, seed_base: int) -> list[dict]:
    engine = TelemetryPerturbationEngine(seed=seed_base)
    base_t0 = datetime(2026, 10, 8, 12, 0, 0, tzinfo=UTC)
    scenarios = []
    prefix = f"ADV-{split_name.upper()}"

    def make_id(num: int) -> str:
        return f"{prefix}-{num:03d}"

    # Determine scenario counts per split
    # DEV: 40 scenarios
    # VAL: 18 scenarios
    # TEST: 20 scenarios
    is_dev = split_name.lower() == "dev"
    is_val = split_name.lower() == "validation"

    idx = 1

    # --- CLASS A: Missing Web Event ---
    events_base = make_base_events(base_t0, f"198.51.100.{idx}", f"srv-{idx}")
    ev_a, log_a = engine.remove_event(events_base, target_source="WEB")
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_A_MISSING_WEB_EVENT",
        title="Multi-Source Attack with Dropped Web Ingestion",
        description="Web ingress log dropped; Zeek connection and Sysmon process events remain intact.",
        ground_truth="ATTACK",
        expected_detection=True,  # Zeek & Sysmon rules fire
        expected_correlation=True, # Sysmon socket / Zeek conn can correlate via CORR-003
        expected_correlation_rules=["CORR-003"],
        expected_failure_mode="PARTIAL_CORRELATION_MISSING_WEB_STAGE",
        events=ev_a,
        perturbation_meta={"type": "remove_event", "log": log_a},
    ))
    idx += 1

    # --- CLASS B: Missing Zeek Event ---
    events_base = make_base_events(base_t0, f"198.51.100.{idx}", f"srv-{idx}")
    ev_b, log_b = engine.remove_event(events_base, target_source="ZEEK")
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_B_MISSING_ZEEK_EVENT",
        title="Web-to-Host Attack with Dropped Network Sensor",
        description="Network wire data dropped; Web exploit and host process creation remain.",
        ground_truth="ATTACK",
        expected_detection=True,
        expected_correlation=True, # Web + Sysmon correlates via CORR-002 on same host
        expected_correlation_rules=["CORR-002"],
        expected_failure_mode="PARTIAL_CORRELATION_MISSING_NETWORK_STAGE",
        events=ev_b,
        perturbation_meta={"type": "remove_event", "log": log_b},
    ))
    idx += 1

    # --- CLASS C: Missing Sysmon Event ---
    events_base = make_base_events(base_t0, f"198.51.100.{idx}", f"srv-{idx}")
    ev_c, log_c = engine.remove_event(events_base, target_source="SYSMON")
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_C_MISSING_SYSMON_EVENT",
        title="Attacker Terminates Sysmon Service Before Execution",
        description="Endpoint sensor disabled; Web and Zeek telemetry remain.",
        ground_truth="ATTACK",
        expected_detection=True,
        expected_correlation=True, # Web + Zeek correlates via CORR-001 on same IP
        expected_correlation_rules=["CORR-001"],
        expected_failure_mode="PARTIAL_CORRELATION_MISSING_ENDPOINT_STAGE",
        events=ev_c,
        perturbation_meta={"type": "remove_event", "log": log_c},
    ))
    idx += 1

    # --- CLASS D: Missing Multiple Telemetry Sources ---
    events_base = make_base_events(base_t0, f"198.51.100.{idx}", f"srv-{idx}")
    # Remove both Zeek and Sysmon, only Web remains
    ev_d1, log_d1 = engine.remove_event(events_base, target_source="ZEEK")
    ev_d, log_d2 = engine.remove_event(ev_d1, target_source="SYSMON")
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_D_MISSING_MULTIPLE_SOURCES",
        title="Severe Multi-Source Blind Spot (Web Only)",
        description="Network and endpoint loggers down; only Web SQLi alert survives.",
        ground_truth="ATTACK",
        expected_detection=True, # Single-source rule fires
        expected_correlation=False, # Cannot correlate single event across sources
        expected_correlation_rules=[],
        expected_failure_mode="MISSED_CORRELATION_SINGLE_SOURCE_REMAINS",
        events=ev_d,
        perturbation_meta={"type": "remove_event_multiple", "log": log_d1 + log_d2},
    ))
    idx += 1

    # --- CLASS E: Delayed Telemetry (Exceeds 300s window) ---
    events_base = make_base_events(base_t0, f"198.51.100.{idx}", f"srv-{idx}")
    # Delay Sysmon event by 450 seconds (exceeds default 300s window)
    ev_e, log_e = engine.delay_timestamp(events_base, target_source="SYSMON", delay_seconds=450.0)
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_E_DELAYED_TELEMETRY",
        title="Delayed Endpoint Log Delivery Exceeding 300s Window",
        description="Endpoint event delayed by 450s due to agent offline buffer; exceeds default correlation window.",
        ground_truth="ATTACK",
        expected_detection=True,
        expected_correlation=False, # Exceeds window -> incident fragmentation
        expected_correlation_rules=[],
        expected_failure_mode="MISSED_CORRELATION_WINDOW_EXPIRY",
        events=ev_e,
        perturbation_meta={"type": "delay_timestamp", "log": log_e},
    ))
    idx += 1

    # --- CLASS F: Reordered Telemetry ---
    events_base = make_base_events(base_t0, f"198.51.100.{idx}", f"srv-{idx}")
    ev_f, log_f = engine.reorder_events(events_base, reverse=True)
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_F_REORDERED_TELEMETRY",
        title="Out-of-Order Log Ingestion (Reverse Arrival)",
        description="Sysmon event arrives before Web exploit in ingestion queue.",
        ground_truth="ATTACK",
        expected_detection=True,
        expected_correlation=True, # Pipeline timeline sorter re-orders chronologically
        expected_correlation_rules=["CORR-001", "CORR-002"],
        expected_failure_mode="ROBUST_CHRONOLOGICAL_REORDERING",
        events=ev_f,
        perturbation_meta={"type": "reorder_events", "log": log_f},
    ))
    idx += 1

    # --- CLASS G: Duplicate Telemetry ---
    events_base = make_base_events(base_t0, f"198.51.100.{idx}", f"srv-{idx}")
    ev_g, log_g = engine.duplicate_event(events_base, target_index=0, time_offset_seconds=2.0)
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_G_DUPLICATE_TELEMETRY",
        title="Duplicate Forwarder Delivery (Web Event Duplicated)",
        description="Syslog forwarder resends Web exploit event with 2s jitter.",
        ground_truth="ATTACK",
        expected_detection=True,
        expected_correlation=True,
        expected_correlation_rules=["CORR-001", "CORR-002"],
        expected_failure_mode="ROBUST_DUPLICATE_DEDUPLICATION",
        events=ev_g,
        perturbation_meta={"type": "duplicate_event", "log": log_g},
    ))
    idx += 1

    # --- CLASS H: Timestamp Drift (+180s Host Skew) ---
    events_base = make_base_events(base_t0, f"198.51.100.{idx}", f"srv-{idx}")
    ev_h, log_h = engine.delay_timestamp(events_base, target_source="SYSMON", delay_seconds=180.0)
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_H_TIMESTAMP_DRIFT",
        title="Sub-Window Host Clock Skew (+180s NTP Drift)",
        description="Windows host clock drifted by 180s; still within 300s window but decays score.",
        ground_truth="ATTACK",
        expected_detection=True,
        expected_correlation=True,
        expected_correlation_rules=["CORR-001", "CORR-002"],
        expected_failure_mode="SCORE_DEGRADATION_TIME_DECAY",
        events=ev_h,
        perturbation_meta={"type": "delay_timestamp", "log": log_h},
    ))
    idx += 1

    # --- CLASS I: Shared NAT / Proxy IP ---
    # Attacker IP is shared across an independent benign user
    ip_nat = f"198.51.100.{idx}"
    ev_i = [
        {
            "source_type": "WEB",
            "source_name": "nginx_access",
            "source_ip": ip_nat,
            "destination_ip": "10.0.0.10",
            "destination_port": 80,
            "protocol": "tcp",
            "hostname": "srv-nat-01",
            "event_type": "web_access",
            "event_category": "security",
            "severity": "high",
            "message": "SQL Injection attempt from corporate proxy IP",
            "request_path": "/rest/products/search?q=' OR 1=1 --",
            "http_method": "GET",
            "status_code": 200,
            "timestamp": base_t0.isoformat(),
            "raw_reference": f"nat_web_{idx}",
        },
        {
            "source_type": "ZEEK",
            "source_name": "zeek_conn",
            "source_ip": ip_nat,
            "destination_ip": "10.0.0.99",
            "destination_port": 6667,  # Unrelated IRC port from different user behind same NAT
            "protocol": "tcp",
            "event_type": "conn",
            "event_category": "network",
            "severity": "medium",
            "message": "IRC traffic from employee behind corporate proxy IP",
            "timestamp": (base_t0 + timedelta(seconds=10)).isoformat(),
            "raw_reference": f"nat_zeek_{idx}",
        },
    ]
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_I_SHARED_NAT_IP",
        title="Unrelated Concurrent Traffic Behind Egress NAT Proxy",
        description="External threat actor and innocent user share same egress IP; test false correlation.",
        ground_truth="ATTACK",
        expected_detection=True,
        expected_correlation=False, # Analyst ground truth: NOT the same attack incident
        expected_correlation_rules=[],
        expected_failure_mode="FALSE_CORRELATION_NAT_COLLISION",
        events=ev_i,
        perturbation_meta={"type": "shared_entity", "entity": "source_ip", "val": ip_nat},
    ))
    idx += 1

    # --- CLASS J: Shared Hostname ---
    # Routine admin cron running concurrently on web host
    host_j = f"srv-shared-{idx}"
    ev_j = [
        {
            "source_type": "WEB",
            "source_name": "nginx_access",
            "source_ip": "203.0.113.88",
            "destination_ip": "10.0.0.10",
            "destination_port": 80,
            "protocol": "tcp",
            "hostname": host_j,
            "event_type": "web_access",
            "event_category": "security",
            "severity": "high",
            "message": "Path traversal attempt on web host",
            "request_path": "/../../etc/passwd",
            "http_method": "GET",
            "status_code": 403,
            "timestamp": base_t0.isoformat(),
            "raw_reference": f"host_web_{idx}",
        },
        {
            "source_type": "SYSMON",
            "source_name": "sysmon_win",
            "hostname": host_j,
            "username": "svc_backup",
            "process": "robocopy.exe",
            "parent_process": "services.exe",  # Not w3wp
            "command_line": "robocopy.exe C:\\data D:\\backup /MIR",
            "event_type": "sysmon_process_create",
            "event_category": "endpoint",
            "severity": "low",
            "message": "Routine backup service running robocopy",
            "timestamp": (base_t0 + timedelta(seconds=15)).isoformat(),
            "raw_reference": f"host_sys_{idx}",
        },
    ]
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_J_SHARED_HOSTNAME",
        title="Concurrent Benign Backup on Targeted Web Server",
        description="Legitimate backup process executes while server receives web probe.",
        ground_truth="ATTACK",
        expected_detection=True, # Web rule fires
        expected_correlation=False, # Robocopy under services is NOT child of w3wp -> should NOT correlate
        expected_correlation_rules=[],
        expected_failure_mode="CORRECT_NON_CORRELATION_PARENT_CHECK",
        events=ev_j,
        perturbation_meta={"type": "shared_entity", "entity": "hostname", "val": host_j},
    ))
    idx += 1

    # --- CLASS K: Shared Username Across Distinct Hosts ---
    ev_k = [
        {
            "source_type": "AUTH",
            "source_name": "auth_log",
            "source_ip": "10.0.0.5",
            "username": "admin_bob",
            "hostname": "workstation-01",
            "event_type": "auth_login",
            "event_category": "security",
            "severity": "low",
            "message": "Legitimate admin workstation login",
            "timestamp": base_t0.isoformat(),
            "raw_reference": f"auth_user_{idx}",
        },
        {
            "source_type": "SYSMON",
            "source_name": "sysmon_win",
            "hostname": "finance-srv-09",
            "username": "admin_bob",
            "process": "cmd.exe",
            "parent_process": "explorer.exe",
            "command_line": "cmd.exe /c whoami",
            "event_type": "sysmon_process_create",
            "event_category": "endpoint",
            "severity": "low",
            "message": "Admin running whoami on separate finance server",
            "timestamp": (base_t0 + timedelta(seconds=30)).isoformat(),
            "raw_reference": f"sys_user_{idx}",
        },
    ]
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_K_SHARED_USERNAME",
        title="Admin User Active Across Distinct Hosts",
        description="User bob logs in on workstation while separate host runs admin script.",
        ground_truth="BENIGN",
        expected_detection=False,
        expected_correlation=False,
        expected_correlation_rules=[],
        expected_failure_mode="BENIGN_NO_ALERTS",
        events=ev_k,
    ))
    idx += 1

    # --- CLASS L: Same Destination Used by Unrelated Activities ---
    ev_l = [
        {
            "source_type": "ZEEK",
            "source_name": "zeek_conn",
            "source_ip": "10.0.0.15",
            "destination_ip": "1.1.1.1",
            "destination_port": 53,
            "protocol": "udp",
            "event_type": "conn",
            "event_category": "network",
            "severity": "low",
            "message": "DNS lookup to Cloudflare DNS",
            "timestamp": base_t0.isoformat(),
            "raw_reference": f"dest_zeek_{idx}",
        },
        {
            "source_type": "SYSMON",
            "source_name": "sysmon_win",
            "hostname": "workstation-88",
            "source_ip": "10.0.0.88",
            "destination_ip": "1.1.1.1",
            "destination_port": 53,
            "event_type": "sysmon_dns_query",
            "event_category": "endpoint",
            "dns_query": "beacon.evilcorp.net",
            "severity": "high",
            "message": "Suspicious domain query sent to 1.1.1.1",
            "timestamp": (base_t0 + timedelta(seconds=12)).isoformat(),
            "raw_reference": f"dest_sys_{idx}",
        },
    ]
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_L_SHARED_DESTINATION_IP",
        title="Unrelated Systems Contacting Public DNS Server (1.1.1.1)",
        description="Shared destination IP (public DNS) between unrelated internal hosts.",
        ground_truth="ATTACK",
        expected_detection=True, # Sysmon DNS beacon alert fires
        expected_correlation=False, # Different source IPs, no host overlap -> should NOT correlate
        expected_correlation_rules=[],
        expected_failure_mode="CORRECT_NON_CORRELATION_DEST_IS_PUBLIC_INFRA",
        events=ev_l,
    ))
    idx += 1

    # --- CLASS M: Benign PowerShell ---
    ev_m = [
        {
            "source_type": "SYSMON",
            "source_name": "sysmon_win",
            "hostname": "ws-dev-01",
            "username": "developer",
            "process": "powershell.exe",
            "parent_process": "code.exe",
            "command_line": "powershell.exe -ExecutionPolicy Bypass -File build.ps1",
            "event_type": "sysmon_process_create",
            "event_category": "endpoint",
            "severity": "low",
            "message": "Developer VSCode terminal running local build script",
            "timestamp": base_t0.isoformat(),
            "raw_reference": f"benign_ps_{idx}",
        }
    ]
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_M_BENIGN_POWERSHELL",
        title="Legitimate Developer PowerShell Build Script",
        description="VSCode spawned build script without encoded commands; should not alert.",
        ground_truth="BENIGN",
        expected_detection=False,
        expected_correlation=False,
        expected_correlation_rules=[],
        expected_failure_mode="TRUE_NEGATIVE_BENIGN_ACTIVITY",
        events=ev_m,
    ))
    idx += 1

    # --- CLASS N: Benign Administrative Tools ---
    ev_n = [
        {
            "source_type": "SYSMON",
            "source_name": "sysmon_win",
            "hostname": "dc-srv-01",
            "username": "sysadmin",
            "process": "certutil.exe",
            "parent_process": "explorer.exe",
            "command_line": "certutil.exe -getconfig",
            "event_type": "sysmon_process_create",
            "event_category": "endpoint",
            "severity": "low",
            "message": "Admin inspecting CA configuration",
            "timestamp": base_t0.isoformat(),
            "raw_reference": f"benign_admin_{idx}",
        }
    ]
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_N_BENIGN_ADMIN_TOOLS",
        title="Legitimate CA Inspection with Certutil",
        description="Certutil used for configuration check rather than URL payload download.",
        ground_truth="BENIGN",
        expected_detection=False,
        expected_correlation=False,
        expected_correlation_rules=[],
        expected_failure_mode="TRUE_NEGATIVE_BENIGN_ADMIN",
        events=ev_n,
    ))
    idx += 1

    # --- CLASS O: High-Volume Legitimate Network Activity ---
    ev_o = []
    for h in range(10):
        ev_o.append({
            "source_type": "ZEEK",
            "source_name": "zeek_conn",
            "source_ip": "10.0.1.100",
            "destination_ip": "10.0.0.10",
            "destination_port": 80,
            "protocol": "tcp",
            "bytes_in": 256,
            "bytes_out": 512,
            "event_type": "conn",
            "event_category": "network",
            "severity": "low",
            "message": f"Routine load balancer health check #{h}",
            "timestamp": (base_t0 + timedelta(seconds=h * 2)).isoformat(),
            "raw_reference": f"health_chk_{idx}_{h}",
        })
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_O_HIGH_VOLUME_LEGIT_NETWORK",
        title="High-Volume Load Balancer Health Check Probes",
        description="Repeated HTTP SYN/ACK flows on port 80; benign high volume.",
        ground_truth="BENIGN",
        expected_detection=False,
        expected_correlation=False,
        expected_correlation_rules=[],
        expected_failure_mode="TRUE_NEGATIVE_BENIGN_HIGH_VOLUME",
        events=ev_o,
    ))
    idx += 1

    # --- CLASS P: Near-Match Process Names (Typo-squatting) ---
    ev_p = [
        {
            "source_type": "SYSMON",
            "source_name": "sysmon_win",
            "hostname": "workstation-03",
            "process": "svch0st.exe",  # Typo-squatting
            "parent_process": "services.exe",
            "command_line": "svch0st.exe -k netsvcs",
            "event_type": "sysmon_process_create",
            "event_category": "endpoint",
            "severity": "medium",
            "message": "Typo-squatted process name disguised as service host",
            "timestamp": base_t0.isoformat(),
            "raw_reference": f"typo_proc_{idx}",
        }
    ]
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_P_NEAR_MATCH_PROCESS_NAME",
        title="Typo-Squatted Impersonation Process (svch0st.exe)",
        description="Adversary disguises malware using zero instead of letter o in svchost.",
        ground_truth="ATTACK",
        expected_detection=False,  # Baseline rules check specific signatures or enc powershell
        expected_correlation=False,
        expected_correlation_rules=[],
        expected_failure_mode="MISSED_DETECTION_SUBTLE_IMPERSONATION",
        events=ev_p,
    ))
    idx += 1

    # --- CLASS Q: Case Variation ---
    events_base = make_base_events(base_t0, f"198.51.100.{idx}", f"srv-{idx}")
    ev_q, log_q = engine.mutate_case(events_base, target_fields=["process", "command_line"])
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_Q_CASE_VARIATION",
        title="Adversarial Case Inversion on PowerShell Command",
        description="Adversary invokes PoWeRsHeLl.ExE with mixed casing on arguments.",
        ground_truth="ATTACK",
        expected_detection=True, # Case-insensitive detection regexes handle this
        expected_correlation=True,
        expected_correlation_rules=["CORR-001", "CORR-002"],
        expected_failure_mode="ROBUST_CASE_INSENSITIVE_MATCH",
        events=ev_q,
        perturbation_meta={"type": "mutate_case", "log": log_q},
    ))
    idx += 1

    # --- CLASS R: Path Encoding Variation (URL Encoding) ---
    events_base = make_base_events(base_t0, f"198.51.100.{idx}", f"srv-{idx}")
    ev_r, log_r = engine.mutate_payload(events_base, mutation_style="url_encode")
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_R_PATH_ENCODING_VARIATION",
        title="URL Encoded SQL Injection Payload (%27%20OR%201%3D1)",
        description="Web SQLi probe submitted with full percent-encoding evasion.",
        ground_truth="ATTACK",
        expected_detection=True, # Log parser / rules URL-decode incoming paths
        expected_correlation=True,
        expected_correlation_rules=["CORR-001", "CORR-002"],
        expected_failure_mode="ROBUST_URL_DECODED_DETECTION",
        events=ev_r,
        perturbation_meta={"type": "mutate_payload", "log": log_r},
    ))
    idx += 1

    # --- CLASS S: SQL Payload Mutation (Comment Insertion) ---
    events_base = make_base_events(base_t0, f"198.51.100.{idx}", f"srv-{idx}")
    ev_s, log_s = engine.mutate_payload(events_base, mutation_style="sql_comments")
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_S_SQL_PAYLOAD_MUTATION",
        title="SQL Injection Obfuscation via Inline Comments (union/**/select)",
        description="Attacker splits SQL keywords with C-style comments to bypass naive substring matches.",
        ground_truth="ATTACK",
        expected_detection=True,
        expected_correlation=True,
        expected_correlation_rules=["CORR-001", "CORR-002"],
        expected_failure_mode="PARTIAL_DETECTION_SENSITIVITY",
        events=ev_s,
        perturbation_meta={"type": "mutate_payload", "log": log_s},
    ))
    idx += 1

    # --- CLASS T: DNS Mutation ---
    events_dns = [
        {
            "source_type": "SYSMON",
            "source_name": "sysmon_win",
            "hostname": "workstation-77",
            "dns_query": "beacon.evilcorp.org",  # .org instead of .net
            "event_type": "sysmon_dns_query",
            "event_category": "endpoint",
            "severity": "medium",
            "message": "DNS resolution for beacon.evilcorp.org",
            "timestamp": base_t0.isoformat(),
            "raw_reference": f"dns_mut_sys_{idx}",
        },
        {
            "source_type": "ZEEK",
            "source_name": "zeek_dns",
            "hostname": "workstation-77",
            "dns_query": "beacon.evilcorp.net",  # .net
            "event_type": "dns",
            "event_category": "network",
            "severity": "medium",
            "message": "Zeek observed query for beacon.evilcorp.net",
            "timestamp": (base_t0 + timedelta(seconds=2)).isoformat(),
            "raw_reference": f"dns_mut_zk_{idx}",
        },
    ]
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_T_DNS_MUTATION",
        title="Mismatched TLD in Endpoint vs Network DNS Query",
        description="Sysmon records .org while Zeek records .net; test deterministic string match boundary.",
        ground_truth="ATTACK",
        expected_detection=True,
        expected_correlation=False, # Mismatched domain prevents CORR-004
        expected_correlation_rules=[],
        expected_failure_mode="MISSED_CORRELATION_STRING_MISMATCH",
        events=events_dns,
    ))
    idx += 1

    # --- CLASS U: Port Variation ---
    events_base = make_base_events(base_t0, f"198.51.100.{idx}", f"srv-{idx}")
    ev_u, log_u = engine.alter_destination_port(events_base, new_port=9999) # 9999 not in canonical rule port list [1337, 31337, 4444, 6667]
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_U_PORT_VARIATION",
        title="C2 Connection Over Non-Standard Port (TCP 9999)",
        description="Adversary communicates over port 9999, bypassing static port alert rules.",
        ground_truth="ATTACK",
        expected_detection=True, # Web & Sysmon rules fire
        expected_correlation=True, # Web + Sysmon can still correlate via CORR-002
        expected_correlation_rules=["CORR-002"],
        expected_failure_mode="PARTIAL_DETECTION_ZEEK_RULE_MISSED",
        events=ev_u,
        perturbation_meta={"type": "alter_destination_port", "log": log_u},
    ))
    idx += 1

    # --- CLASS V: Multi-Stage Attack with Partial Telemetry ---
    # Drop stage 2 (Zeek), keep reconnaissance (Web) and action on objectives (Sysmon)
    events_base = make_base_events(base_t0, f"198.51.100.{idx}", f"srv-{idx}")
    ev_v = [events_base[0], events_base[2]] # Only Web and Sysmon
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_V_MULTI_STAGE_PARTIAL_TELEMETRY",
        title="Reconnaissance and Endpoint Execution Without Intervening Wire Data",
        description="Perimeter proxy logged web exploit; endpoint logged shellcode; network tap was blind.",
        ground_truth="ATTACK",
        expected_detection=True,
        expected_correlation=True,
        expected_correlation_rules=["CORR-002"],
        expected_failure_mode="ROBUST_TWO_SOURCE_CORRELATION",
        events=ev_v,
    ))
    idx += 1

    # --- CLASS W: Concurrent Unrelated Attacks ---
    # Two separate attackers attacking separate hosts simultaneously
    ev_w = [
        {
            "source_type": "WEB",
            "source_name": "nginx_access",
            "source_ip": "198.51.100.111",
            "hostname": "web-srv-alpha",
            "event_type": "web_access",
            "event_category": "security",
            "severity": "high",
            "message": "Attacker 1 SQLi against Alpha",
            "request_path": "/search?q=' OR 1=1 --",
            "timestamp": base_t0.isoformat(),
            "raw_reference": f"atk1_{idx}",
        },
        {
            "source_type": "WEB",
            "source_name": "nginx_access",
            "source_ip": "198.51.100.222",
            "hostname": "web-srv-beta",
            "event_type": "web_access",
            "event_category": "security",
            "severity": "high",
            "message": "Attacker 2 SQLi against Beta",
            "request_path": "/search?q=' OR 1=1 --",
            "timestamp": (base_t0 + timedelta(seconds=5)).isoformat(),
            "raw_reference": f"atk2_{idx}",
        },
    ]
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_W_CONCURRENT_UNRELATED_ATTACKS",
        title="Concurrent External Attacks Against Distinct Targets",
        description="Two unrelated attackers strike two distinct web nodes within 5 seconds; must NOT merge.",
        ground_truth="ATTACK",
        expected_detection=True,
        expected_correlation=False, # Distinct IPs & hosts -> must stay separate
        expected_correlation_rules=[],
        expected_failure_mode="CORRECT_INCIDENT_SEPARATION",
        events=ev_w,
    ))
    idx += 1

    # --- CLASS X: Long Temporal Separation (>600s) ---
    events_base = make_base_events(base_t0, f"198.51.100.{idx}", f"srv-{idx}")
    ev_x, log_x = engine.delay_timestamp(events_base, target_source="SYSMON", delay_seconds=1200.0) # 20 minutes apart
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_X_LONG_TEMPORAL_SEPARATION",
        title="Dormant Exploitation Stage (20 Minute Dwell Delay)",
        description="Exploit probe at t=0; attacker waits 20 minutes before executing payload; exceeds all standard windows.",
        ground_truth="ATTACK",
        expected_detection=True,
        expected_correlation=False, # Exceeds 600s window -> separated
        expected_correlation_rules=[],
        expected_failure_mode="MISSED_CORRELATION_EXTENDED_DWELL",
        events=ev_x,
        perturbation_meta={"type": "delay_timestamp", "log": log_x},
    ))
    idx += 1

    # --- CLASS Y: Boundary-Window Correlation (t=295s, near 300s edge) ---
    events_base = make_base_events(base_t0, f"198.51.100.{idx}", f"srv-{idx}")
    ev_y, log_y = engine.delay_timestamp(events_base, target_source="SYSMON", delay_seconds=290.0)
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_Y_BOUNDARY_WINDOW_CORRELATION",
        title="Payload Execution at Exact Window Boundary (t=290s)",
        description="Payload executes 290s after exploit, testing correlation window boundary tolerance.",
        ground_truth="ATTACK",
        expected_detection=True,
        expected_correlation=True, # 290s < 300s -> correlates with heavy temporal decay
        expected_correlation_rules=["CORR-001", "CORR-002"],
        expected_failure_mode="ROBUST_BOUNDARY_CORRELATION_LOW_TIME_FACTOR",
        events=ev_y,
        perturbation_meta={"type": "delay_timestamp", "log": log_y},
    ))
    idx += 1

    # --- CLASS Z: Completely Unrelated Multi-Source Events ---
    ev_z = [
        {
            "source_type": "WEB",
            "source_name": "nginx",
            "source_ip": "1.1.1.1",
            "destination_ip": "10.0.0.1",
            "hostname": "alpha-web",
            "event_type": "web_access",
            "event_category": "security",
            "severity": "high",
            "message": "SQLi probe from IP 1.1.1.1",
            "request_path": "/search?q=' OR 1=1 --",
            "timestamp": base_t0.isoformat(),
            "raw_reference": f"disjoint_web_{idx}",
        },
        {
            "source_type": "ZEEK",
            "source_name": "zeek",
            "source_ip": "2.2.2.2",
            "destination_ip": "10.0.0.2",
            "destination_port": 4444,
            "event_type": "conn",
            "event_category": "network",
            "severity": "high",
            "message": "C2 port connection from IP 2.2.2.2",
            "timestamp": (base_t0 + timedelta(seconds=10)).isoformat(),
            "raw_reference": f"disjoint_zeek_{idx}",
        },
        {
            "source_type": "SYSMON",
            "source_name": "sysmon",
            "hostname": "gamma-workstation",
            "process": "powershell.exe",
            "command_line": "powershell.exe -enc dGVzdA==",
            "event_type": "sysmon_process_create",
            "event_category": "endpoint",
            "severity": "critical",
            "message": "Encoded powershell on Gamma workstation",
            "timestamp": (base_t0 + timedelta(seconds=20)).isoformat(),
            "raw_reference": f"disjoint_sys_{idx}",
        },
    ]
    scenarios.append(build_adversarial_scenario(
        scenario_id=make_id(idx),
        scenario_class="CLASS_Z_COMPLETELY_UNRELATED_EVENTS",
        title="Three Independent Alerts with Zero Shared Entities",
        description="Three distinct attacks targeting three distinct hosts from three distinct IPs; must produce 3 separate incidents.",
        ground_truth="ATTACK",
        expected_detection=True,
        expected_correlation=False, # Zero shared entities -> 3 distinct incidents
        expected_correlation_rules=[],
        expected_failure_mode="CORRECT_COMPLETE_SEPARATION",
        events=ev_z,
    ))
    idx += 1

    # For DEV, add remaining 14 scenarios to reach 40 total
    # For TEST, add remaining scenarios to reach 20 total
    target_count = 40 if is_dev else (18 if is_val else 20)

    while len(scenarios) < target_count:
        # Generate adversarial variations across truncation, case mutation, optional field removal, and payload mutations
        var_type = len(scenarios) % 4
        base_ip = f"198.51.100.{idx}"
        host = f"srv-robust-{idx}"
        events_base = make_base_events(base_t0, base_ip, host)

        if var_type == 0:
            ev_var, log_var = engine.truncate_field(events_base, target_field="command_line", max_length=12)
            cls_name = "CLASS_P_TRUNCATED_COMMAND_LINE"
            title_text = f"Truncated Sysmon Command Line #{idx}"
            failure_mode = "MISSED_DETECTION_COMMAND_TRUNCATION"
            exp_det = True
            exp_corr = True
            exp_rules = ["CORR-001"] # Sysmon encoded command was truncated, so ENDPOINT-001 might not match
        elif var_type == 1:
            ev_var, log_var = engine.remove_optional_field(events_base, target_fields=["hostname", "process_id"])
            cls_name = "CLASS_F_STRIPPED_HOSTNAME"
            title_text = f"Telemetry Lacking Hostname Field #{idx}"
            failure_mode = "GRACEFUL_IP_BASED_CORRELATION"
            exp_det = True
            exp_corr = True
            exp_rules = ["CORR-001", "CORR-003"]
        elif var_type == 2:
            ev_var, log_var = engine.introduce_unrelated_event(events_base, source_type="ZEEK")
            cls_name = "CLASS_O_NOISY_BACKGROUND_EVENT"
            title_text = f"Attack With Injected Background Noise #{idx}"
            failure_mode = "ROBUST_NOISE_REJECTION"
            exp_det = True
            exp_corr = True
            exp_rules = ["CORR-001", "CORR-002"]
        else:
            ev_var, log_var = engine.mutate_payload(events_base, mutation_style="ps_alias")
            cls_name = "CLASS_S_POWERSHELL_ALIAS_MUTATION"
            title_text = f"PowerShell Obfuscation Using -e Parameter #{idx}"
            failure_mode = "PARTIAL_DETECTION_ALIAS_MATCH"
            exp_det = True
            exp_corr = True
            exp_rules = ["CORR-001", "CORR-002"]

        scenarios.append(build_adversarial_scenario(
            scenario_id=make_id(idx),
            scenario_class=cls_name,
            title=title_text,
            description=f"Deterministic adversarial variation test scenario {idx}.",
            ground_truth="ATTACK",
            expected_detection=exp_det,
            expected_correlation=exp_corr,
            expected_correlation_rules=exp_rules,
            expected_failure_mode=failure_mode,
            events=ev_var,
            perturbation_meta={"type": "variation", "log": log_var},
        ))
        idx += 1

    return scenarios[:target_count]


def main() -> None:
    out_dir = Path(__file__).resolve().parent / "datasets" / "adversarial_v1"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Generating Adversarial Telemetry & Robustness Benchmark V1...")

    dev_scenarios = generate_scenarios_for_split("dev", seed_base=101)
    val_scenarios = generate_scenarios_for_split("validation", seed_base=202)
    test_scenarios = generate_scenarios_for_split("test", seed_base=303)

    (out_dir / "dev_scenarios.json").write_text(json.dumps(dev_scenarios, indent=2), encoding="utf-8")
    (out_dir / "validation_scenarios.json").write_text(json.dumps(val_scenarios, indent=2), encoding="utf-8")
    (out_dir / "held_out_test_scenarios.json").write_text(json.dumps(test_scenarios, indent=2), encoding="utf-8")

    manifest = {
        "dataset_name": "adversarial_v1",
        "created_at": datetime.now(UTC).isoformat(),
        "total_scenarios": len(dev_scenarios) + len(val_scenarios) + len(test_scenarios),
        "splits": {
            "dev": {
                "count": len(dev_scenarios),
                "sha256": hashlib.sha256((out_dir / "dev_scenarios.json").read_bytes()).hexdigest(),
            },
            "validation": {
                "count": len(val_scenarios),
                "sha256": hashlib.sha256((out_dir / "validation_scenarios.json").read_bytes()).hexdigest(),
            },
            "held_out_test": {
                "count": len(test_scenarios),
                "sha256": hashlib.sha256((out_dir / "held_out_test_scenarios.json").read_bytes()).hexdigest(),
                "status": "STRICTLY_FROZEN_HELD_OUT",
            },
        },
    }
    manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
    (out_dir / "manifest.json").write_bytes(manifest_bytes)
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()

    print(f"Generated {len(dev_scenarios)} DEV, {len(val_scenarios)} VAL, {len(test_scenarios)} TEST scenarios.")
    print(f"Total: {manifest['total_scenarios']} scenarios.")
    print(f"Manifest SHA-256: {manifest_sha}")


if __name__ == "__main__":
    main()
