"""
research/generate_cross_source_v1.py

Phase 6: Cross-Source Correlation Benchmark Dataset V1 Generator

Generates a balanced multi-source benchmark covering telemetry from:
  - WEB / AUTH
  - ZEEK NETWORK TELEMETRY
  - WINDOWS SYSMON TELEMETRY

Dataset Specifications:
  - Splits:
      * DEV: 36 scenarios
      * VALIDATION: 16 scenarios
      * HELD-OUT TEST: 18 scenarios (Strictly frozen & untouched)
      * TOTAL: 70 scenarios
  - Balanced distribution across Categories A through J:
      * Category A: Web-only activity (SQLi, XSS, Path Traversal)
      * Category B: Network-only activity (Zeek backdoor port, C2 beaconing)
      * Category C: Endpoint-only activity (Sysmon encoded PowerShell, web worker shell)
      * Category D: Multi-source attacks (Web probe -> Zeek network flow -> Sysmon execution)
      * Category E: Multi-source benign activity (Developer testing, automated CI/CD pipeline)
      * Category F: Events with missing telemetry (missing endpoint or network layer)
      * Category G: Similar-looking but unrelated events (simultaneous benign admin & scanner)
      * Category H: Timing variations (evaluating ±30s, ±120s, ±300s, ±600s boundaries)
      * Category I: Shared IP but unrelated activity (NAT gateway / public proxy non-correlation)
      * Category J: Shared hostname but unrelated activity (multi-user or background system cron)
  - Ground Truth:
      * Distinguishes TRUE CORRELATION, FALSE CORRELATION, MISSED CORRELATION.
      * Explicit non-correlation criteria ensuring Same IP != Same Incident.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent / "datasets" / "cross_source_v1"


def create_scenario(
    scenario_id: str,
    category: str,
    category_name: str,
    title: str,
    description: str,
    ground_truth: str,  # "ATTACK" | "BENIGN"
    is_multi_source: bool,
    expected_incident_count: int,
    expected_correlation: bool,
    expected_correlation_rules: list[str],
    expected_non_correlation_reason: str | None,
    events: list[dict],
) -> dict:
    return {
        "scenario_id": scenario_id,
        "category": category,
        "category_name": category_name,
        "title": title,
        "description": description,
        "ground_truth": ground_truth,
        "is_multi_source": is_multi_source,
        "expected_incident_count": expected_incident_count,
        "expected_correlation": expected_correlation,
        "expected_correlation_rules": expected_correlation_rules,
        "expected_non_correlation_reason": expected_non_correlation_reason,
        "events": events,
    }


def make_dev_scenarios() -> list[dict]:
    t0 = datetime(2026, 10, 8, 10, 0, 0, tzinfo=UTC)
    scenarios = []

    # Category A: Web-only activity (4 scenarios)
    # DEV-01: Web SQL Injection attack (triggers RULE-012)
    scenarios.append(create_scenario(
        "CROSS-DEV-001", "A", "Web-Only Activity",
        "Web SQL Injection Attack",
        "Isolated Web SQLi attack with no matching network or endpoint anomalies.",
        "ATTACK", False, 1, False, [],
        "Single-source web activity without cross-source telemetry link",
        [
            {
                "timestamp": t0.isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "critical",
                "source_ip": "198.51.100.22", "destination_ip": "10.0.0.10", "destination_port": 443,
                "request_path": "/api/users?id=1' union select username,password from users--",
                "http_method": "GET", "status_code": 200, "user_agent": "sqlmap/1.6",
                "message": "SQL injection attempt detected via union select query",
            }
        ]
    ))

    # DEV-02: Web Path Traversal attempt (triggers RULE-013)
    scenarios.append(create_scenario(
        "CROSS-DEV-002", "A", "Web-Only Activity",
        "Web Path Traversal Attempt",
        "Single-source directory traversal attempt targeting /etc/passwd.",
        "ATTACK", False, 1, False, [],
        "Single-source web activity",
        [
            {
                "timestamp": (t0 + timedelta(seconds=5)).isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "high",
                "source_ip": "198.51.100.33", "destination_ip": "10.0.0.10", "destination_port": 80,
                "request_path": "/static/../../../../etc/passwd", "http_method": "GET", "status_code": 403,
                "message": "Path traversal attempt detected in request path",
            }
        ]
    ))

    # DEV-03: Benign Web Browsing
    scenarios.append(create_scenario(
        "CROSS-DEV-003", "A", "Web-Only Activity",
        "Normal Web Browsing",
        "Benign user accessing documentation and static assets.",
        "BENIGN", False, 0, False, [],
        "Benign activity without detections",
        [
            {
                "timestamp": (t0 + timedelta(seconds=10)).isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "low",
                "source_ip": "192.168.1.105", "destination_ip": "10.0.0.10", "destination_port": 443,
                "request_path": "/docs/index.html", "http_method": "GET", "status_code": 200,
                "message": "Standard HTTP GET request to documentation",
            }
        ]
    ))

    # DEV-04: Benign Web Search
    scenarios.append(create_scenario(
        "CROSS-DEV-004", "A", "Web-Only Activity",
        "Normal Search API Request",
        "Standard user search query with typical parameters.",
        "BENIGN", False, 0, False, [],
        "Benign query without anomaly",
        [
            {
                "timestamp": (t0 + timedelta(seconds=15)).isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "low",
                "source_ip": "192.168.1.110", "destination_ip": "10.0.0.10", "destination_port": 443,
                "request_path": "/api/search?q=compliance", "http_method": "GET", "status_code": 200,
                "message": "Standard search API request",
            }
        ]
    ))

    # Category B: Network-only activity (4 scenarios)
    # DEV-05: Zeek Suspicious Port Connection (triggers NETWORK-001)
    scenarios.append(create_scenario(
        "CROSS-DEV-005", "B", "Network-Only Activity",
        "Zeek Backdoor Port Connection",
        "Zeek network detection of connection targeting C2 backdoor port 4444.",
        "ATTACK", False, 1, False, [],
        "Single-source network telemetry",
        [
            {
                "timestamp": (t0 + timedelta(seconds=20)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                "source_ip": "203.0.113.88", "destination_ip": "10.0.0.15", "destination_port": 4444,
                "protocol": "TCP", "connection_state": "SF", "raw_reference": "Cscan101",
                "message": "Suspicious destination port connection to 4444",
            }
        ]
    ))

    # DEV-06: Zeek Backdoor High Port Connection (triggers NETWORK-001)
    scenarios.append(create_scenario(
        "CROSS-DEV-006", "B", "Network-Only Activity",
        "Zeek Port 31337 Trojan Connection",
        "Suspicious inbound connection to known Elite Trojan port 31337.",
        "ATTACK", False, 1, False, [],
        "Single-source Zeek network anomaly",
        [
            {
                "timestamp": (t0 + timedelta(seconds=25)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                "source_ip": "203.0.113.89", "destination_ip": "10.0.0.55", "destination_port": 31337,
                "protocol": "TCP", "connection_state": "SF",
                "message": "Suspicious connection to trojan port 31337",
            }
        ]
    ))

    # DEV-07: Normal NTP Network Traffic
    scenarios.append(create_scenario(
        "CROSS-DEV-007", "B", "Network-Only Activity",
        "Normal NTP Synchronization",
        "Standard Zeek connection log of internal host querying time server.",
        "BENIGN", False, 0, False, [],
        "Benign protocol sync",
        [
            {
                "timestamp": (t0 + timedelta(seconds=30)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "low",
                "source_ip": "10.0.0.20", "destination_ip": "129.6.15.28", "destination_port": 123,
                "protocol": "UDP", "connection_state": "SF", "bytes_in": 48, "bytes_out": 48,
                "message": "NTP network synchronization connection",
            }
        ]
    ))

    # DEV-08: Normal Outbound HTTPS Connection
    scenarios.append(create_scenario(
        "CROSS-DEV-008", "B", "Network-Only Activity",
        "Standard Cloud API Outbound Flow",
        "Internal service connecting to AWS S3 endpoint on port 443.",
        "BENIGN", False, 0, False, [],
        "Routine business traffic",
        [
            {
                "timestamp": (t0 + timedelta(seconds=35)).isoformat(),
                "source_type": "ZEEK", "event_type": "ssl", "severity": "low",
                "source_ip": "10.0.0.22", "destination_ip": "52.216.14.8", "destination_port": 443,
                "protocol": "TCP", "connection_state": "SF", "bytes_in": 4500, "bytes_out": 1200,
                "message": "Routine HTTPS connection to public cloud service",
            }
        ]
    ))

    # Category C: Endpoint-only activity (4 scenarios)
    # DEV-09: Sysmon Encoded PowerShell Execution (triggers ENDPOINT-001)
    scenarios.append(create_scenario(
        "CROSS-DEV-009", "C", "Endpoint-Only Activity",
        "Sysmon Encoded PowerShell Execution",
        "PowerShell executed with -enc flag indicating obfuscated payload.",
        "ATTACK", False, 1, False, [],
        "Single-source endpoint detection",
        [
            {
                "timestamp": (t0 + timedelta(seconds=40)).isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_process_create", "severity": "high",
                "hostname": "CORP-WKSTN-12", "username": "corp\\jsmith", "process": "powershell.exe",
                "process_id": 4120, "command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGo...",
                "message": "Suspicious process execution with encoded command line",
            }
        ]
    ))

    # DEV-10: Sysmon Web Worker Shell (triggers ENDPOINT-002)
    scenarios.append(create_scenario(
        "CROSS-DEV-010", "C", "Endpoint-Only Activity",
        "Sysmon Web Worker Shell Spawn",
        "Web worker w3wp.exe spawned cmd.exe command shell.",
        "ATTACK", False, 1, False, [],
        "Endpoint-only defense evasion",
        [
            {
                "timestamp": (t0 + timedelta(seconds=45)).isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_process_create", "severity": "critical",
                "hostname": "CORP-SRV-01", "username": "IIS APPPOOL\\DefaultAppPool", "process": "cmd.exe",
                "parent_process": "w3wp.exe", "process_id": 5512, "command_line": "cmd.exe /c whoami",
                "message": "Suspicious parent-child relationship: w3wp.exe spawned cmd.exe",
            }
        ]
    ))

    # DEV-11: Benign Host Process Startup
    scenarios.append(create_scenario(
        "CROSS-DEV-011", "C", "Endpoint-Only Activity",
        "Benign Windows Update Service Execution",
        "Legitimate svchost.exe invocation of Windows Update agent.",
        "BENIGN", False, 0, False, [],
        "Standard operating system background task",
        [
            {
                "timestamp": (t0 + timedelta(seconds=50)).isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_process_create", "severity": "low",
                "hostname": "CORP-WKSTN-12", "username": "NT AUTHORITY\\SYSTEM", "process": "svchost.exe",
                "process_id": 1104, "command_line": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s wuauserv",
                "message": "Windows Update service component launch",
            }
        ]
    ))

    # DEV-12: Benign Calculator Execution
    scenarios.append(create_scenario(
        "CROSS-DEV-012", "C", "Endpoint-Only Activity",
        "User Launching Calculator",
        "Normal interactive launch of calc.exe from Explorer.",
        "BENIGN", False, 0, False, [],
        "Benign user application startup",
        [
            {
                "timestamp": (t0 + timedelta(seconds=55)).isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_process_create", "severity": "low",
                "hostname": "CORP-WKSTN-03", "username": "corp\\alice", "process": "calc.exe",
                "process_id": 7820, "parent_process": "explorer.exe",
                "command_line": "C:\\Windows\\System32\\calc.exe",
                "message": "Standard interactive application execution",
            }
        ]
    ))

    # Category D: Multi-source attacks (6 scenarios)
    # DEV-13: CORR-001 (Web SQLi [RULE-012] + Zeek Backdoor Port [NETWORK-001], same IP 198.51.100.99 within 12s)
    scenarios.append(create_scenario(
        "CROSS-DEV-013", "D", "Multi-Source Attack",
        "Web Exploit and Zeek Connection Correlation [CORR-001]",
        "External IP attempts Web SQL injection, followed by Zeek connection to backdoor port 4444.",
        "ATTACK", True, 1, True, ["CORR-001"],
        None,
        [
            {
                "timestamp": (t0 + timedelta(seconds=60)).isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "critical",
                "source_ip": "198.51.100.99", "destination_ip": "10.0.0.10", "destination_port": 443,
                "request_path": "/login.php?user=admin' or '1'='1", "http_method": "POST", "status_code": 500,
                "message": "SQL injection attempt detected in request path",
            },
            {
                "timestamp": (t0 + timedelta(seconds=72)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                "source_ip": "198.51.100.99", "destination_ip": "10.0.0.10", "destination_port": 4444,
                "protocol": "TCP", "connection_state": "SF", "bytes_in": 12500, "bytes_out": 840,
                "message": "Suspicious destination port connection to 4444",
            }
        ]
    ))

    # DEV-14: CORR-002 (Web Path Traversal [RULE-013] + Sysmon Shell Spawn [ENDPOINT-002], same host CORP-WEB-01 within 8s)
    scenarios.append(create_scenario(
        "CROSS-DEV-014", "D", "Multi-Source Attack",
        "Web Exploit Spawning Host Shell [CORR-002]",
        "Web path traversal exploit followed by w3wp.exe spawning cmd.exe whoami on same host.",
        "ATTACK", True, 1, True, ["CORR-002"],
        None,
        [
            {
                "timestamp": (t0 + timedelta(seconds=90)).isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "high",
                "source_ip": "198.51.100.105", "destination_ip": "10.0.0.10", "hostname": "CORP-WEB-01",
                "request_path": "/uploads/../../etc/passwd", "http_method": "GET", "status_code": 200,
                "message": "Path traversal attempt detected in request path",
            },
            {
                "timestamp": (t0 + timedelta(seconds=98)).isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_process_create", "severity": "critical",
                "hostname": "CORP-WEB-01", "username": "IIS APPPOOL\\DefaultAppPool",
                "process": "cmd.exe", "parent_process": "w3wp.exe", "process_id": 6224,
                "command_line": "cmd.exe /c whoami", "source_ip": "10.0.0.10",
                "message": "Suspicious parent-child relationship: w3wp.exe spawned cmd.exe",
            }
        ]
    ))

    # DEV-15: CORR-003 (Sysmon Network Connect [ENDPOINT-003] + Zeek Flow [NETWORK-001], same dest IP 203.0.113.50 within 10s)
    scenarios.append(create_scenario(
        "CROSS-DEV-015", "D", "Multi-Source Attack",
        "Endpoint C2 Connection Correlated with Zeek Network Flow [CORR-003]",
        "Sysmon logs rundll32.exe connecting to port 4444; Zeek captures matching flow.",
        "ATTACK", True, 1, True, ["CORR-003"],
        None,
        [
            {
                "timestamp": (t0 + timedelta(seconds=120)).isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_network_connection", "severity": "high",
                "hostname": "CORP-SRV-02", "username": "corp\\jsmith", "process": "rundll32.exe",
                "process_id": 9112, "destination_ip": "203.0.113.50", "destination_port": 4444,
                "message": "Suspicious process network connection: rundll32.exe to port 4444",
            },
            {
                "timestamp": (t0 + timedelta(seconds=130)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                "source_ip": "10.0.0.25", "destination_ip": "203.0.113.50", "destination_port": 4444,
                "protocol": "TCP", "connection_state": "SF", "bytes_out": 850000, "bytes_in": 1200,
                "message": "Suspicious destination port connection to 4444",
            }
        ]
    ))

    # DEV-16: CORR-004 (Sysmon DNS Query [ENDPOINT-004] + Zeek Backdoor Port [NETWORK-001], matching domain within 5s)
    scenarios.append(create_scenario(
        "CROSS-DEV-016", "D", "Multi-Source Attack",
        "Sysmon Process DNS Query Correlated with Zeek Telemetry [CORR-004]",
        "Malicious executable queries C2 domain beacon.darkcorridor.org, verified on Zeek sensor.",
        "ATTACK", True, 1, True, ["CORR-004"],
        None,
        [
            {
                "timestamp": (t0 + timedelta(seconds=150)).isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_dns_query", "severity": "medium",
                "hostname": "CORP-WKSTN-08", "username": "corp\\victim", "process": "powershell.exe",
                "process_id": 3410, "dns_query": "beacon.darkcorridor.org",
                "message": "Suspicious DNS activity: queried beacon domain",
            },
            {
                "timestamp": (t0 + timedelta(seconds=155)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                "source_ip": "10.0.0.88", "destination_ip": "203.0.113.70", "destination_port": 4444,
                "dns_query": "beacon.darkcorridor.org",
                "message": "Suspicious destination port connection to 4444",
            }
        ]
    ))

    # DEV-17: Tri-Source Chain (Web SQLi -> Zeek Port 4444 -> Sysmon Shell on Host)
    scenarios.append(create_scenario(
        "CROSS-DEV-017", "D", "Multi-Source Attack",
        "Full Tri-Source Attack Chain (Web + Zeek + Sysmon)",
        "End-to-end multi-source intrusion: web SQLi, network backdoor flow, host shell execution.",
        "ATTACK", True, 1, True, ["CORR-001", "CORR-002"],
        None,
        [
            {
                "timestamp": (t0 + timedelta(seconds=180)).isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "critical",
                "source_ip": "198.51.100.200", "destination_ip": "10.0.0.10", "hostname": "CORP-WEB-02",
                "request_path": "/admin/upload.php?id=1' union select 1,2--", "http_method": "POST", "status_code": 200,
                "message": "SQL injection attempt detected via union select query",
            },
            {
                "timestamp": (t0 + timedelta(seconds=195)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                "source_ip": "198.51.100.200", "destination_ip": "10.0.0.10", "destination_port": 4444,
                "protocol": "TCP", "connection_state": "SF", "bytes_in": 45000, "bytes_out": 3200,
                "message": "Suspicious destination port connection to 4444",
            },
            {
                "timestamp": (t0 + timedelta(seconds=210)).isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_process_create", "severity": "critical",
                "hostname": "CORP-WEB-02", "username": "IIS APPPOOL\\DefaultAppPool", "process": "cmd.exe",
                "parent_process": "w3wp.exe", "process_id": 8840,
                "command_line": "cmd.exe /c whoami", "source_ip": "10.0.0.10",
                "message": "Suspicious parent-child relationship: w3wp.exe spawned cmd.exe",
            }
        ]
    ))

    # DEV-18: Multi-Source Web SQLi + Matching Zeek Connection
    scenarios.append(create_scenario(
        "CROSS-DEV-018", "D", "Multi-Source Attack",
        "Web Exploit and Secondary C2 Flow",
        "Web application SQL injection followed immediately by Zeek backdoor communication.",
        "ATTACK", True, 1, True, ["CORR-001"],
        None,
        [
            {
                "timestamp": (t0 + timedelta(seconds=240)).isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "critical",
                "source_ip": "198.51.100.77", "destination_ip": "10.0.0.5",
                "request_path": "/search?q=' or 1=1--", "message": "SQL injection attempt detected",
            },
            {
                "timestamp": (t0 + timedelta(seconds=248)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                "source_ip": "198.51.100.77", "destination_ip": "10.0.0.5", "destination_port": 1337,
                "protocol": "TCP", "connection_state": "SF",
                "message": "Suspicious destination port connection to 1337",
            }
        ]
    ))

    # Category E: Multi-source benign activity (4 scenarios)
    # DEV-19: Developer Local Testing (Web request + Zeek flow + npm/node compile, NO attack signature)
    scenarios.append(create_scenario(
        "CROSS-DEV-019", "E", "Multi-Source Benign Activity",
        "Developer Local Testing Workflow",
        "Dev running local web service test with benign node.exe and git.exe actions.",
        "BENIGN", True, 0, False, [],
        "Multi-source routine developer engineering task without attack telemetry",
        [
            {
                "timestamp": (t0 + timedelta(seconds=270)).isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "low",
                "source_ip": "192.168.1.150", "destination_ip": "10.0.0.10", "destination_port": 3000,
                "request_path": "/api/health", "http_method": "GET", "status_code": 200,
                "message": "Developer automated healthcheck request",
            },
            {
                "timestamp": (t0 + timedelta(seconds=275)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "low",
                "source_ip": "192.168.1.150", "destination_ip": "10.0.0.10", "destination_port": 3000,
                "protocol": "TCP", "connection_state": "SF", "bytes_in": 120, "bytes_out": 250,
                "message": "Standard HTTP test connection",
            },
            {
                "timestamp": (t0 + timedelta(seconds=280)).isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_process_create", "severity": "low",
                "hostname": "CORP-DEV-01", "username": "corp\\developer", "process": "node.exe",
                "process_id": 9920, "command_line": "node.exe server.js --env=test",
                "message": "Local development server initialization",
            }
        ]
    ))

    # DEV-20: CI/CD Build Pipeline
    scenarios.append(create_scenario(
        "CROSS-DEV-020", "E", "Multi-Source Benign Activity",
        "Automated CI/CD Build Pipeline",
        "Runner executing build steps and fetching dependencies from package registry.",
        "BENIGN", True, 0, False, [],
        "Legitimate automated pipeline across network and host",
        [
            {
                "timestamp": (t0 + timedelta(seconds=300)).isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_process_create", "severity": "low",
                "hostname": "BUILD-RUNNER-01", "username": "corp\\svc_ci", "process": "git.exe",
                "process_id": 1420, "command_line": "git.exe clone https://github.com/internal/repo.git",
                "message": "Build agent checking out source code",
            },
            {
                "timestamp": (t0 + timedelta(seconds=305)).isoformat(),
                "source_type": "ZEEK", "event_type": "ssl", "severity": "low",
                "source_ip": "10.0.1.50", "destination_ip": "140.82.121.4", "destination_port": 443,
                "protocol": "TCP", "connection_state": "SF", "bytes_out": 3400, "bytes_in": 450000,
                "message": "Legitimate code repository TLS transfer",
            }
        ]
    ))

    # DEV-21: IT Administrator Patch Deployment
    scenarios.append(create_scenario(
        "CROSS-DEV-021", "E", "Multi-Source Benign Activity",
        "Sysadmin Routine Patch Deployment",
        "Admin installing security hotfix via approved deployment scripts.",
        "BENIGN", True, 0, False, [],
        "Authorized administrative maintenance",
        [
            {
                "timestamp": (t0 + timedelta(seconds=330)).isoformat(),
                "source_type": "AUTH", "event_type": "successful_login", "severity": "low",
                "source_ip": "192.168.1.10", "username": "corp\\adm_bob", "hostname": "CORP-SRV-05",
                "message": "Interactive administrator logon via jumpbox",
            },
            {
                "timestamp": (t0 + timedelta(seconds=335)).isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_process_create", "severity": "low",
                "hostname": "CORP-SRV-05", "username": "corp\\adm_bob", "process": "msiexec.exe",
                "process_id": 5120, "command_line": "msiexec.exe /quiet /i KB5012345.msi",
                "message": "Silent installation of approved security update",
            }
        ]
    ))

    # DEV-22: Web Health Check & Monitoring Agent
    scenarios.append(create_scenario(
        "CROSS-DEV-022", "E", "Multi-Source Benign Activity",
        "Monitoring Probe and Zeek Inspection",
        "Prometheus agent probing internal web dashboard and recording ping.",
        "BENIGN", True, 0, False, [],
        "Approved infrastructure monitoring",
        [
            {
                "timestamp": (t0 + timedelta(seconds=360)).isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "low",
                "source_ip": "10.0.0.250", "destination_ip": "10.0.0.10", "request_path": "/metrics",
                "http_method": "GET", "status_code": 200, "user_agent": "Prometheus/2.40",
                "message": "Prometheus metrics scrape",
            },
            {
                "timestamp": (t0 + timedelta(seconds=362)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "low",
                "source_ip": "10.0.0.250", "destination_ip": "10.0.0.10", "destination_port": 9090,
                "protocol": "TCP", "connection_state": "SF",
                "message": "Telemetry poll connection",
            }
        ]
    ))

    # Category F: Events with missing telemetry (3 scenarios)
    # DEV-23: Missing Endpoint Log (Zeek sees C2 traffic, but endpoint agent was uninstalled)
    scenarios.append(create_scenario(
        "CROSS-DEV-023", "F", "Missing Telemetry Layer",
        "C2 Traffic with Missing Endpoint Telemetry",
        "Network sensor detects backdoor flow on port 4444, but endpoint Sysmon log was dropped/absent.",
        "ATTACK", False, 1, False, [],
        "Partial telemetry visibility: network only captured, endpoint missing",
        [
            {
                "timestamp": (t0 + timedelta(seconds=390)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                "source_ip": "10.0.0.101", "destination_ip": "198.51.100.66", "destination_port": 4444,
                "protocol": "TCP", "connection_state": "SF", "bytes_out": 98000, "bytes_in": 450,
                "message": "Suspicious destination port connection to 4444",
            }
        ]
    ))

    # DEV-24: Missing Network Log (Sysmon sees encoded powershell, but perimeter network saw nothing)
    scenarios.append(create_scenario(
        "CROSS-DEV-024", "F", "Missing Telemetry Layer",
        "Credential Dump with Missing Network Telemetry",
        "Host execution detected by Sysmon without any network connection created.",
        "ATTACK", False, 1, False, [],
        "Host-local exploit; no network telemetry exists",
        [
            {
                "timestamp": (t0 + timedelta(seconds=410)).isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_process_create", "severity": "high",
                "hostname": "CORP-SEC-01", "username": "corp\\badactor", "process": "powershell.exe",
                "process_id": 4412, "command_line": "powershell.exe -enc SQBFAFgA...",
                "message": "Suspicious process execution with encoded command line",
            }
        ]
    ))

    # DEV-25: Web Probe with Dropped Zeek Connection Log
    scenarios.append(create_scenario(
        "CROSS-DEV-025", "F", "Missing Telemetry Layer",
        "Web Probe with Network Sensor Blindspot",
        "Web access log recorded XSS payload, but network packet capture dropped.",
        "ATTACK", False, 1, False, [],
        "Web log only; network packet capture dropped",
        [
            {
                "timestamp": (t0 + timedelta(seconds=430)).isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "high",
                "source_ip": "198.51.100.11", "destination_ip": "10.0.0.10", "destination_port": 443,
                "request_path": "/search?q=<script>alert(1)</script>",
                "http_method": "GET", "status_code": 200,
                "message": "Cross-site scripting probe detected",
            }
        ]
    ))

    # Category G: Similar-looking but unrelated events (3 scenarios)
    # DEV-26: Benign Admin and Malicious Attacker at Exact Same Time (Different Source IPs)
    scenarios.append(create_scenario(
        "CROSS-DEV-026", "G", "Unrelated Simultaneous Events",
        "Simultaneous Admin and External Scanner",
        "Two events occur at dt=1.2s: internal admin browsing docs, external attacker scanning.",
        "ATTACK", True, 1, False, [],
        "Different IPs (192.168.1.5 vs 203.0.113.99); must NOT merge unrelated activities",
        [
            {
                "timestamp": (t0 + timedelta(seconds=450)).isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "low",
                "source_ip": "192.168.1.5", "destination_ip": "10.0.0.10", "request_path": "/docs/index.html",
                "http_method": "GET", "status_code": 200,
                "message": "Authorized internal administrator session",
            },
            {
                "timestamp": (t0 + timedelta(seconds=451, milliseconds=200)).isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "critical",
                "source_ip": "203.0.113.99", "destination_ip": "10.0.0.10", "request_path": "/login?id=1' or 1=1--",
                "http_method": "POST", "status_code": 500,
                "message": "SQL injection attempt detected",
            }
        ]
    ))

    # DEV-27: Simultaneous Benign Developers on Separate Workstations
    scenarios.append(create_scenario(
        "CROSS-DEV-027", "G", "Unrelated Simultaneous Events",
        "Multiple Developers Running Python at Same Second",
        "Two developers on different workstations start python.exe concurrently.",
        "BENIGN", True, 0, False, [],
        "Different hosts (DEV-01 vs DEV-02) and different users; isolated benign activities",
        [
            {
                "timestamp": (t0 + timedelta(seconds=470)).isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_process_create", "severity": "low",
                "hostname": "CORP-DEV-01", "username": "corp\\alice", "process": "python.exe",
                "process_id": 8100, "command_line": "python.exe test_suite.py",
                "message": "Alice running automated test script",
            },
            {
                "timestamp": (t0 + timedelta(seconds=470, milliseconds=500)).isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_process_create", "severity": "low",
                "hostname": "CORP-DEV-02", "username": "corp\\bob", "process": "python.exe",
                "process_id": 9200, "command_line": "python.exe script.py",
                "message": "Bob running local python script",
            }
        ]
    ))

    # DEV-28: Independent Scanners Probing Different Ports
    scenarios.append(create_scenario(
        "CROSS-DEV-028", "G", "Unrelated Simultaneous Events",
        "Two Independent External Scanners",
        "Zeek detects probe from IP-A on port 4444 and separate probe from IP-B on port 1337 concurrently.",
        "ATTACK", True, 2, False, [],
        "Different source IPs (198.51.100.1 vs 203.0.113.2); separate independent incidents",
        [
            {
                "timestamp": (t0 + timedelta(seconds=490)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                "source_ip": "198.51.100.1", "destination_ip": "10.0.0.10", "destination_port": 4444,
                "message": "Suspicious destination port connection to 4444",
            },
            {
                "timestamp": (t0 + timedelta(seconds=491)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                "source_ip": "203.0.113.2", "destination_ip": "10.0.0.10", "destination_port": 1337,
                "message": "Suspicious destination port connection to 1337",
            }
        ]
    ))

    # Category H: Timing variations (3 scenarios)
    # DEV-29: Timing Within Window (dt = 25s, window = 300s -> Correlated)
    scenarios.append(create_scenario(
        "CROSS-DEV-029", "H", "Timing Boundary Evaluation",
        "Multi-Source Events Within 25 Seconds [Correlated]",
        "Attacker attacks web service and connects via Zeek within 25s (well within default 300s window).",
        "ATTACK", True, 1, True, ["CORR-001"],
        None,
        [
            {
                "timestamp": (t0 + timedelta(seconds=510)).isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "critical",
                "source_ip": "198.51.100.180", "destination_ip": "10.0.0.10",
                "request_path": "/vuln?test=1' or '1'='1", "message": "SQL injection attempt detected",
            },
            {
                "timestamp": (t0 + timedelta(seconds=535)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                "source_ip": "198.51.100.180", "destination_ip": "10.0.0.10", "destination_port": 4444,
                "message": "Zeek connection matching source IP within 25 seconds",
            }
        ]
    ))

    # DEV-30: Timing at 180s (within 300s window)
    scenarios.append(create_scenario(
        "CROSS-DEV-030", "H", "Timing Boundary Evaluation",
        "Multi-Source Events at 180 Seconds Window Boundary",
        "Events spaced by 180 seconds to test behavior across 120s vs 300s window configurations.",
        "ATTACK", True, 1, True, ["CORR-001"],
        "Valid at default window (300s); should separate if window set to 120s",
        [
            {
                "timestamp": (t0 + timedelta(seconds=560)).isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "high",
                "source_ip": "198.51.100.190", "destination_ip": "10.0.0.10",
                "request_path": "/static/../../etc/passwd", "message": "Path traversal attempt detected",
            },
            {
                "timestamp": (t0 + timedelta(seconds=740)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                "source_ip": "198.51.100.190", "destination_ip": "10.0.0.10", "destination_port": 4444,
                "message": "Follow-up connection after 180 seconds delay",
            }
        ]
    ))

    # DEV-31: Timing Completely Outside Default Window (dt = 850s > 600s -> Must NOT Correlate)
    scenarios.append(create_scenario(
        "CROSS-DEV-031", "H", "Timing Boundary Evaluation",
        "Multi-Source Events Separated by 850 Seconds [Uncorrelated]",
        "Same IP attacks web at t=0, and separate probe seen 14 minutes later; outside correlation window.",
        "ATTACK", True, 2, False, [],
        "Temporal delta (850s) exceeds default 300s and max 600s window; must treat as separate incidents",
        [
            {
                "timestamp": (t0 + timedelta(seconds=800)).isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "critical",
                "source_ip": "198.51.100.199", "destination_ip": "10.0.0.10",
                "request_path": "/admin/config?id=' or '1'='1", "message": "SQL injection attempt detected",
            },
            {
                "timestamp": (t0 + timedelta(seconds=1650)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                "source_ip": "198.51.100.199", "destination_ip": "10.0.0.10", "destination_port": 4444,
                "message": "Unrelated connection 850s later",
            }
        ]
    ))

    # Category I: Shared IP but unrelated activity (3 scenarios)
    # DEV-32: NAT Gateway IP with Unrelated Users
    scenarios.append(create_scenario(
        "CROSS-DEV-032", "I", "Shared IP Non-Correlation",
        "Shared NAT Gateway IP with Unrelated Internal Users",
        "External NAT IP 198.51.100.50 used by employee reading news, and separate malware probe.",
        "ATTACK", True, 1, False, [],
        "Shared public IP does NOT imply same user or attack chain; completely unrelated destination/user",
        [
            {
                "timestamp": (t0 + timedelta(seconds=1700)).isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "low",
                "source_ip": "198.51.100.50", "destination_ip": "10.0.0.10", "request_path": "/company/news.html",
                "username": "corp\\employee1", "message": "Legitimate employee browsing internal portal",
            },
            {
                "timestamp": (t0 + timedelta(seconds=1710)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                "source_ip": "198.51.100.50", "destination_ip": "10.0.0.99", "destination_port": 4444,
                "message": "Suspicious destination port connection to 4444",
            }
        ]
    ))

    # DEV-33: Public CDN / Proxy IP Serving Different Clients
    scenarios.append(create_scenario(
        "CROSS-DEV-033", "I", "Shared IP Non-Correlation",
        "Shared Cloudflare/CDN Proxy IP",
        "Two unrelated external clients connecting through Cloudflare shared egress IP.",
        "BENIGN", True, 0, False, [],
        "Shared CDN reverse-proxy IP; must NOT falsely correlate different clients",
        [
            {
                "timestamp": (t0 + timedelta(seconds=1740)).isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "low",
                "source_ip": "104.16.12.34", "destination_ip": "10.0.0.10", "request_path": "/customer-portal/login",
                "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
                "message": "Mobile client login request",
            },
            {
                "timestamp": (t0 + timedelta(seconds=1745)).isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "low",
                "source_ip": "104.16.12.34", "destination_ip": "10.0.0.10", "request_path": "/api/v1/status",
                "user_agent": "Go-http-client/1.1",
                "message": "Automated API client status query",
            }
        ]
    ))

    # DEV-34: Dynamic DHCP IP Reassigned
    scenarios.append(create_scenario(
        "CROSS-DEV-034", "I", "Shared IP Non-Correlation",
        "Reassigned Dynamic DHCP IP",
        "IP 10.0.0.111 assigned to host A for morning backup, then host B at afternoon.",
        "BENIGN", True, 0, False, [],
        "Different hostnames (CORP-PC-01 vs CORP-PC-02) sharing transient DHCP IP",
        [
            {
                "timestamp": (t0 + timedelta(seconds=1780)).isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_process_create", "severity": "low",
                "source_ip": "10.0.0.111", "hostname": "CORP-PC-01", "username": "corp\\user_a",
                "process": "outlook.exe", "message": "Email client launch on host A",
            },
            {
                "timestamp": (t0 + timedelta(seconds=2400)).isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_process_create", "severity": "low",
                "source_ip": "10.0.0.111", "hostname": "CORP-PC-02", "username": "corp\\user_b",
                "process": "slack.exe", "message": "Chat client launch on host B hours later",
            }
        ]
    ))

    # Category J: Shared hostname but unrelated activity (2 scenarios)
    # DEV-35: Shared Multi-Session Terminal Server
    scenarios.append(create_scenario(
        "CROSS-DEV-035", "J", "Shared Host Non-Correlation",
        "Multi-User Terminal Server Activity",
        "On RDS-SRV-01, User A edits spreadsheet while User B launches PowerShell.",
        "BENIGN", True, 0, False, [],
        "Same hostname, but different unlinked user sessions without malicious chain",
        [
            {
                "timestamp": (t0 + timedelta(seconds=2500)).isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_process_create", "severity": "low",
                "hostname": "RDS-SRV-01", "username": "corp\\finance1", "process": "excel.exe",
                "process_id": 12040, "message": "Finance user opening spreadsheet",
            },
            {
                "timestamp": (t0 + timedelta(seconds=2510)).isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_process_create", "severity": "low",
                "hostname": "RDS-SRV-01", "username": "corp\\helpdesk", "process": "powershell.exe",
                "process_id": 13080, "command_line": "powershell.exe Get-Service",
                "message": "Helpdesk user running diagnostic query",
            }
        ]
    ))

    # DEV-36: Scheduled Backup Cron vs Web Server Activity
    scenarios.append(create_scenario(
        "CROSS-DEV-036", "J", "Shared Host Non-Correlation",
        "Shared Host Background Backup Job",
        "Host CORP-APP-01 runs nightly backup script while web server receives normal request.",
        "BENIGN", True, 0, False, [],
        "Background system maintenance does not correlate with separate web request",
        [
            {
                "timestamp": (t0 + timedelta(seconds=2600)).isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_process_create", "severity": "low",
                "hostname": "CORP-APP-01", "username": "NT AUTHORITY\\SYSTEM", "process": "tar.exe",
                "process_id": 3310, "command_line": "tar.exe -czf C:\\backups\\logs.tar.gz C:\\logs",
                "message": "System scheduled backup archive creation",
            },
            {
                "timestamp": (t0 + timedelta(seconds=2605)).isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "low",
                "hostname": "CORP-APP-01", "source_ip": "192.168.1.80", "request_path": "/api/ping",
                "message": "Routine health check",
            }
        ]
    ))

    return scenarios


def make_val_scenarios() -> list[dict]:
    t0 = datetime(2026, 10, 8, 14, 0, 0, tzinfo=UTC)
    scenarios = []

    val_specs = [
        ("CROSS-VAL-001", "A", "Web-Only Activity", "Web XSS Injection", "Single-source cross-site scripting attempt", "ATTACK", False, 1, False, [], "Single-source web"),
        ("CROSS-VAL-002", "A", "Web-Only Activity", "Benign API Call", "Standard REST API GET request", "BENIGN", False, 0, False, [], "Benign query"),
        ("CROSS-VAL-003", "B", "Network-Only Activity", "Zeek Port 4444 Probe", "External probe targeting backdoor port 4444", "ATTACK", False, 1, False, [], "Single-source network"),
        ("CROSS-VAL-004", "B", "Network-Only Activity", "Normal DNS Resolution", "Standard query for google.com", "BENIGN", False, 0, False, [], "Benign DNS lookup"),
        ("CROSS-VAL-005", "C", "Endpoint-Only Activity", "Sysmon Encoded PowerShell", "PowerShell with -enc parameter", "ATTACK", False, 1, False, [], "Single-source endpoint"),
        ("CROSS-VAL-006", "C", "Endpoint-Only Activity", "Benign Notepad Launch", "Standard notepad.exe text editor execution", "BENIGN", False, 0, False, [], "Benign user activity"),
        ("CROSS-VAL-007", "D", "Multi-Source Attack", "Web SQLi & Zeek Flow [CORR-001]", "Web probe followed by matching Zeek session", "ATTACK", True, 1, True, ["CORR-001"], None),
        ("CROSS-VAL-008", "D", "Multi-Source Attack", "Web Exploit & Sysmon Shell [CORR-002]", "Web exploit spawns host cmd.exe", "ATTACK", True, 1, True, ["CORR-002"], None),
        ("CROSS-VAL-009", "D", "Multi-Source Attack", "Sysmon Net & Zeek Flow [CORR-003]", "Endpoint process outbound socket matched by Zeek flow", "ATTACK", True, 1, True, ["CORR-003"], None),
        ("CROSS-VAL-010", "D", "Multi-Source Attack", "Sysmon DNS & Zeek DNS [CORR-004]", "Endpoint DNS resolution matched on Zeek monitor", "ATTACK", True, 1, True, ["CORR-004"], None),
        ("CROSS-VAL-011", "E", "Multi-Source Benign Activity", "Admin SSH & Backup Execution", "Admin connects via SSH and runs tar", "BENIGN", True, 0, False, [], "Legitimate maintenance"),
        ("CROSS-VAL-012", "E", "Multi-Source Benign Activity", "Jenkins Build Execution", "Build agent pulls package and compiles", "BENIGN", True, 0, False, [], "CI build pipeline"),
        ("CROSS-VAL-013", "F", "Missing Telemetry Layer", "Web Exploit Missing Zeek Log", "Web server exploit with dropped network telemetry", "ATTACK", False, 1, False, [], "Single-source web visible"),
        ("CROSS-VAL-014", "G", "Unrelated Simultaneous Events", "Concurrent Scans from 2 Distinct IPs", "IP-1 and IP-2 probe server at dt=1s", "ATTACK", True, 2, False, [], "Different IPs; separate incidents"),
        ("CROSS-VAL-015", "H", "Timing Boundary Evaluation", "Timing Delta at 800s (Outside Window)", "Events spaced by 800s with window=300s", "ATTACK", True, 2, False, [], "Exceeds 300s window; not correlated"),
        ("CROSS-VAL-016", "I", "Shared IP Non-Correlation", "Public Proxy IP Unrelated Sessions", "Public proxy IP used by 2 unrelated clients", "BENIGN", True, 0, False, [], "Shared proxy IP does not correlate"),
    ]

    for idx, (s_id, cat, cat_name, title, desc, gt, is_ms, inc_count, exp_corr, corr_rules, non_corr_r) in enumerate(val_specs):
        t_cur = t0 + timedelta(minutes=idx * 5)
        evs = []
        if cat == "A":
            evs.append({
                "timestamp": t_cur.isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "high" if gt == "ATTACK" else "low",
                "source_ip": "198.51.100.21" if gt == "ATTACK" else "192.168.1.40",
                "request_path": "/item?search=<script>alert(1)</script>" if gt == "ATTACK" else "/item?search=laptop",
                "message": desc,
            })
        elif cat == "B":
            evs.append({
                "timestamp": t_cur.isoformat(),
                "source_type": "ZEEK", "event_type": "connection",
                "severity": "high" if gt == "ATTACK" else "low",
                "source_ip": "203.0.113.77" if gt == "ATTACK" else "10.0.0.15",
                "destination_ip": "10.0.0.1", "destination_port": 4444 if gt == "ATTACK" else 80,
                "message": desc,
            })
        elif cat == "C":
            evs.append({
                "timestamp": t_cur.isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_process_create",
                "severity": "high" if gt == "ATTACK" else "low",
                "hostname": "CORP-WKSTN-VAL", "username": "corp\\user",
                "process": "powershell.exe" if gt == "ATTACK" else "notepad.exe",
                "command_line": "powershell.exe -enc SQBFAFgA..." if gt == "ATTACK" else "notepad.exe notes.txt",
                "message": desc,
            })
        elif cat == "D":
            # Multi-source attack pair
            if "CORR-001" in corr_rules:
                evs.append({
                    "timestamp": t_cur.isoformat(),
                    "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "critical",
                    "source_ip": "198.51.100.80", "destination_ip": "10.0.0.10",
                    "request_path": "/vuln.php?id=' or '1'='1", "message": "SQL injection attempt detected",
                })
                evs.append({
                    "timestamp": (t_cur + timedelta(seconds=12)).isoformat(),
                    "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                    "source_ip": "198.51.100.80", "destination_ip": "10.0.0.10", "destination_port": 4444,
                    "message": "Suspicious destination port connection to 4444",
                })
            elif "CORR-002" in corr_rules:
                evs.append({
                    "timestamp": t_cur.isoformat(),
                    "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "high",
                    "source_ip": "198.51.100.82", "destination_ip": "10.0.0.10", "hostname": "CORP-VAL-01",
                    "request_path": "/vuln/../../etc/passwd", "message": "Path traversal attempt detected",
                })
                evs.append({
                    "timestamp": (t_cur + timedelta(seconds=12)).isoformat(),
                    "source_type": "SYSMON", "event_type": "sysmon_process_create", "severity": "critical",
                    "hostname": "CORP-VAL-01", "username": "IIS APPPOOL\\default",
                    "process": "cmd.exe", "parent_process": "w3wp.exe", "command_line": "cmd.exe /c whoami",
                    "message": "Suspicious parent-child relationship: w3wp.exe spawned cmd.exe",
                })
            elif "CORR-003" in corr_rules:
                evs.append({
                    "timestamp": t_cur.isoformat(),
                    "source_type": "SYSMON", "event_type": "sysmon_network_connection", "severity": "high",
                    "hostname": "CORP-VAL-02", "process": "rundll32.exe",
                    "destination_ip": "203.0.113.88", "destination_port": 4444,
                    "message": "Suspicious process network connection: rundll32.exe to port 4444",
                })
                evs.append({
                    "timestamp": (t_cur + timedelta(seconds=12)).isoformat(),
                    "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                    "source_ip": "10.0.0.25", "destination_ip": "203.0.113.88", "destination_port": 4444,
                    "message": "Suspicious destination port connection to 4444",
                })
            else:
                evs.append({
                    "timestamp": t_cur.isoformat(),
                    "source_type": "SYSMON", "event_type": "sysmon_dns_query", "severity": "medium",
                    "hostname": "CORP-VAL-03", "process": "powershell.exe", "dns_query": "beacon.darkcorridor.org",
                    "message": "Suspicious DNS activity: queried beacon domain",
                })
                evs.append({
                    "timestamp": (t_cur + timedelta(seconds=12)).isoformat(),
                    "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                    "source_ip": "10.0.0.88", "destination_ip": "203.0.113.99", "destination_port": 4444,
                    "dns_query": "beacon.darkcorridor.org", "message": "Suspicious destination port connection to 4444",
                })
        elif cat in ("E", "I"):
            evs.append({
                "timestamp": t_cur.isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "low",
                "source_ip": "192.0.2.10", "request_path": "/api/ping", "message": "Benign client 1",
            })
            evs.append({
                "timestamp": (t_cur + timedelta(seconds=8)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "low",
                "source_ip": "192.0.2.10", "destination_ip": "10.0.0.10", "destination_port": 80, "message": "Benign client 2",
            })
        elif cat == "G":
            evs.append({
                "timestamp": t_cur.isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                "source_ip": "198.51.100.91", "destination_ip": "10.0.0.10", "destination_port": 4444,
                "message": "Scan from IP-1",
            })
            evs.append({
                "timestamp": (t_cur + timedelta(seconds=1)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                "source_ip": "203.0.113.92", "destination_ip": "10.0.0.10", "destination_port": 1337,
                "message": "Scan from IP-2",
            })
        elif cat == "H":
            evs.append({
                "timestamp": t_cur.isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "critical",
                "source_ip": "198.51.100.70", "destination_ip": "10.0.0.10",
                "request_path": "/vuln?q=' or '1'='1", "message": "First attack",
            })
            evs.append({
                "timestamp": (t_cur + timedelta(seconds=800)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                "source_ip": "198.51.100.70", "destination_ip": "10.0.0.10", "destination_port": 4444,
                "message": "Second attack 800s later",
            })
        else:
            evs.append({
                "timestamp": t_cur.isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "critical",
                "source_ip": "198.51.100.99", "request_path": "/vuln?id=' or '1'='1", "message": desc,
            })

        scenarios.append(create_scenario(
            s_id, cat, cat_name, title, desc, gt, is_ms, inc_count, exp_corr, corr_rules, non_corr_r, evs
        ))

    return scenarios


def make_test_scenarios() -> list[dict]:
    t0 = datetime(2026, 10, 8, 18, 0, 0, tzinfo=UTC)
    scenarios = []

    test_specs = [
        ("CROSS-TEST-001", "A", "Web-Only Activity", "Web SQLi Probe", "SQL injection probe in web form", "ATTACK", False, 1, False, [], "Web-only"),
        ("CROSS-TEST-002", "A", "Web-Only Activity", "Benign CSS Request", "Browser loading stylesheet", "BENIGN", False, 0, False, [], "Benign static asset"),
        ("CROSS-TEST-003", "B", "Network-Only Activity", "Zeek Port 4444 Connection", "Zeek detects connection to backdoor port 4444", "ATTACK", False, 1, False, [], "Network-only"),
        ("CROSS-TEST-004", "B", "Network-Only Activity", "Routine NTP Sync", "Internal host synchronizing clock", "BENIGN", False, 0, False, [], "Benign NTP"),
        ("CROSS-TEST-005", "C", "Endpoint-Only Activity", "Sysmon Encoded PowerShell", "Obfuscated powershell -enc execution", "ATTACK", False, 1, False, [], "Endpoint-only"),
        ("CROSS-TEST-006", "C", "Endpoint-Only Activity", "Benign Explorer Launch", "User opening Windows explorer", "BENIGN", False, 0, False, [], "Benign host activity"),
        ("CROSS-TEST-007", "D", "Multi-Source Attack", "Web SQLi -> Zeek Connection [CORR-001]", "SQLi attack followed by Zeek TCP session on 4444", "ATTACK", True, 1, True, ["CORR-001"], None),
        ("CROSS-TEST-008", "D", "Multi-Source Attack", "Web Upload -> Sysmon Process [CORR-002]", "Web backdoor upload spawning cmd.exe", "ATTACK", True, 1, True, ["CORR-002"], None),
        ("CROSS-TEST-009", "D", "Multi-Source Attack", "Endpoint Outbound -> Zeek Flow [CORR-003]", "Sysmon rundll32 network socket matched by Zeek flow", "ATTACK", True, 1, True, ["CORR-003"], None),
        ("CROSS-TEST-010", "D", "Multi-Source Attack", "Endpoint DNS -> Zeek DNS [CORR-004]", "Sysmon malware DNS lookup verified by Zeek sensor", "ATTACK", True, 1, True, ["CORR-004"], None),
        ("CROSS-TEST-011", "D", "Multi-Source Attack", "Tri-Source Web + Zeek + Sysmon Chain", "End-to-end multi-stage intrusion", "ATTACK", True, 1, True, ["CORR-001", "CORR-002"], None),
        ("CROSS-TEST-012", "E", "Multi-Source Benign Activity", "Developer Node Build & Web Test", "Developer local dev server & curl test", "BENIGN", True, 0, False, [], "Benign workflow"),
        ("CROSS-TEST-013", "E", "Multi-Source Benign Activity", "Automated Ansible Deployment", "Config management tool updating packages", "BENIGN", True, 0, False, [], "Approved IT config"),
        ("CROSS-TEST-014", "F", "Missing Telemetry Layer", "Web Exploit Without Net Traffic", "Web SQL injection with dropped network log", "ATTACK", False, 1, False, [], "Web-only visible"),
        ("CROSS-TEST-015", "G", "Unrelated Simultaneous Events", "Admin Curl & External Scanner at dt=0.5s", "Simultaneous unrelated events with different IPs", "ATTACK", True, 1, False, [], "Distinct IPs; must not merge"),
        ("CROSS-TEST-016", "H", "Timing Boundary Evaluation", "Attacks Separated by 800s (Exceeds Max)", "Same IP attacks spaced by 800s", "ATTACK", True, 2, False, [], "Exceeds 600s window limit"),
        ("CROSS-TEST-017", "I", "Shared IP Non-Correlation", "Public NAT Gateway Mixed Traffic", "NAT IP used by benign user and separate attacker", "ATTACK", True, 1, False, [], "NAT IP sharing; unrelated destination"),
        ("CROSS-TEST-018", "J", "Shared Host Non-Correlation", "Shared Host Scheduled Antivirus Scan", "Endpoint running scan during normal web visit", "BENIGN", True, 0, False, [], "Separate processes without attack"),
    ]

    for idx, (s_id, cat, cat_name, title, desc, gt, is_ms, inc_count, exp_corr, corr_rules, non_corr_r) in enumerate(test_specs):
        t_cur = t0 + timedelta(minutes=idx * 6)
        evs = []
        if cat == "A":
            evs.append({
                "timestamp": t_cur.isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "critical" if gt == "ATTACK" else "low",
                "source_ip": "198.51.100.60" if gt == "ATTACK" else "192.168.1.60",
                "request_path": "/run?q=' or '1'='1" if gt == "ATTACK" else "/style.css",
                "message": desc,
            })
        elif cat == "B":
            evs.append({
                "timestamp": t_cur.isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "high" if gt == "ATTACK" else "low",
                "source_ip": "203.0.113.44" if gt == "ATTACK" else "10.0.0.30",
                "destination_ip": "10.0.0.1", "destination_port": 4444 if gt == "ATTACK" else 123,
                "message": desc,
            })
        elif cat == "C":
            evs.append({
                "timestamp": t_cur.isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_process_create",
                "severity": "high" if gt == "ATTACK" else "low",
                "hostname": "CORP-TEST-HOST", "username": "corp\\testuser",
                "process": "powershell.exe" if gt == "ATTACK" else "explorer.exe",
                "command_line": "powershell.exe -enc SQBFAFgA..." if gt == "ATTACK" else "explorer.exe C:\\Users",
                "message": desc,
            })
        elif cat == "D":
            evs.append({
                "timestamp": t_cur.isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "critical",
                "source_ip": "198.51.100.95", "hostname": "CORP-TEST-01", "destination_ip": "10.0.0.10",
                "request_path": "/shell.php?id=' or '1'='1", "message": "Initial exploit probe",
            })
            evs.append({
                "timestamp": (t_cur + timedelta(seconds=14)).isoformat(),
                "source_type": "ZEEK" if "CORR-001" in corr_rules else "SYSMON",
                "event_type": "connection" if "CORR-001" in corr_rules else "sysmon_process_create",
                "severity": "high", "source_ip": "198.51.100.95", "hostname": "CORP-TEST-01",
                "destination_ip": "10.0.0.10", "destination_port": 4444, "process": "cmd.exe",
                "parent_process": "w3wp.exe", "command_line": "cmd.exe /c whoami",
                "message": "Correlated exploit follow-up",
            })
            if "CORR-002" in corr_rules and len(corr_rules) > 1:
                evs.append({
                    "timestamp": (t_cur + timedelta(seconds=22)).isoformat(),
                    "source_type": "SYSMON", "event_type": "sysmon_process_create", "severity": "critical",
                    "hostname": "CORP-TEST-01", "username": "IIS APPPOOL\\default", "process": "cmd.exe",
                    "parent_process": "w3wp.exe", "command_line": "cmd.exe /c whoami", "message": "Payload execution",
                })
        elif cat in ("E", "I", "J"):
            evs.append({
                "timestamp": t_cur.isoformat(),
                "source_type": "SYSMON", "event_type": "sysmon_process_create", "severity": "low",
                "hostname": "CORP-NODE-01", "username": "corp\\dev", "process": "node.exe",
                "source_ip": "192.0.2.88", "message": "Benign activity 1",
            })
            evs.append({
                "timestamp": (t_cur + timedelta(seconds=9)).isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "low",
                "source_ip": "192.0.2.88", "request_path": "/api/test", "message": "Benign activity 2",
            })
        elif cat in ("G", "H"):
            evs.append({
                "timestamp": t_cur.isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "critical",
                "source_ip": "198.51.100.41", "request_path": "/admin?id=' or '1'='1", "message": "Initial scan",
            })
            evs.append({
                "timestamp": (t_cur + timedelta(seconds=800 if cat == "H" else 1)).isoformat(),
                "source_type": "ZEEK", "event_type": "connection", "severity": "high",
                "source_ip": "198.51.100.41" if cat == "H" else "203.0.113.42", "destination_port": 4444,
                "message": "Secondary scan",
            })
        else:
            evs.append({
                "timestamp": t_cur.isoformat(),
                "source_type": "WEB", "event_type": "WEB_REQUEST", "severity": "critical",
                "source_ip": "198.51.100.55", "request_path": "/test?id=' or '1'='1", "message": desc,
            })

        scenarios.append(create_scenario(
            s_id, cat, cat_name, title, desc, gt, is_ms, inc_count, exp_corr, corr_rules, non_corr_r, evs
        ))

    return scenarios


def write_split(path: Path, data: list[dict]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(data, indent=2, sort_keys=True)
    path.write_text(serialized, encoding="utf-8")
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def main():
    BASE_DIR.mkdir(parents=True, exist_ok=True)

    dev_data = make_dev_scenarios()
    val_data = make_val_scenarios()
    test_data = make_test_scenarios()

    dev_hash = write_split(BASE_DIR / "dev_scenarios.json", dev_data)
    val_hash = write_split(BASE_DIR / "validation_scenarios.json", val_data)
    test_hash = write_split(BASE_DIR / "held_out_test_scenarios.json", test_data)

    manifest = {
        "dataset_name": "Cross-Source Correlation Benchmark Dataset V1",
        "version": "1.0.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "total_scenarios": len(dev_data) + len(val_data) + len(test_data),
        "splits": {
            "dev": {
                "file": "dev_scenarios.json",
                "scenarios_count": len(dev_data),
                "sha256": dev_hash,
            },
            "validation": {
                "file": "validation_scenarios.json",
                "scenarios_count": len(val_data),
                "sha256": val_hash,
            },
            "held_out_test": {
                "file": "held_out_test_scenarios.json",
                "scenarios_count": len(test_data),
                "sha256": test_hash,
                "status": "HELD_OUT_FROZEN",
            },
        },
        "categories_covered": [
            "A: Web-only activity",
            "B: Network-only activity",
            "C: Endpoint-only activity",
            "D: Multi-source attacks",
            "E: Multi-source benign activity",
            "F: Events with missing telemetry",
            "G: Similar-looking but unrelated events",
            "H: Timing variations",
            "I: Shared IP but unrelated activity (NAT / proxy non-correlation)",
            "J: Shared hostname but unrelated activity (multi-user / cron non-correlation)",
        ],
    }

    manifest_path = BASE_DIR / "manifest.json"
    manifest_serialized = json.dumps(manifest, indent=2, sort_keys=True)
    manifest_path.write_text(manifest_serialized, encoding="utf-8")
    manifest_hash = hashlib.sha256(manifest_serialized.encode("utf-8")).hexdigest()

    print(f"Generated {len(dev_data)} DEV, {len(val_data)} VAL, {len(test_data)} TEST scenarios.")
    print(f"Total: {manifest['total_scenarios']} scenarios.")
    print(f"Manifest SHA-256: {manifest_hash}")


if __name__ == "__main__":
    main()
