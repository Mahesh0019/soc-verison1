"""
backend/app/rules/network_rules.py

Phase 4 Detection-as-Code: Zeek Network Telemetry Detection Rules.
Defines measurable network detections:
- NETWORK-001: Suspicious destination port connection
- NETWORK-002: Repeated rejected connections
- NETWORK-003: Abnormal network connection burst
- NETWORK-004: Suspicious HTTP activity from Zeek
- NETWORK-005: DNS resolution anomaly
- NETWORK-006: Potential reconnaissance pattern

Adheres strictly to the Detection-as-Code metadata specification:
rule_id, name, description, category, severity, source, version, status,
confidence, mitre_technique, false_positive_notes, expected_data_source,
test_cases_json (positive & negative).
"""

from typing import Any


def network_rules() -> list[dict[str, Any]]:
    return [
        {
            "rule_id": "NETWORK-001",
            "name": "Suspicious destination port connection",
            "description": "Detects network connections directed at known backdoor, trojan, or non-standard command-and-control destination ports (e.g., 1337, 31337, 4444, 6667).",
            "category": "network",
            "severity": "high",
            "version": "1.0",
            "status": "ACTIVE",
            "source": "zeek",
            "owner": "secops-team",
            "mitre_technique": "T1571",
            "confidence": 0.85,
            "false_positive_notes": "Legitimate local development servers, sandbox ports, or custom internal microservices bound to non-standard ports.",
            "expected_data_source": "network_telemetry",
            "enabled": True,
            "conditions_json": {
                "type": "threshold",
                "filters": {
                    "source_type": "ZEEK",
                    "destination_port": [1337, 31337, 4444, 6667],
                },
                "group_by": ["source_ip", "destination_port"],
            },
            "time_window_minutes": 10,
            "threshold": 1,
            "test_cases_json": {
                "positive": "Zeek connection event targeting destination_port 31337 from 192.168.1.54",
                "negative": "Zeek connection event targeting standard web ports (destination_port 80 or 443)",
            },
        },
        {
            "rule_id": "NETWORK-002",
            "name": "Repeated rejected connections",
            "description": "Detects multiple rejected network connections (REJ or RSTO) from a single host within a sliding window, indicating active port scanning or service disruption.",
            "category": "network",
            "severity": "medium",
            "version": "1.0",
            "status": "ACTIVE",
            "source": "zeek",
            "owner": "secops-team",
            "mitre_technique": "T1046",
            "confidence": 0.80,
            "false_positive_notes": "Internal hosts with misconfigured destination socket endpoints repeatedly retrying a stopped service.",
            "expected_data_source": "network_telemetry",
            "enabled": True,
            "conditions_json": {
                "type": "threshold",
                "filters": {
                    "source_type": "ZEEK",
                    "connection_state": ["REJ", "RSTO", "RSTR"],
                },
                "group_by": ["source_ip"],
            },
            "time_window_minutes": 10,
            "threshold": 5,
            "test_cases_json": {
                "positive": "5 rejected connections (REJ) from single source_ip within 10 minutes",
                "negative": "1 rejected connection (REJ) within 10 minutes (below threshold of 5)",
            },
        },
        {
            "rule_id": "NETWORK-003",
            "name": "Abnormal network connection burst",
            "description": "Detects an anomalous surge of network connections initiated by a single host within a short sliding window.",
            "category": "traffic_anomaly",
            "severity": "medium",
            "version": "1.0",
            "status": "ACTIVE",
            "source": "zeek",
            "owner": "secops-team",
            "mitre_technique": "T1499.001",
            "confidence": 0.70,
            "false_positive_notes": "High-throughput API client, parallel asset downloads, or package manager mirror updates.",
            "expected_data_source": "network_telemetry",
            "enabled": True,
            "conditions_json": {
                "type": "threshold",
                "filters": {
                    "source_type": "ZEEK",
                    "event_category": "network",
                },
                "group_by": ["source_ip"],
            },
            "time_window_minutes": 5,
            "threshold": 15,
            "test_cases_json": {
                "positive": "15 network connection events from single source_ip in 5 minutes",
                "negative": "5 network connection events from single source_ip in 5 minutes",
            },
        },
        {
            "rule_id": "NETWORK-004",
            "name": "Suspicious HTTP activity from Zeek",
            "description": "Detects repeated requests to sensitive configuration, backup, or administrative paths observed in Zeek HTTP network telemetry.",
            "category": "reconnaissance",
            "severity": "high",
            "version": "1.0",
            "status": "ACTIVE",
            "source": "zeek",
            "owner": "secops-team",
            "mitre_technique": "T1595.002",
            "confidence": 0.80,
            "false_positive_notes": "Authorized administrator inspecting configuration portals or routine security audit scans.",
            "expected_data_source": "network_telemetry",
            "enabled": True,
            "conditions_json": {
                "type": "threshold",
                "filters": {
                    "source_type": "ZEEK",
                    "event_type": "sensitive_path_access",
                },
                "group_by": ["source_ip"],
            },
            "time_window_minutes": 10,
            "threshold": 3,
            "test_cases_json": {
                "positive": "3 Zeek HTTP events querying sensitive paths (e.g., /.env, /admin) from single source_ip",
                "negative": "1 Zeek HTTP event querying sensitive path",
            },
        },
        {
            "rule_id": "NETWORK-005",
            "name": "DNS resolution anomaly",
            "description": "Detects repeated non-existent domain (NXDOMAIN) responses in Zeek DNS logs from a single client host, indicating domain generation algorithms or reconnaissance sweeps.",
            "category": "network",
            "severity": "medium",
            "version": "1.0",
            "status": "ACTIVE",
            "source": "zeek",
            "owner": "secops-team",
            "mitre_technique": "T1568",
            "confidence": 0.75,
            "false_positive_notes": "Misconfigured DNS search domains, expired subdomains, or human typos in domain entry.",
            "expected_data_source": "network_telemetry",
            "enabled": True,
            "conditions_json": {
                "type": "threshold",
                "filters": {
                    "source_type": "ZEEK",
                    "event_type": "zeek_dns_nxdomain",
                },
                "group_by": ["source_ip"],
            },
            "time_window_minutes": 10,
            "threshold": 3,
            "test_cases_json": {
                "positive": "3 NXDOMAIN DNS responses from single source_ip within 10 minutes",
                "negative": "1 NXDOMAIN DNS response (sporadic lookup failure)",
            },
        },
        {
            "rule_id": "NETWORK-006",
            "name": "Potential reconnaissance pattern",
            "description": "Detects scanning patterns combining rejected connection attempts and probes to non-standard ports from an external host.",
            "category": "reconnaissance",
            "severity": "high",
            "version": "1.0",
            "status": "ACTIVE",
            "source": "zeek",
            "owner": "secops-team",
            "mitre_technique": "T1595",
            "confidence": 0.82,
            "false_positive_notes": "Authorized external vulnerability scans or periodic network monitoring sweeps.",
            "expected_data_source": "network_telemetry",
            "enabled": True,
            "conditions_json": {
                "type": "threshold",
                "filters": {
                    "source_type": "ZEEK",
                    "event_type": ["zeek_conn_rejected", "zeek_suspicious_port"],
                },
                "group_by": ["source_ip"],
            },
            "time_window_minutes": 10,
            "threshold": 4,
            "test_cases_json": {
                "positive": "4 combined rejected or suspicious port events from single source_ip in 10 minutes",
                "negative": "1 rejected connection and 0 suspicious ports",
            },
        },
    ]
