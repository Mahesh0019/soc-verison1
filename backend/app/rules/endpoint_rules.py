"""
backend/app/rules/endpoint_rules.py

Phase 5 Detection-as-Code: Windows Sysmon Endpoint Telemetry Detection Rules.
Defines measurable endpoint detections:
- ENDPOINT-001: Suspicious process execution
- ENDPOINT-002: Suspicious parent-child process relationship
- ENDPOINT-003: Suspicious process network connection
- ENDPOINT-004: Suspicious DNS activity
- ENDPOINT-005: Suspicious executable/file creation

Adheres strictly to the Detection-as-Code metadata specification:
rule_id, name, description, category, severity, source, version, status,
confidence, mitre_technique, false_positive_notes, expected_data_source,
test_cases_json (positive & negative).
"""

from typing import Any


def endpoint_rules() -> list[dict[str, Any]]:
    return [
        {
            "rule_id": "ENDPOINT-001",
            "name": "Suspicious process execution",
            "description": "Detects process execution with high-risk command-line arguments indicative of stealth execution, payload obfuscation, or credential access (e.g. encoded PowerShell commands via -enc/-encodedcommand, hidden window execution with bypass flags, vssadmin shadow copy deletion, or whoami /priv reconnaissance).",
            "category": "endpoint",
            "severity": "high",
            "version": "1.0",
            "status": "ACTIVE",
            "source": "sysmon",
            "owner": "secops-team",
            "mitre_technique": "T1059.001",
            "confidence": 0.88,
            "false_positive_notes": "Legitimate enterprise orchestration tools (SCCM, Ansible, InTune) using base64 encoded scripts or maintenance automation.",
            "expected_data_source": "endpoint_telemetry",
            "enabled": True,
            "conditions_json": {
                "type": "pattern",
                "filters": {
                    "source_type": "SYSMON",
                    "event_type": "sysmon_process_create",
                    "command_line_contains_any": [
                        "-enc ",
                        "-encodedcommand ",
                        "-w hidden",
                        "-windowstyle hidden",
                        "vssadmin delete shadows",
                        "whoami /priv",
                        "downloadstring(",
                        "invoke-expression",
                    ],
                },
                "group_by": ["hostname", "process"],
            },
            "time_window_minutes": 10,
            "threshold": 1,
            "test_cases_json": {
                "positive": "powershell.exe -enc SQBFAFgA... or cmd.exe /c vssadmin delete shadows",
                "negative": "powershell.exe Get-Service or legitimate un-obfuscated admin commands",
            },
        },
        {
            "rule_id": "ENDPOINT-002",
            "name": "Suspicious parent-child process relationship",
            "description": "Detects interactive command shells (cmd.exe, powershell.exe, wscript.exe, cscript.exe) spawned by web server processes (w3wp.exe, nginx.exe, httpd.exe) or office productivity applications (winword.exe, excel.exe).",
            "category": "endpoint",
            "severity": "critical",
            "version": "1.0",
            "status": "ACTIVE",
            "source": "sysmon",
            "owner": "secops-team",
            "mitre_technique": "T1059.003",
            "confidence": 0.92,
            "false_positive_notes": "Web applications legitimately invoking server-side batch utilities or Office plugins running authorized local shell integrations.",
            "expected_data_source": "endpoint_telemetry",
            "enabled": True,
            "conditions_json": {
                "type": "threshold",
                "filters": {
                    "source_type": "SYSMON",
                    "event_type": "sysmon_process_create",
                    "process_in": ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"],
                    "parent_process_in": ["w3wp.exe", "nginx.exe", "httpd.exe", "apache.exe", "winword.exe", "excel.exe"],
                },
                "group_by": ["hostname", "parent_process"],
            },
            "time_window_minutes": 10,
            "threshold": 1,
            "test_cases_json": {
                "positive": "w3wp.exe spawning cmd.exe or winword.exe spawning powershell.exe",
                "negative": "explorer.exe spawning cmd.exe or system32 services spawning powershell.exe",
            },
        },
        {
            "rule_id": "ENDPOINT-003",
            "name": "Suspicious process network connection",
            "description": "Detects non-browser utility or script interpreter processes (certutil.exe, rundll32.exe, regsvr32.exe, powershell.exe, cmd.exe) initiating outbound network connections to suspicious or non-standard external ports (e.g., 4444, 1337, 31337, 6667, 8080, 8443).",
            "category": "endpoint",
            "severity": "high",
            "version": "1.0",
            "status": "ACTIVE",
            "source": "sysmon",
            "owner": "secops-team",
            "mitre_technique": "T1105",
            "confidence": 0.85,
            "false_positive_notes": "Legitimate certutil CRL verification over HTTP port 80, or developer PowerShell scripts interacting with external APIs on port 8080.",
            "expected_data_source": "endpoint_telemetry",
            "enabled": True,
            "conditions_json": {
                "type": "threshold",
                "filters": {
                    "source_type": "SYSMON",
                    "event_type": "sysmon_network_connection",
                    "process_in": ["certutil.exe", "rundll32.exe", "regsvr32.exe", "powershell.exe", "cmd.exe"],
                    "destination_port_in": [4444, 1337, 31337, 6667, 8080, 8443],
                },
                "group_by": ["hostname", "process"],
            },
            "time_window_minutes": 10,
            "threshold": 1,
            "test_cases_json": {
                "positive": "certutil.exe connecting to 198.51.100.55:8080 or powershell.exe connecting to port 4444",
                "negative": "msedge.exe or chrome.exe connecting to port 443",
            },
        },
        {
            "rule_id": "ENDPOINT-004",
            "name": "Suspicious DNS activity",
            "description": "Detects command-line utilities, script hosts, or suspicious processes querying dynamic DNS providers, high-risk TLDs, or known tunneling/C2 staging domains.",
            "category": "endpoint",
            "severity": "medium",
            "version": "1.0",
            "status": "ACTIVE",
            "source": "sysmon",
            "owner": "secops-team",
            "mitre_technique": "T1071.004",
            "confidence": 0.82,
            "false_positive_notes": "Legitimate development testing of dynamic DNS domains or IT infrastructure health checks against ddns providers.",
            "expected_data_source": "endpoint_telemetry",
            "enabled": True,
            "conditions_json": {
                "type": "threshold",
                "filters": {
                    "source_type": "SYSMON",
                    "event_type": "sysmon_dns_query",
                    "dns_query_contains_any": [
                        ".duckdns.org",
                        ".ngrok.io",
                        ".burpcollaborator.net",
                        ".tunnel.me",
                        "c2-stage.",
                        "beacon.",
                    ],
                },
                "group_by": ["hostname", "process"],
            },
            "time_window_minutes": 10,
            "threshold": 1,
            "test_cases_json": {
                "positive": "Sysmon Event 22 querying test.duckdns.org or evil.c2-stage.local",
                "negative": "Sysmon Event 22 querying microsoft.com, google.com, or internal.corp",
            },
        },
        {
            "rule_id": "ENDPOINT-005",
            "name": "Suspicious executable/file creation",
            "description": "Detects script interpreters, office productivity apps, or web servers creating executable files (.exe, .dll, .bat, .vbs, .ps1) in temporary, AppData, or Startup folders.",
            "category": "endpoint",
            "severity": "high",
            "version": "1.0",
            "status": "ACTIVE",
            "source": "sysmon",
            "owner": "secops-team",
            "mitre_technique": "T1105",
            "confidence": 0.86,
            "false_positive_notes": "Legitimate software installers unpacking executables to %TEMP%, or developer compilers (csc.exe, gcc) writing output binaries.",
            "expected_data_source": "endpoint_telemetry",
            "enabled": True,
            "conditions_json": {
                "type": "pattern",
                "filters": {
                    "source_type": "SYSMON",
                    "event_type": "sysmon_file_create",
                    "process_in": ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "w3wp.exe", "winword.exe", "excel.exe"],
                    "pattern_any": ["\\temp\\", "\\appdata\\local\\temp\\", "\\startup\\", "/tmp/"],
                },
                "group_by": ["hostname", "process"],
            },
            "time_window_minutes": 10,
            "threshold": 1,
            "test_cases_json": {
                "positive": "powershell.exe creating C:\\Users\\User\\AppData\\Local\\Temp\\payload.exe",
                "negative": "devenv.exe or trusted installer creating files in Program Files",
            },
        },
    ]
