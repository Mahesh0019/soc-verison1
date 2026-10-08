# Windows Sysmon Endpoint Telemetry & Detection Architecture (Phase 5)

## Executive Summary

Phase 5 extends the SOC architecture with host endpoint telemetry derived from **Windows System Monitor (Sysmon)**, establishing an independent endpoint detection pipeline while preserving existing Web, Authentication, Firewall, and Zeek network pipelines.

```
Windows / Sysmon (XML / JSONL)
              ↓
        Sysmon Parser
              ↓
       NormalizedEvent
              ↓
  Endpoint Detection Rules
      (ENDPOINT-001..005)
              ↓
            Alert
              ↓
           Evidence
              ↓
       Detection Quality
```

> **Research Boundary Notice (Phase 5)**:
> In accordance with research boundaries, this phase implements **zero cross-source correlation** and **no incident graph reconstruction**. Cross-telemetry correlation (Web + Zeek + Sysmon) is strictly reserved for Phase 6. Results reported herein reflect controlled development and validation benchmark evaluations (`Sysmon V1`), not generalized real-world enterprise endpoint defense.

---

## 1. Supported Sysmon Event Types

The Sysmon ingestion pipeline natively parses and normalizes six foundational Windows Sysmon event IDs:

| Sysmon Event ID | Event Description | Normalized `event_type` | Category | Key Normalized Telemetry Fields |
| :--- | :--- | :--- | :--- | :--- |
| **Event ID 1** | Process Create | `sysmon_process_create` | `endpoint` | `process`, `parent_process`, `process_id`, `parent_process_id`, `command_line`, `image_path`, `file_hash`, `hostname`, `username` |
| **Event ID 3** | Network Connection | `sysmon_network_connection` | `endpoint` | `process`, `process_id`, `source_ip`, `source_port`, `destination_ip`, `destination_port`, `protocol`, `hostname`, `username` |
| **Event ID 5** | Process Terminated | `sysmon_process_terminate` | `endpoint` | `process`, `process_id`, `image_path`, `hostname` |
| **Event ID 7** | Image Loaded | `sysmon_image_load` | `endpoint` | `process`, `process_id`, `image_path`, `file_hash` (image hash), `raw_reference` (ImageLoaded) |
| **Event ID 11** | File Create | `sysmon_file_create` | `endpoint` | `process`, `process_id`, `image_path`, `raw_reference` (TargetFilename), `hostname` |
| **Event ID 22** | DNS Query | `sysmon_dns_query` | `endpoint` | `process`, `process_id`, `dns_query` (QueryName), `dns_response` (QueryResults), `hostname` |

---

## 2. Telemetry Normalization Schema

The `NormalizedEvent` entity model supports host and process telemetry via bounded, nullable fields without fabricating missing values:

```python
# Identity, Host & Endpoint / Sysmon Fields
username: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
process: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
parent_process: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
process_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
parent_process_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
command_line: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
image_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
file_hash: Mapped[Optional[str]] = mapped_column(String(256), nullable=True, index=True)
```

### Deterministic Field Mapping
- **`Computer`** $\rightarrow$ `hostname`
- **`User`** $\rightarrow$ `username`
- **`Image`** $\rightarrow$ `image_path` (full executable path) & `process` (basename: `cmd.exe`)
- **`ParentImage`** $\rightarrow$ `parent_process` (basename: `explorer.exe`)
- **`ProcessId`** $\rightarrow$ `process_id` (integer)
- **`ParentProcessId`** $\rightarrow$ `parent_process_id` (integer)
- **`CommandLine`** $\rightarrow$ `command_line` (bounded string, max 8,192 chars)
- **`Hashes`** $\rightarrow$ `file_hash` (e.g., `SHA256=...`)
- **`SourceIp` / `DestinationIp`** $\rightarrow$ `source_ip` / `destination_ip`
- **`SourcePort` / `DestinationPort`** $\rightarrow$ `source_port` / `destination_port`
- **`Protocol`** $\rightarrow$ `protocol`
- **`QueryName` / `QueryResults`** $\rightarrow$ `dns_query` / `dns_response`
- **`ProcessGuid` / `EventRecordID`** $\rightarrow$ `raw_reference` and deterministic `event_id` generation

---

## 3. Input Formats & Safe Parser Architecture

The Sysmon parser (`backend/app/parsers/sysmon_parser.py`) provides safe auto-detection across two primary enterprise representations:
1. **Windows Event XML**: Standard EVTX XML representation (`<Event xmlns="...">...<System>...</System><EventData>...</EventData></Event>`) or multi-event collections.
2. **Sysmon JSON / JSON Lines**: Structured export format supporting flat dictionaries or nested EVTX-JSON objects.

### Security & Fault-Tolerance Controls
- **XML Entity Protection**: Standard XML entity resolution is disabled to prevent XML External Entity (XXE) and billion laughs expansion vulnerabilities.
- **Strict Size Bounds**: Input uploads bounded to 10 MB (`MAX_RAW_SIZE`); command-line bounded to 8,192 characters; image paths bounded to 1,024 characters; DNS strings bounded to 512 characters.
- **Malformed Containment**: Syntax errors in XML or JSON Lines are isolated and recorded in the `errors` payload without terminating parser execution or crashing database ingestion.
- **Case-Insensitive Windows Semantics**: Process names and paths are queried using `func.lower(...)` to honor Windows case-insensitivity without false negatives on capitalized filenames (e.g. `WINWORD.EXE`).
- **Audit Provenance**: Raw events and upload metadata are stored in `RawLog` with replay labeling (`LIVE`, `REPLAY`, `SIMULATED`).

---

## 4. Detection-as-Code: Endpoint Detection Rules

Five targeted endpoint detection rules were authored following the Detection-as-Code metadata specification:

| Rule ID | Rule Name | Category | Severity | MITRE Technique | Confidence | Condition Logic | Expected Telemetry |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **ENDPOINT-001** | Suspicious process execution | `endpoint` | `high` | T1059.001 (PowerShell) / T1027 | 0.88 | Pattern match on encoded commands (`-enc`), hidden window style, shadow copy deletion (`vssadmin delete shadows`), or privilege recon (`whoami /priv`) | `endpoint_telemetry` |
| **ENDPOINT-002** | Suspicious parent-child process relationship | `endpoint` | `critical` | T1059.003 / T1190 | 0.92 | Interactive shells (`cmd.exe`, `powershell.exe`) spawned by web servers (`w3wp.exe`, `nginx.exe`, `httpd.exe`) or Office apps (`winword.exe`, `excel.exe`) | `endpoint_telemetry` |
| **ENDPOINT-003** | Suspicious process network connection | `endpoint` | `high` | T1105 / T1571 | 0.85 | LOLBINs / interpreters (`certutil.exe`, `rundll32.exe`, `regsvr32.exe`, `powershell.exe`) connecting to non-standard ports (8080, 4444, 1337, 31337) | `endpoint_telemetry` |
| **ENDPOINT-004** | Suspicious DNS activity | `endpoint` | `medium` | T1071.004 (DNS) | 0.82 | Utilities querying dynamic DNS (`duckdns.org`, `ngrok.io`, `tunnel.me`) or C2 staging domains | `endpoint_telemetry` |
| **ENDPOINT-005** | Suspicious executable/file creation | `endpoint` | `high` | T1105 / T1059 | 0.86 | Script engines or web servers creating binary executables in user Temp, AppData, or Startup folders | `endpoint_telemetry` |

---

## 5. Benchmark Dataset: Sysmon V1

A separate endpoint detection benchmark was constructed under `research/datasets/sysmon_v1/`:

- **Total Scenarios**: 50
- **Ground Truth Distribution**: 25 Attack / Suspicious, 25 Benign (50% / 50% balanced)
- **Partitions**:
  - **Development Split**: 26 scenarios (13 Attack, 13 Benign)
  - **Validation Split**: 10 scenarios (5 Attack, 5 Benign)
  - **Test Split (Held-Out)**: 14 scenarios (7 Attack, 7 Benign) — **STRICTLY UNTOUCHED**
- **Integrity Manifest**: `research/datasets/sysmon_v1/sysmon_v1_manifest.json`
  - Full Dataset SHA-256: `3a4be6c25b28faa672a21703218cb84ed64830aa296c1f51c277a2bb744dba93`
  - Test Set SHA-256: `a937a0780ae66922579dfd95d10526e855737e96ffea04221d606138676bf03e`

### False-Positive Resistance Scenarios
To prevent simplistic signatures (e.g., "powershell.exe = malware") from achieving artificially inflated scores, the benchmark incorporates realistic benign activity:
- Standard PowerShell administrative queries (`Get-Service`, `Get-Process`, `Get-Date`)
- Developer build pipelines invoking `csc.exe`, `git.exe`, `python.exe`
- Web browsers (`msedge.exe`, `chrome.exe`) connecting to ports 80/443 and querying `microsoft.com` / `azure.com`
- System background services (`services.exe` spawning `svchost.exe`)
- Legitimate software installers (`msiexec.exe`) deploying DLLs into `Program Files`

---

## 6. Evaluation Results (Development & Validation Splits)

The benchmark was executed via `research/evaluate_sysmon_detection.py` against Development and Validation partitions:

| Metric | Development Split (26 Scenarios) | Validation Split (10 Scenarios) | Combined Dev + Val (36 Scenarios) | Held-Out Test Set (14 Scenarios) |
| :--- | :--- | :--- | :--- | :--- |
| **True Positives (TP)** | 13 | 5 | 18 | *UNTOUCHED* |
| **False Positives (FP)** | 0 | 0 | 0 | *UNTOUCHED* |
| **False Negatives (FN)** | 0 | 0 | 0 | *UNTOUCHED* |
| **True Negatives (TN)** | 13 | 5 | 18 | *UNTOUCHED* |
| **Precision** | **1.0000** (100.0%) | **1.0000** (100.0%) | **1.0000** (100.0%) | *UNTOUCHED* |
| **Recall** | **1.0000** (100.0%) | **1.0000** (100.0%) | **1.0000** (100.0%) | *UNTOUCHED* |
| **F1-Score** | **1.0000** (100.0%) | **1.0000** (100.0%) | **1.0000** (100.0%) | *UNTOUCHED* |
| **False Positive Rate (FPR)** | **0.0000** (0.0%) | **0.0000** (0.0%) | **0.0000** (0.0%) | *UNTOUCHED* |
| **Avg Detection Latency** | 5.96 ms | 4.60 ms | 5.58 ms | *UNTOUCHED* |
| **Max Detection Latency** | 14.47 ms | 7.77 ms | 14.47 ms | *UNTOUCHED* |

### Per-Rule Detection Breakdown & Health Score
| Rule ID | Rule Name | TP | FP | FN | Precision | Recall | Health Score | Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **ENDPOINT-001** | Suspicious process execution | 5 | 0 | 0 | 1.00 | 1.00 | **98.1 / 100** | `EXCELLENT` |
| **ENDPOINT-002** | Suspicious parent-child process relationship | 4 | 0 | 0 | 1.00 | 1.00 | **98.7 / 100** | `EXCELLENT` |
| **ENDPOINT-003** | Suspicious process network connection | 3 | 0 | 0 | 1.00 | 1.00 | **98.0 / 100** | `EXCELLENT` |
| **ENDPOINT-004** | Suspicious DNS activity | 3 | 0 | 0 | 1.00 | 1.00 | **97.8 / 100** | `EXCELLENT` |
| **ENDPOINT-005** | Suspicious executable/file creation | 3 | 0 | 0 | 1.00 | 1.00 | **98.1 / 100** | `EXCELLENT` |

---

## 7. Performance & Throughput Profiling

Throughput was measured distinctly across pipeline stages using a 500-event streaming batch:

| Pipeline Stage | Measurement | Stage Latency | Description |
| :--- | :--- | :--- | :--- |
| **Parser Stage** | **10,917.05 EPS** | 45.80 ms | Raw JSON/XML deserialization, schema mapping, and validation |
| **Ingestion Stage** | **2,482.45 EPS** | 155.61 ms | DB normalization, `RawLog` provenance, and relational insert |
| **Detection Stage** | **470.99 EPS** | 1,061.60 ms | Sliding window queries across all 25 active detection rules |
| **End-to-End SOC** | **395.51 EPS** | 1,262.90 ms | Complete synchronous parse + ingest + detect + persist |
| **Per-Event Latency** | **Avg: 0.111 ms** | **Max: 0.476 ms** | Single-event pipeline processing time |

---

## 8. Research Limitations & Phase Boundary

1. **Controlled Benchmark Context**: The 100% precision and recall metrics on `Sysmon V1` DEV and VALIDATION splits demonstrate internal validity on modeled endpoint attack scenarios. They do not constitute an evaluation of real-world enterprise environments containing novel zero-days or diverse endpoint behaviors.
2. **No Claim of EDR Parity**: Sysmon is an event logging mechanism, not an Endpoint Detection and Response (EDR) platform with active process suspension, memory inspection, or driver hooks.
3. **No Cross-Source Correlation**: Endpoint detections operate strictly on host telemetry without cross-referencing Zeek network logs or Web application logs. Cross-source correlation belongs strictly to Phase 6.
