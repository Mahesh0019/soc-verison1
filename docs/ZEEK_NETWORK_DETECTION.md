# Zeek Network Telemetry Validation & Network Detection Engineering

**Phase**: Phase 4  
**Status**: Implemented & Verified  
**Date**: October 2026  
**Document Version**: 1.0.0  

---

## 1. Executive Summary

Phase 4 moves beyond basic parsing and ingestion of Zeek network logs into **active network detection engineering, alert generation, evidence packaging, and detection quality validation**.

Using the source-aware `NormalizedEvent` schema established in Phase 3, this phase validates the complete network detection lifecycle:
```
Zeek Telemetry (conn.log / http.log / dns.log)
         │
         ▼
Resilient Normalization (Safe type conversion & bounds)
         │
         ▼
Database Persistence (NormalizedEvent & RawLog provenance)
         │
         ▼
Detection Engine (NETWORK-001 through NETWORK-006)
         │
         ▼
Alert Generation & Threat Attribution
         │
         ▼
Evidence Packaging (Ports, Protocols, Bytes, UIDs, DNS)
         │
         ▼
Detection Quality & Rule Health Scoring
```

> [!IMPORTANT]
> **Architectural Boundary**: Cross-source correlation between network telemetry and host/application logs is **NOT implemented in Phase 4**. Host telemetry (Sysmon) remains `PLANNED / NOT IMPLEMENTED`. All detections in this phase evaluate network-layer telemetry independently.

---

## 2. Detection-as-Code Network Rules

Six specialized network detection rules were designed, implemented, and integrated into the Detection-as-Code framework:

| Rule ID | Rule Name | Category | Severity | MITRE ATT&CK | Confidence | Threshold / Window | Expected Source |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **NETWORK-001** | Suspicious destination port connection | `network` | `high` | T1571 (Non-Standard Port) | 0.85 | 1 conn / 10 min | `network_telemetry` |
| **NETWORK-002** | Repeated rejected connections | `network` | `medium` | T1046 (Network Discovery) | 0.80 | 5 REJ / 10 min | `network_telemetry` |
| **NETWORK-003** | Abnormal network connection burst | `traffic_anomaly` | `medium` | T1499.001 (Endpoint DoS) | 0.70 | 15 conns / 5 min | `network_telemetry` |
| **NETWORK-004** | Suspicious HTTP activity from Zeek | `reconnaissance` | `high` | T1595.002 (Vuln Scan) | 0.80 | 3 probes / 10 min | `network_telemetry` |
| **NETWORK-005** | DNS resolution anomaly | `network` | `medium` | T1568 (Dynamic Resolution) | 0.75 | 3 NXDOMAIN / 10 min | `network_telemetry` |
| **NETWORK-006** | Potential reconnaissance pattern | `reconnaissance` | `high` | T1595 (Active Scanning) | 0.82 | 4 probes / 10 min | `network_telemetry` |

### Detailed Rule Criteria

#### NETWORK-001: Suspicious destination port connection
* **Logic**: Evaluates `source_type == "ZEEK"` and `destination_port in [1337, 31337, 4444, 6667]`.
* **Rationale**: Flags connection attempts directed at notorious trojan backdoors (e.g. Back Orifice), default penetration testing handlers (Metasploit 4444), and standard IRC bots (6667).
* **False Positive Notes**: Local sandbox testing or internal microservices bound to non-standard ports.

#### NETWORK-002: Repeated rejected connections
* **Logic**: Evaluates `source_type == "ZEEK"`, `connection_state in ["REJ", "RSTO", "RSTR"]`, threshold $\ge 5$ within 10 minutes, grouped by `source_ip`.
* **Rationale**: Distinguishes active port scanning or horizontal network sweeping from isolated connection failures.
* **False Positive Notes**: Misconfigured internal service clients or clients retrying a temporarily stopped service.

#### NETWORK-003: Abnormal network connection burst
* **Logic**: Evaluates `source_type == "ZEEK"`, `event_category == "network"`, threshold $\ge 15$ within 5 minutes, grouped by `source_ip`.
* **Rationale**: Captures flood behavior, fast-rate port scanning, or high-frequency automated scraping.
* **False Positive Notes**: High-throughput legitimate API consumers, package repository syncing, or parallel browser asset downloading.

#### NETWORK-004: Suspicious HTTP activity from Zeek
* **Logic**: Evaluates `source_type == "ZEEK"`, `event_type == "sensitive_path_access"` (URIs querying `/.env`, `/admin`, `/config`, `/wp-admin`), threshold $\ge 3$ within 10 minutes, grouped by `source_ip`.
* **Rationale**: Detects web vulnerability scanning observed strictly through passive network taps rather than web server access logs.
* **False Positive Notes**: Authorized web administrator navigating administrative console pages.

#### NETWORK-005: DNS resolution anomaly
* **Logic**: Evaluates `source_type == "ZEEK"`, `event_type == "zeek_dns_nxdomain"`, threshold $\ge 3$ within 10 minutes, grouped by `source_ip`.
* **Rationale**: Catches repeated non-existent domain responses characteristic of Domain Generation Algorithms (DGA) or failed internal recon.
* **False Positive Notes**: Human typos in web browsers or misconfigured corporate search domain suffixes.

#### NETWORK-006: Potential reconnaissance pattern
* **Logic**: Evaluates `source_type == "ZEEK"`, `event_type in ["zeek_conn_rejected", "zeek_suspicious_port"]`, threshold $\ge 4$ within 10 minutes, grouped by `source_ip`.
* **Rationale**: Identifies combined network reconnaissance sequences across disparate ports.
* **False Positive Notes**: Periodic internal network health auditing or vulnerability scanning.

---

## 3. Network Benchmark Dataset V1 (`research/datasets/network_v1/`)

A separate controlled dataset was engineered to benchmark network detection rules.

> [!CAUTION]
> **Dataset Isolation**: Dataset V2 was preserved without modification. The `test` partition of Network Dataset V1 is **strictly held out and un-evaluated**. Only the `development` and `validation` partitions were evaluated in Phase 4.

### Dataset Partitions & Balance
* **Total Scenarios**: 60 (30 ATTACK, 30 BENIGN)
* **Total Telemetry Events**: 338 events
* **Partition Split**:
  * **Development (50%)**: 30 scenarios (15 Attack, 15 Benign) — SHA-256: `ac1b0fb2fc4df8ea...`
  * **Validation (20%)**: 12 scenarios (6 Attack, 6 Benign) — SHA-256: `d9487c6be786a362...`
  * **Test (30%)**: 18 scenarios (9 Attack, 9 Benign) — **Held out / Untouched** — SHA-256: `a7f5bc655c68b7ca...`
* **Full Dataset SHA-256**: `9d6cf5919811a7b894681d1db3beecfbc63eb085ea4b76519f49a631e550b367`

### Ground Truth Categories Covered
1. **Benign Scenarios**:
   - Normal TLS/HTTPS browsing sessions (port 443, SF)
   - Normal corporate DNS resolutions (NOERROR, valid answers)
   - Normal HTTP portal navigations (GET /index.html, 200 OK)
   - Isolated connection failures (1-2 REJ connections, under threshold 5)
   - High-volume legitimate traffic (7 connections in 4 min, under threshold 15)
   - Repeated CDN DNS query sequences (2 queries, NOERROR, under threshold 3)
2. **Attack Scenarios**:
   - Backdoor port connection attempts (destination port 31337 / 1337)
   - High-frequency connection flood (16 connections in 2 min)
   - Reconnaissance port sweep sequences (5 sequential connection attempts)
   - Repeated rejected connection probing (6 consecutive REJ connections)
   - Sensitive path reconnaissance (4 probes to `/.env`, `/admin/config`, etc.)
   - DGA NXDOMAIN DNS anomalies (4 consecutive NXDOMAIN lookups)

---

## 4. Evaluation Methodology & Empirical Results

The network rules were evaluated on the **DEV** and **VALIDATION** partitions using `research/evaluate_network_detection.py`.

### Empirical Results Table

| Split | Scenarios | TP | FP | FN | TN | Precision | Recall | F1 Score | FPR | Avg Detection Latency | Alert Volume |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Development** | 30 | 15 | 0 | 0 | 15 | **1.0000** | **1.0000** | **1.0000** | **0.0000** | 21.28 ms | 20 |
| **Validation** | 12 | 6 | 0 | 0 | 6 | **1.0000** | **1.0000** | **1.0000** | **0.0000** | 18.91 ms | 8 |
| **COMBINED (Dev+Val)** | **42** | **21** | **0** | **0** | **21** | **1.0000** | **1.0000** | **1.0000** | **0.0000** | **20.60 ms** | **28** |
| **Test Set** | 18 | — | — | — | — | *HELD-OUT* | *HELD-OUT* | *HELD-OUT* | *HELD-OUT* | *UNTOUCHED* | — |

---

## 5. Benign False-Positive Analysis & Threshold Trade-offs

A central objective in Phase 4 was proving that network detection rules resist false positives under typical non-malicious network anomalies:

1. **Rejected Connections Trade-off (NETWORK-002)**:
   - Setting a threshold of $\ge 1$ rejection produced unacceptable false positives from routine client connectivity blips.
   - Setting threshold $= 5$ within 10 minutes successfully suppressed all benign test cases (1–3 isolated rejections yielded 0 alerts) while reliably catching port scanning sweeps (6+ rejections yielded 100% recall).
2. **Traffic Volumetrics Trade-off (NETWORK-003)**:
   - Modern web browsers and asset pre-loaders easily generate 6–10 parallel TCP handshakes.
   - Setting the burst threshold to $\ge 15$ within 5 minutes allowed high-volume benign web sessions (7 connections) to pass without alert generation ($FPR = 0.00$), while correctly flagging sustained automated floods (16+ connections).
3. **DNS Query Failures Trade-off (NETWORK-005)**:
   - Occasional client typos or expired search domains produce 1 NXDOMAIN response.
   - Requiring a threshold of $\ge 3$ NXDOMAIN responses in 10 minutes successfully filtered transient lookup errors while flagging repetitive DGA domain sweeps.

---

## 6. Evidence Packaging for Network Alerts

The Evidence Engine (`backend/app/services/evidence_service.py`) was extended to package network-specific provenance:
* **Triggering Event Evidence**: Captures `source_ip`, `destination_ip`, `source_port`, `destination_port`, `protocol`, `connection_state`, `bytes_in`, `bytes_out`, `response_time_ms`, `dns_query`, `dns_response`, `raw_reference` (Zeek UID), and `source_type`.
* **Supporting Events Evidence**: Captures correlated destination ports, observed protocols, and Zeek UIDs across the sliding window.
* **Integrity Guarantee**: Deterministic SHA-256 evidence hashing ensures immutability of recorded network forensics.

---

## 7. Detection Quality & Rule Health Scores

Rule Health scoring was executed through `evaluate_rule_health()` and persisted to `rule_health_records`:

| Rule ID | Rule Name | Precision | Recall | F1 Score | FPR | Health Score | Health Tier | Regression Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **NETWORK-001** | Suspicious destination port connection | 1.00 | 1.00 | 1.00 | 0.00 | **97.7 / 100** | `EXCELLENT` | `PASSED` |
| **NETWORK-002** | Repeated rejected connections | 1.00 | 1.00 | 1.00 | 0.00 | **96.7 / 100** | `EXCELLENT` | `PASSED` |
| **NETWORK-003** | Abnormal network connection burst | 1.00 | 1.00 | 1.00 | 0.00 | **93.9 / 100** | `EXCELLENT` | `PASSED` |
| **NETWORK-004** | Suspicious HTTP activity from Zeek | 1.00 | 1.00 | 1.00 | 0.00 | **97.2 / 100** | `EXCELLENT` | `PASSED` |
| **NETWORK-005** | DNS resolution anomaly | 1.00 | 1.00 | 1.00 | 0.00 | **96.6 / 100** | `EXCELLENT` | `PASSED` |
| **NETWORK-006** | Potential reconnaissance pattern | 1.00 | 1.00 | 1.00 | 0.00 | **97.2 / 100** | `EXCELLENT` | `PASSED` |

---

## 8. Multi-Stage Performance Benchmarks

Measured using `scripts/benchmark_zeek.py` across all standard fixtures:

| Pipeline Stage | Measurement | Value |
| :--- | :--- | :--- |
| **Parser Throughput** | In-memory token parsing & type coercion | **17,654.60 eps** |
| **Ingestion Throughput** | Parse + ORM database persistence | **712.17 eps** |
| **Detection Throughput** | Multi-rule matching & window evaluation | **2,243.05 eps** |
| **Total SOC Pipeline Throughput** | End-to-end replay, DB, detection & alerting | **527.00 eps** |
| **Avg Ingestion Latency** | Per-event DB persistence latency | **0.190 ms** |
| **Avg DB Persistence Time** | Batch commit latency | **29.30 ms** |
| **Avg Detection Latency** | Rule evaluation latency | **2.69 ms** |
| **Peak Event Latency** | Maximum observed latency | **0.331 ms** |

---

## 9. Failure Testing & Robustness

The system was stressed with abnormal inputs in `test_07_failure_testing_robustness`:
* **Malformed log lines**: Handled per line with `errors` recording; did not crash ingestion.
* **Missing fields (`-`)**: Mapped to `None` without type errors.
* **Duplicate UIDs**: Detected and tracked via `events_duplicated` counter.
* **Large / extreme values**: Safely bounded without database overflow.
* **No partial state corruption**: Database rollback and per-event validation ensure atomicity.

---

## 10. Research Boundaries & Limitations

### What Phase 4 Demonstrates
* Zeek network telemetry can be normalized and reliably detected in real-time.
* Network rules achieve high precision and low false-positive rates when thresholds account for benign network bursts.
* Full traceability from Zeek UID to Alert Evidence is established.

### Explicit Research Non-Claims
* We do **NOT** claim that internal network defense is complete.
* We do **NOT** claim enterprise-scale network detection is validated.
* We do **NOT** claim real-world attack detection is proven beyond the controlled benchmark.
* We do **NOT** claim Zeek provides complete network visibility (packet payloads, encrypted TLS contents, and Layer-2 framing are uninspected).

### Future Work
* **Phase 5**: Cross-source correlation (Network $\leftrightarrow$ Application $\leftrightarrow$ Host).
* **Phase 6 / Future**: Sysmon host telemetry integration.
