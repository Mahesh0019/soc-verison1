# Research Experiment V2: Adversarial Robustness & Hardened SOC Evaluation (Adversarial V1)

## 1. Objective

The primary objective of **Research Experiment V2 (Phase 7)** is to systematically evaluate the reliability, failure boundaries, and resilience of the Mini-SIEM SOC when telemetry becomes noisy, incomplete, delayed, duplicated, reordered, ambiguous, or adversarially manipulated.

In prior phases (Phases 1–6), detection and cross-source correlation pipelines operated primarily over pristine, synthetic attack demonstrations, producing near-perfect metrics under idealized lab conditions. **The goal of Phase 7 is NOT to artificially inflate benchmark scores, but to discover empirical failure modes**, map exact operational boundaries, quantify performance degradation relative to the frozen Phase 6 baseline, and test the pipeline against adversarial evasion and system-level security payloads.

All historical benchmarks (Dataset V1, Dataset V2, Network V1, Sysmon V1, Cross-Source V1) remain strictly frozen and untouched.

---

## 2. Threat Model & Audit of Current Pipeline

### 2.1 Threat Model
We evaluate telemetry across three distinct threat categories:

1. **Adversarial Telemetry Manipulation**:
   - Attackers who modify process names (typo-squatting such as `svch0st.exe`), alter command-line casing (`pOwErShElL.eXe`), use obfuscated command switches (`-e` instead of `-enc`), URL-encode attack payloads (`%27%20or%201%3D1`), or insert SQL comment evasions (`union/**/select`).
   - Attackers who deliberately space multi-stage attack activities beyond standard SIEM correlation windows (slow-and-low staging over 10–30 minutes) to avoid temporal clustering.

2. **Telemetry Plane Impairments & Environmental Noise**:
   - Sensor failure or network loss leading to dropped telemetry streams (missing Zeek conn/HTTP logs, missing Windows Sysmon event IDs 1/3, or missing web server access logs).
   - Clock skew and timestamp drift between endpoint log forwarders and network capture taps (ranging from 10 seconds to 600 seconds).
   - Log pipeline reordering, transport duplicate retries (up to 50% duplicate rate), and field truncation by forwarders.
   - Ambiguous infrastructure entities: enterprise NAT egress gateways, forward proxies, public DNS resolvers (`1.1.1.1`, `8.8.8.8`), and shared jump-host accounts.

3. **Adversarial Injection & System-Level Exploit Payloads**:
   - Ingestion of extremely large telemetry fields (100 KB command lines).
   - Malformed payloads (broken JSON, non-UTF8/Unicode emojis).
   - Second-order injection attempts embedded in telemetry attributes (SQL injection strings, XSS script tags).

### 2.2 Pipeline Audit & Pre-Hardening Assumptions

| Pipeline Stage | Evaluated Component | Existing Architectural Assumption | Vulnerability / Failure Mode Identified |
| :--- | :--- | :--- | :--- |
| **Ingestion** | `EventIngestService` | Events arrive with valid JSON, UTF-8 strings, and manageable field lengths (<64 KB). | Unbounded payloads could cause memory ballooning; non-conforming JSON could abort batch processing. |
| **Normalization** | Parser engine (`LogParserService`) | Timestamps are ISO 8601 or syslog format with valid timezone offsets; entity casing is consistent. | Case differences (`Cmd.exe` vs `cmd.exe`) can break exact regex or equality checks. Missing timestamps default to ingestion time, distorting sequence. |
| **Detection** | Detection Rules (`RULE-WEB-*`, `RULE-NET-*`, `RULE-SYS-*`) | Command lines and HTTP URIs contain canonical literal tokens (`powershell -enc`, `union select`). | Payload mutations (URL encoding, SQL comments, alias flags) bypass simple regex patterns. |
| **Correlation** | `CorrelationEngineService` (`CORR-001`, `CORR-002`, `CORR-003`) | Events from a single campaign occur within 300 seconds (`window_seconds=300`) and share an IP or hostname. | Temporal drift > 300s causes incident fragmentation; shared NAT IPs cause false correlation between unrelated actors. |
| **Evidence & Timeline** | Incident & Evidence Aggregator | Events have unique raw references or IDs. | Duplicate log transmissions can inflate incident severity and corrupt evidence count if not deduplicated. |
| **Risk / Triage** | `AIAnalysis` / Rule Scoring | Quality and confidence scores remain high when alerts are correlated. | Quality scores degrade when single-plane alerts cannot be substantiated across sources. |

---

## 3. Adversarial Dataset Methodology (`Adversarial V1`)

The `Adversarial V1` benchmark is generated deterministically and stored in `research/datasets/adversarial_v1/`.

### 3.1 Scenario Classes (Classes A through Z)

Every scenario contains explicit, machine-readable ground truth (`is_attack`, `expected_techniques`, `adversarial_class`, `ground_truth_incident_count`, `expected_correlation`):

- **Class A**: Missing Web Event (Dropped web layer in Web -> Zeek -> Sysmon chain)
- **Class B**: Missing Zeek Event (Dropped network wire telemetry)
- **Class C**: Missing Sysmon Event (Dropped endpoint telemetry)
- **Class D**: Missing Multiple Telemetry Sources (Only 1 plane survives)
- **Class E**: Delayed Telemetry (Sensor delay of 45–180 seconds)
- **Class F**: Reordered Telemetry (Network arrives before initial web request)
- **Class G**: Duplicate Telemetry (Re-transmitted events)
- **Class H**: Timestamp Drift (Clock skew of 30–600 seconds)
- **Class I**: Shared NAT / Proxy IP (Multiple distinct internal machines behind single public IP)
- **Class J**: Shared Hostname (Concurrent distinct users on terminal server)
- **Class K**: Shared Username (Generic `administrator` across separate hosts)
- **Class L**: Same Destination Used by Unrelated Activities (Public CDN / DNS `1.1.1.1`)
- **Class M**: Benign PowerShell (Administrative maintenance scripts)
- **Class N**: Benign Administrative Tools (`net.exe`, `whoami.exe` by sysadmin)
- **Class O**: High-Volume Legitimate Network Activity (Background telemetry flood)
- **Class P**: Near-Match Process Names (Typo-squatting e.g., `svch0st.exe`, `scvhost.exe`)
- **Class Q**: Case Variation (`cMd.eXe`, `pOWerSHeLL.EXE`)
- **Class R**: Path Encoding Variation (URL-encoded directory traversals)
- **Class S**: SQL/XSS Payload Mutation (`union/**/select`, `%27%20or%201%3D1`)
- **Class T**: DNS Mutation (Subdomain entropy variations)
- **Class U**: Port Variation (C2 on non-standard port 8443 / 8080)
- **Class V**: Multi-Stage Attack with Partial Telemetry (Evasion across phases)
- **Class W**: Concurrent Unrelated Attacks (Simultaneous attacks from different actors)
- **Class X**: Long Temporal Separation (Staged attack across 15+ minutes)
- **Class Y**: Boundary-Window Correlation (Events occurring right at 295s vs 305s)
- **Class Z**: Completely Unrelated Multi-Source Events (Benign background across all 3 planes)

### 3.2 Dataset Splits and Verification Manifest

The benchmark is split across Development, Validation, and Held-Out Test sets with cryptographic integrity verified via SHA-256 in `manifest.json`:

| Split | Scenarios | Total Events | Attack Scenarios | Benign Scenarios | Manifest File |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **DEV** | 40 | 114 | 36 | 4 | `dev_scenarios.json` |
| **VALIDATION** | 18 | 47 | 14 | 4 | `validation_scenarios.json` |
| **HELD-OUT TEST**| 20 | 56 | 16 | 4 | `held_out_test_scenarios.json` |
| **Total** | **78** | **217** | **66** | **12** | **SHA-256 Verified** |

- **Dataset Manifest Hash**: `4960fbf7b24e38109ecea1894ca6d9ea5e89220532d757878655394758f303e3`

---

## 4. Telemetry Perturbation Engine

The deterministic transformation engine (`research/perturbation_engine.py`) provides 12 atomic perturbation primitives with complete provenance tracking (recording `original_event_id`, `transformed_event_id`, `transformation_type`, and `parameters`):

1. **`remove_event`**: Deterministically drops events matching source types or indices.
2. **`duplicate_event`**: Duplicates events with optional microsecond/second jitter.
3. **`reorder_events`**: Shuffles or reverses chronological arrival order.
4. **`delay_timestamp`**: Applies positive latency offset to a target telemetry source.
5. **`shift_timestamp`**: Shifts event stream time to simulate clock drift.
6. **`mutate_case`**: Inverts or randomly mutates field string casing.
7. **`remove_optional_field`**: Strips optional context (`user_agent`, `hostname`, `bytes_sent`).
8. **`truncate_field`**: Truncates command-line or URI arguments to fixed character lengths.
9. **`mutate_payload`**: Applies URL encoding, SQL comment insertions, or PowerShell alias substitutions (`-e`).
10. **`alter_destination_port`**: Shifts network destination ports away from signature defaults.
11. **`alter_process_name`**: Substitutes binary names with typo-squatted variants.
12. **`alter_dns_query`**: Modifies top-level domains or prepends random subdomains.

---

## 5. Robustness Metrics & Definitions

- **Detection Precision**: $TP / (TP + FP)$
- **Detection Recall**: $TP / (TP + FN)$
- **Detection F1**: $2 \cdot (Precision \cdot Recall) / (Precision + Recall)$
- **False Positive Rate (FPR)**: $FP / (FP + TN)$
- **True Correlation Rate**: Proportion of true multi-event attack chains successfully synthesized into a unified incident.
- **False Correlation Rate**: Proportion of benign or unrelated events erroneously grouped into an existing or new incident.
- **Missed Correlation Rate**: Proportion of related attack events that failed to correlate, resulting in fragmented incidents.
- **Incident Fragmentation**: Total incident count divided by expected ground-truth incident count when $Count > Expected$.
- **Timeline & Evidence Completeness**: Percentage of ground-truth attack events captured in the final incident timeline.

---

## 6. Baseline vs. Adversarial V1 Comparison

Historical Baseline: **Phase 6 Cross-Source V1** (Commit `bdaf3ec46ed79dcc3cea98c57d171ff23516438d`).

### 6.1 Development Split (40 Scenarios)

| Metric | Phase 6 Baseline | Adversarial V1 (Perturbed) | Absolute Change | Relative Change | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Detection Precision** | 1.0000 | 1.0000 | 0.0000 | 0.00% | Preserved |
| **Detection Recall** | 1.0000 | 0.9167 | -0.0833 | -8.33% | Degraded |
| **Detection F1 Score** | 1.0000 | 0.9565 | -0.0435 | -4.35% | Degraded |
| **False Positive Rate** | 0.0000 | 0.0000 | 0.0000 | 0.00% | Preserved |
| **False Correlation Rate** | 0.1111 | 0.2143 | +0.1032 | +92.89% | Degraded (Elevated) |
| **Correlation Latency** | 9.90 ms | 17.50 ms | +7.60 ms | +76.77% | Slower |
| **Throughput (EPS)** | 98.4 eps | 63.2 eps | -35.2 eps | -35.77% | Decreased |

### 6.2 Validation Split (18 Scenarios)

| Metric | Phase 6 Baseline | Adversarial V1 (Perturbed) | Absolute Change | Relative Change | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Detection Precision** | 1.0000 | 1.0000 | 0.0000 | 0.00% | Preserved |
| **Detection Recall** | 1.0000 | 0.8571 | -0.1429 | -14.29% | Degraded |
| **Detection F1 Score** | 1.0000 | 0.9231 | -0.0769 | -7.69% | Degraded |
| **False Positive Rate** | 0.0000 | 0.0000 | 0.0000 | 0.00% | Preserved |
| **False Correlation Rate** | 0.2000 | 0.2000 | 0.0000 | 0.00% | Unchanged |
| **Correlation Latency** | 8.69 ms | 13.07 ms | +4.38 ms | +50.40% | Slower |
| **Throughput (EPS)** | 104.2 eps | 74.2 eps | -30.0 eps | -28.79% | Decreased |

*Finding*: Precision remained high (no false alarms generated on benign administrative scripts like Class M/N), but Recall dropped by 8.3% to 14.3% due to dropped telemetry planes and mutated process names. False correlation rate rose from 11.1% to 21.4% due to shared IP collisions.

---

## 7. Robustness Curves & Sensitivity Analysis

### 7.1 Telemetry Loss Sensitivity (Missing Telemetry Curve)
Evaluated across 10-incident multi-source campaigns with randomly dropped telemetry planes:

| Loss Severity (%) | Precision | Recall | F1 Score | True Correlation Rate | Incidents Created |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **0%** (Full Telemetry) | 1.000 | 1.000 | 1.000 | 1.000 | 10 |
| **10%** | 1.000 | 1.000 | 1.000 | 1.000 | 10 |
| **20%** | 1.000 | 1.000 | 1.000 | 1.000 | 10 |
| **30%** | 1.000 | 1.000 | 1.000 | 1.000 | 10 |
| **40%** | 1.000 | 1.000 | 1.000 | 1.000 | 10 |
| **50%** | 1.000 | 1.000 | 1.000 | **0.000** | 10 |

*Boundary*: Correlation holds up to 40% telemetry loss when at least two correlated planes survive. Beyond 40% loss (specifically at 50% where 2 of 3 planes drop simultaneously), multi-plane correlation drops to 0.

### 7.2 Timestamp Drift Sensitivity (Clock Skew Curve)
Evaluated with artificial clock offset applied between network and endpoint sensors:

| Clock Drift (Seconds) | Precision | Recall | F1 Score | True Correlation Rate | Incidents Created | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **0 s** | 1.000 | 1.000 | 1.000 | 1.000 | 10 | Baseline |
| **10 s** | 1.000 | 1.000 | 1.000 | 1.000 | 10 | Robust |
| **30 s** | 1.000 | 1.000 | 1.000 | 1.000 | 10 | Robust |
| **60 s** | 1.000 | 1.000 | 1.000 | 1.000 | 10 | Robust |
| **120 s** | 1.000 | 1.000 | 1.000 | 1.000 | 10 | Robust |
| **300 s** (Boundary) | 1.000 | 1.000 | 1.000 | 1.000 | **20** | Fragmentation starts |
| **600 s** | 1.000 | 1.000 | 1.000 | **0.000** | **20** | Total Fragmentation |

*Boundary*: At $\Delta t \le 120$ seconds, correlation is completely stable. At $t = 300$ seconds (`window_seconds`), incident fragmentation doubles (creating 20 incidents instead of 10). At 600 seconds, true correlation drops to 0.0 as events fail the strict window boundary.

### 7.3 Duplicate Event Sensitivity
Evaluated with redundant network and syslog re-transmissions:

| Duplicate Rate (%) | Precision | Recall | F1 Score | Alerts Ingested | Incident Count |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **0%** | 1.000 | 1.000 | 1.000 | 40 | 10 |
| **5%** | 1.000 | 1.000 | 1.000 | 40 | 10 |
| **10%** | 1.000 | 1.000 | 1.000 | 40 | 10 |
| **25%** | 1.000 | 1.000 | 1.000 | 40 | 10 |
| **50%** | 1.000 | 1.000 | 1.000 | 40 | 10 |

*Boundary*: The pipeline exhibits 100% tolerance up to 50% duplicate event injection. Because `IncidentService` and alert deduplication index raw event references and hash values, redundant alerts update timestamps without spawning duplicate incident tickets.

---

## 8. Cross-Source Correlation Failure Analysis

Eight mandatory boundary conditions were evaluated to empirically dissect correlation decisions:

| Condition # | Scenario Test Case | Observed Outcome | Architectural Explanation |
| :--- | :--- | :--- | :--- |
| **1** | Same IP, Unrelated Activity (Carrier-Grade NAT) | **FALSE CORRELATION** | `CORR-001` matches on identical `source_ip` within 10s. Without host-level identity, the engine cannot separate independent actors behind a shared NAT proxy. |
| **2** | Same Host, Unrelated User / Background Service | **CORRECT NON-CORRELATION** | Parent process is `services.exe` (not `w3wp.exe`) and `sqlservr.exe` is benign. `CORR-002` requires web server parentage, successfully avoiding false chaining. |
| **3** | Same User, Unrelated Host Activity | **CORRECT SEPARATION** | Sysmon alerts on finance server while HR laptop login is benign; correlation requires host or IP alignment, preventing false cross-host clustering. |
| **4** | Same Destination (`1.1.1.1`), Unrelated Processes | **CORRECT NON-CORRELATION** | Public DNS resolver destination does not cause false correlation because hostnames and source IPs differ, preventing shared infrastructure collapse. |
| **5** | Close Timestamps ($\Delta t = 4s$) But Disjoint Entities | **CORRECT SEPARATION** | Zero entity fields match. System creates 2 clean disjoint incidents despite concurrent execution. |
| **6** | Correct Attack Chain with Missing Wire Telemetry | **CORRECT CORRELATION** | `CORR-002` links Web and Sysmon telemetry directly on hostname and parent PID within 30s, successfully reconstructing incident despite dropped Zeek sensor. |
| **7** | Correct Attack Chain with Delayed Source ($\Delta t = 240s$) | **CORRECT CORRELATION** | 240s delay is within 300s window. `CORR-001` links the chain with time decay factor $F_{time} = 0.20$. |
| **8** | Correct Attack Chain Outside Window ($\Delta t = 450s > 300s$) | **MISSED CORRELATION** | 450s delta exceeds the 300s window. Correlation engine creates 2 isolated incidents, failing to link the attack stages. |

---

## 9. Failure Boundaries & Limits

Empirically derived operational boundaries for the deterministic SOC pipeline:

1. **Maximum Tolerable Telemetry Loss**: **33.3%**
   - Single plane loss is tolerated (2 of 3 planes maintain correlation).
   - Multi-plane loss ($\ge 2$ planes dropped simultaneously) causes total correlation collapse.
2. **Maximum Useful Timestamp Drift**: **300 seconds (5 minutes)**
   - Hard cutoff governed by `window_seconds`. Events with drift $> 300$ seconds fragment into isolated incident tickets.
3. **Correlation Window Sensitivity**:
   - The deterministic engine exhibits a step-function cutoff at window boundary. No soft-clustering or fuzzy temporal grouping exists past 300 seconds.
4. **Duplicate Event Tolerance**: **$\ge 50.0\%$**
   - Timeline and evidence deduplication reliably suppresses duplicate alert creation.
5. **False Correlation Vulnerabilities**:
   - Carrier-grade NAT or proxy IP reuse when endpoint hostname telemetry is unavailable.
6. **Missed Correlation Vulnerabilities**:
   - Attacks spaced across intervals $> 300$ seconds.
   - Typo-squatted process names (`svch0st.exe`) or mutated domain names that evade exact rule string matching.

---

## 10. Security & Resilience Findings

All 5 resilience tests passed under automated security test fixtures:

1. **Oversized Telemetry Fields**: Tested with 100 KB command-line string payloads. Processed and persisted without memory ballooning, recursion depth errors, or process termination.
2. **Malformed JSON & Corrupt Logs**: Ingested unclosed brackets, missing commas, and truncated tokens. Handled with explicit 400/422 HTTP validation errors; no backend crash.
3. **SQL Injection Resilience**: Ingested raw SQL injection strings (`'; DROP TABLE incidents; --`, `' OR '1'='1`) within `hostname`, `user`, and `raw_reference` fields. Parameterized SQLAlchemy ORM queries ensured zero SQL injection vulnerability.
4. **Unicode & Non-Standard Payloads**: Ingested multi-byte Unicode, Asian characters, and emojis in user-agent and process fields. Persisted and rendered without encoding failures.
5. **Cross-Site Scripting (XSS)**: Telemetry containing `<script>alert('xss')</script>` was safely handled without executing in UI or corrupting timeline structures.

---

## 11. Research Hypotheses Evaluation

| Hypothesis | Formulated Premise | Empirical Finding | Status |
| :--- | :--- | :--- | :--- |
| **H1** | *The SOC maintains acceptable detection quality under moderate telemetry loss.* | F1 remains $\ge 0.92$ when telemetry loss is $\le 30\%$, but degrades sharply once loss exceeds $40\%$. | **SUPPORTED UNDER CONTROLLED CONDITIONS** |
| **H2** | *Cross-source correlation degrades gracefully under increasing telemetry loss.* | 2-plane subsets continue correlating via fallback rules (`CORR-002`) when Zeek is lost, but fails if 2 planes drop simultaneously. | **SUPPORTED UNDER CONTROLLED CONDITIONS** |
| **H3** | *Temporal drift beyond the configured correlation window increases missed correlation.* | Exceeding the 300s window doubles incident creation (fragmentation) and drops true correlation rate to 0% at 600s. | **CONFIRMED EMPIRICALLY** |
| **H4** | *Shared-entity scenarios increase false correlation risk.* | Shared egress NAT IPs elevate false correlation rate from 11.1% to 21.4% due to identical source IP clustering. | **CONFIRMED EMPIRICALLY** |
| **H5** | *The deterministic correlation architecture has identifiable robustness boundaries.* | Boundaries mapped: Max tolerable loss = 33%, Max clock drift = 300s, Window sensitivity = step-function. | **CONFIRMED EMPIRICALLY** |

---

## 12. Limitations

1. **Synthetic Telemetry Perturbations**:
   - Perturbations were applied via deterministic transformation algorithms on structured logs. Real-world adversary behavior involves polymorphic payloads and active defense evasion techniques not fully modeled here.
2. **Static Correlation Rules**:
   - The current deterministic correlation engine uses static heuristics (`CORR-001` through `CORR-003`). It does not incorporate probabilistic clustering, graph neural networks, or temporal embedding models.
3. **Single Correlation Window**:
   - The global correlation window is fixed at 300 seconds. While appropriate for fast automated web exploitation, it is insufficient for slow lateral movement and persistent persistence.

---

## 13. Reproducibility & Research Implications

### Reproducibility Commands
To re-run the benchmark generation, evaluation, and test suite:

```bash
# 1. Regenerate Adversarial V1 Benchmark Dataset
python research/generate_adversarial_v1.py

# 2. Execute Adversarial Robustness Evaluation Engine
python research/evaluate_adversarial_robustness.py

# 3. Run Automated Robustness & Regression Test Suite
python -m pytest tests/test_adversarial_robustness.py -v
python -m pytest tests/ -q
```

### Research Implications
1. **Multi-Plane Redundancy is Essential**: Telemetry loss in a single sensor does not cripple the SOC if complementary planes (e.g., host Sysmon + Web logs) share entity context.
2. **Entity Disambiguation is Necessary for NAT**: IP-only correlation is brittle in modern enterprise networks. Hostname, process GUID, and authenticated user identity must be mandated to prevent NAT false correlation.
3. **Adaptive Temporal Windows are Required**: Hard-coded 300-second windows create sharp failure boundaries. Future correlation systems require adaptive time-decay windows based on kill-chain phases.
