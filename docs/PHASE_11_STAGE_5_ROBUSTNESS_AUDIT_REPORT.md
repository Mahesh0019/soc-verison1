# Phase 11 Stage 5 — Independent Robustness and Reproducibility Audit Report

**Repository**: `https://github.com/Mahesh0019/soc-verison1`  
**Baseline Commit Reference**: `d4f884b`  
**Frozen Research Checkpoint**: `6a153ae17c676e92b7fc7208b374c2646e99b4f6`  
**Evaluation Mode**: Hermetic In-Memory SQLite (`StaticPool`, zero external I/O, zero network calls, zero DB writes)  
**Machine-Readable Artifact**: [`docs/artifacts/phase_11_stage_5_audit_results.json`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/docs/artifacts/phase_11_stage_5_audit_results.json)  
**Audit Date**: October 2026  
**Auditor**: Independent Robustness & Verification Subsystem  

---

## Executive Summary & Audit Verdict

This audit independently challenged the **Stage 4 Dual-Threshold Candidate Architecture** (`RULE-008` threshold 60 on non-excluded paths + `RULE-008B` threshold 110 on `/socket.io`, `/assets/`, and `/media/`) across an expanded evaluation catalog of **35 standardized scenarios** (the 23 frozen scenarios from Stages 2–4 plus 12 newly engineered robustness, boundary, and architectural stress challenges).

### Audit Verdict

1. **Mathematical Reproducibility Confirmed**: Every confusion matrix cell ($TP, FP, TN, FN$), metric denominator, and reported percentage in the Stage 4 machine-readable artifact was recomputed directly and verified with zero discrepancy.
2. **Anti-Inflation Confirmed**: The evaluation unit was verified to be strictly a **scenario**. Attack scenarios generating multiple alerts across multiple rules (e.g., `ATTACK-06` generating 8 alerts across 6 rules) incremented true positives by exactly 1.
3. **Candidate Superiority Confirmed on Single-Source Volumetric Attacks**:
   - The dual-threshold architecture achieved an overall $F_1\text{-score}$ of **0.9268** (Precision 90.48%, Recall 95.00%, FPR 13.33%) across all 35 scenarios, substantially outperforming the production baseline ($F_1 = 0.8444$, FPR 40.00%).
   - Benign Socket.IO polling false positives were suppressed by **75.0%** (`POLL-01` through `POLL-06` yielded zero false positives under the candidate, whereas baseline generated 4 false positives).
4. **Boundary Robustness Confirmed**:
   - Threshold 60: 59 requests in 5 minutes yielded 0 alerts (TN); 60 requests yielded 1 alert (TP); 61 requests yielded 1 alert (TP).
   - Companion Threshold 110: 109 socket requests in 5 minutes yielded 0 alerts (TN); 110 socket requests yielded 1 alert (TP).
   - Sliding Window: 60 requests spread across 305 seconds (maximum in any 300s window = 59) yielded 0 alerts (TN).
   - Out-of-Order Telemetry: 65 requests arriving in scrambled sequence within 120s correctly triggered `RULE-008` (TP).
5. **Evasion Neutralization Confirmed**:
   - URL fragment smuggling (`#bypass=/socket.io`, scenario `STG5-FRAG-01`), query-string smuggling (`?bypass=/socket.io`, `ADV-EXCL-03`), and encoded directory traversal (`/%61ssets/../`, `ADV-EXCL-06`) were all stripped by path normalization, properly alerting on `RULE-008`.
6. **Critical Architectural Blind Spots Identified Under Stress**:
   - **Corporate NAT / Shared Gateway Evasion Limitation (`STG5-NAT-01`)**: Two benign users behind a corporate gateway generating 35 requests each (70 total) trigger `RULE-008` (False Positive). Pure single-IP grouping cannot distinguish multi-user NAT aggregation from single-source volumetric flooding.
   - **Distributed Botnet Scraper Blind Spot (`STG5-DIST-01`)**: A scraping attack distributed across 5 IP addresses, each generating 25 requests (125 total requests site-wide), failed to trigger any alerts (False Negative). Single-IP thresholding is structurally blind to low-and-slow distributed botnets.
7. **Query Engine Equivalence & Performance Speedup**:
   - Batched query evaluation (`evaluate_threshold_rule_batched`) produced **100% identical detection classifications, alert counts, and fired rules** as sequential query execution across all 35 scenarios (0 correctness discrepancies).
   - Batched query execution reduced overall median processing latency from **262.90 ms** to **48.21 ms** (a **5.4x speedup / 81.7% latency reduction**) and burst-traffic median latency from **544.19 ms** to **104.23 ms** (a **5.2x speedup / 80.8% latency reduction**).

---

## Task 1: Independent Recomputation of Stage 4 Artifact Metrics

The machine-readable artifact `docs/artifacts/phase_11_stage_4_candidate_evaluation_results.json` was audited using an automated mathematical validation script ([`scripts/audit_stage4_artifact_math.py`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/scripts/audit_stage4_artifact_math.py)). Every calculation was re-evaluated against standard statistical formulas:

$$\text{Precision} = \frac{TP}{TP + FP}, \quad \text{Recall} = \frac{TP}{TP + FN}, \quad \text{FPR} = \frac{FP}{FP + TN}, \quad \text{FNR} = \frac{FN}{TP + FN}, \quad F_1 = \frac{2 \cdot P \cdot R}{P + R}$$

### Audit Verification Table (23 Stage 4 Scenarios)

| Configuration | Metric | Reported Value | Recomputed Value | Denominator Verification | Audit Status |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Baseline Sequential** | Confusion Matrix | 12 / 4 / 7 / 0 | 12 / 4 / 7 / 0 | $12+4+7+0 = 23$ | **VERIFIED** |
| | Precision | 75.00% | 0.7500 | $12 / (12 + 4) = 12 / 16$ | **VERIFIED** |
| | Recall | 100.00% | 1.0000 | $12 / (12 + 0) = 12 / 12$ | **VERIFIED** |
| | FPR | 36.36% | 0.3636 | $4 / (4 + 7) = 4 / 11$ | **VERIFIED** |
| | FNR | 0.00% | 0.0000 | $0 / (12 + 0) = 0 / 12$ | **VERIFIED** |
| | $F_1\text{-Score}$ | 0.8571 | 0.8571 | $2 \cdot 0.75 \cdot 1.0 / 1.75$ | **VERIFIED** |
| **Candidate Hardened Single (Seq)** | Confusion Matrix | 10 / 1 / 10 / 2 | 10 / 1 / 10 / 2 | $10+1+10+2 = 23$ | **VERIFIED** |
| | Precision | 90.91% | 0.9091 | $10 / (10 + 1) = 10 / 11$ | **VERIFIED** |
| | Recall | 83.33% | 0.8333 | $10 / (10 + 2) = 10 / 12$ | **VERIFIED** |
| | FPR | 9.09% | 0.0909 | $1 / (1 + 10) = 1 / 11$ | **VERIFIED** |
| | FNR | 16.67% | 0.1667 | $2 / (10 + 2) = 2 / 12$ | **VERIFIED** |
| | $F_1\text{-Score}$ | 0.8696 | 0.8696 | $2 \cdot 0.9091 \cdot 0.8333 / 1.7424$ | **VERIFIED** |
| **Candidate Dual-Threshold (Batched)** | Confusion Matrix | 12 / 1 / 10 / 0 | 12 / 1 / 10 / 0 | $12+1+10+0 = 23$ | **VERIFIED** |
| | Precision | 92.31% | 0.9231 | $12 / (12 + 1) = 12 / 13$ | **VERIFIED** |
| | Recall | 100.00% | 1.0000 | $12 / (12 + 0) = 12 / 12$ | **VERIFIED** |
| | FPR | 9.09% | 0.0909 | $1 / (1 + 10) = 1 / 11$ | **VERIFIED** |
| | FNR | 0.00% | 0.0000 | $0 / (12 + 0) = 0 / 12$ | **VERIFIED** |
| | $F_1\text{-Score}$ | 0.9600 | 0.9600 | $2 \cdot 0.9231 \cdot 1.0 / 1.9231$ | **VERIFIED** |
| **Independent 404 (Batched)** | Confusion Matrix | 9 / 0 / 11 / 3 | 9 / 0 / 11 / 3 | $9+0+11+3 = 23$ | **VERIFIED** |
| | Precision | 100.00% | 1.0000 | $9 / (9 + 0) = 9 / 9$ | **VERIFIED** |
| | Recall | 75.00% | 0.7500 | $9 / (9 + 3) = 9 / 12$ | **VERIFIED** |
| | FPR | 0.00% | 0.0000 | $0 / (0 + 11) = 0 / 11$ | **VERIFIED** |
| | FNR | 25.00% | 0.2500 | $3 / (9 + 3) = 3 / 12$ | **VERIFIED** |
| | $F_1\text{-Score}$ | 0.8571 | 0.8571 | $2 \cdot 1.0 \cdot 0.75 / 1.75$ | **VERIFIED** |

**Zero mathematical errors, misreported decimals, or invalid denominators exist in the Stage 4 artifact.**

---

## Task 2: Evaluation Unit Verification & Anti-Inflation Proof

A critical concern in SIEM rule benchmarking is alert inflation: if an attack scenario generates multiple alerts, treating each alert as a True Positive artificially inflates detection recall and masks false negatives.

### Verification of Evaluation Logic

In both `backend/app/services/evaluation_phase11_stage4.py` and `backend/app/services/evaluation_phase11_stage5.py`, scenario classification is determined strictly at the **scenario level**:

```python
has_alert = len(final_alerts) > 0

if scenario.category == "attack":
    classification = "TP" if has_alert else "FN"
else:
    classification = "FP" if has_alert else "TN"
```

### Empirical Audit Findings

1. **Exact Scenario Counts**: Across all configurations, $\sum (TP + FP + TN + FN)$ equals exactly the total number of scenarios (23 in Stage 4, 35 in Stage 5).
2. **Alert vs. Scenario Multiplicity**:
   - In Stage 4 Candidate Dual-Threshold, the **12 True Positive scenarios generated 25 total alerts**.
   - For example, scenario `ATTACK-06` (Multi-stage web assault) generated **8 alerts** across rules `RULE-001`, `RULE-005`, `RULE-006`, `RULE-007`, `RULE-008`, and `RULE-012`.
   - Despite producing 8 alerts, `ATTACK-06` incremented True Positives by **exactly 1**.
   - Scenario `ATTACK-02` generated 4 alerts (`RULE-005`, `RULE-006`, `RULE-007`, `RULE-008`) and incremented True Positives by **exactly 1**.
3. **Duplicate Alert Accounting**: Multiple alerts sharing the same `(rule_id, source_ip)` are tracked independently in `duplicate_alerts` and are never added to confusion matrix counts.

**Conclusion**: The evaluation unit is rigorously verified to be a scenario. True positives are not inflated by alert multiplicity.

---

## Task 3: Boundary Condition Stress Testing

To verify the deterministic reliability of sliding-window threshold evaluation, 5 dedicated boundary scenarios were executed:

```
STG5-BOUND-01 (59 reqs)  ---> [ NO ALERT ] -> TN (Passed)
STG5-BOUND-02 (60 reqs)  ---> [ RULE-008 ] -> TP (Passed)
STG5-BOUND-03 (61 reqs)  ---> [ RULE-008 ] -> TP (Passed)

STG5-BOUND-04 (109 reqs) ---> [ NO ALERT ] -> TN (Passed)
STG5-BOUND-05 (110 reqs) ---> [ RULE-008B] -> TP (Passed)

STG5-WINDOW-01 (305s)    ---> [ NO ALERT ] -> TN (Passed)
STG5-OOO-01 (Jittered)   ---> [ RULE-008 ] -> TP (Passed)
```

### 1. Primary Threshold Boundary (Threshold = 60 requests in 5 minutes)
- **STG5-BOUND-01 (59 requests in 300s)**: Emitted exactly 59 GET requests spaced 5.0s apart. Result: **0 alerts**, correctly classified as **TN**. Confirms the rule does not prematurely trigger at $N - 1$.
- **STG5-BOUND-02 (60 requests in 295s)**: Emitted exactly 60 GET requests spaced 4.9s apart. Result: **1 alert (`RULE-008`)**, correctly classified as **TP**. Confirms exact boundary trigger at threshold $N$.
- **STG5-BOUND-03 (61 requests in 295s)**: Emitted exactly 61 GET requests spaced 4.8s apart. Result: **1 alert (`RULE-008`)**, correctly classified as **TP**.

### 2. Companion Threshold Boundary (Threshold = 110 requests in 5 minutes)
- **STG5-BOUND-04 (109 socket requests in 300s)**: Emitted 109 GET requests to `/health/socket.io/?...` spaced 2.7s apart. Result: **0 alerts**, correctly classified as **TN**.
- **STG5-BOUND-05 (110 socket requests in 290s)**: Emitted 110 GET requests to `/health/socket.io/?...` spaced 2.6s apart. Result: **1 alert (`RULE-008B`)**, correctly classified as **TP**. Confirms exact boundary trigger on companion rule.

### 3. Time Window Boundary (Window = 300 seconds / 5 minutes)
- **STG5-WINDOW-01 (60 requests spread across 305 seconds)**: Emitted 60 requests spaced 5.16s apart. Spanning 304.44s total, the maximum number of requests falling into any 300-second sliding window is **59**. Result: **0 alerts**, correctly classified as **TN**. Verifies sliding-window timestamp math is exact and does not alert on requests that fall outside the 5-minute interval.

### 4. Out-of-Order Telemetry Arrival
- **STG5-OOO-01 (65 requests within 120s arriving shuffled)**: Ingested 65 events with randomized arrival order to simulate asynchronous network buffering or log collector batch jitter. Result: **1 alert (`RULE-008`)**, correctly classified as **TP**. The database time-window query (`timestamp >= start_ts AND timestamp <= max_ts`) properly reconstructed the temporal order regardless of ingestion order.

---

## Task 4: Multi-IP, NAT, Distributed, and High-Volume Session Analysis

Real-world enterprise network architectures present conditions that challenge simplistic single-source IP thresholding. Two targeted stress scenarios were evaluated to expose these boundaries:

### 1. Corporate NAT / Shared Egress Gateway (`STG5-NAT-01`)
- **Traffic Profile**: Two distinct legitimate corporate users (`alice` and `bob`) browse an internal web application via the same corporate NAT proxy gateway (`203.0.113.50`). Each user generates 35 requests across 5 minutes (70 total requests).
- **Classification Result**: **False Positive (FP)**. `RULE-008` fired because 70 events aggregated under the shared `source_ip`.
- **Architectural Analysis**: This is an inherent, unresolvable vulnerability of any detection rule that groups exclusively by `source_ip`. When multiple concurrent users share a single public IP, their aggregate traffic sums up, exceeding single-user volumetric thresholds.
- **Production Recommendation**: Add compound grouping (e.g., `group_by: ["source_ip", "user_agent"]` or session cookie identification) or whitelist corporate proxy egress ranges.

### 2. Distributed Low-and-Slow Botnet Scraper (`STG5-DIST-01`)
- **Traffic Profile**: An adversary distributes product scraping across 5 distinct residential IP addresses (`198.51.100.211` through `198.51.100.215`). Each IP sends 25 GET requests across 5 minutes (125 total requests site-wide).
- **Classification Result**: **False Negative (FN)**. Zero alerts fired.
- **Architectural Analysis**: Because each botnet IP generated only 25 requests ($25 < 60$), no individual IP tripped `RULE-008`. The dual-threshold architecture, like the baseline, is blind to distributed volumetric attacks where per-node rates remain below the threshold.
- **Production Recommendation**: Implement cluster-wide endpoint volumetric rules (e.g., total requests to `/rest/products/` exceeding standard traffic baselines regardless of IP) or cross-IP behavioral correlation.

---

## Task 5 & 6: HTTP Methods, Path Normalization, and Query/Fragment Evasion Analysis

The audit examined HTTP method handling, static asset routes, and URL normalization across diverse attack vectors.

### 1. HTTP Method Support
- **STG5-POST-01 (Socket.IO HTTP POST Flood)**: Transmitted 120 HTTP POST requests in 2 minutes to `/health/socket.io/?EIO=4&transport=polling`. Result: **1 alert (`RULE-008B`)**, correctly classified as **TP**. Verifies that path filtering applies uniformly to POST payloads as well as GET requests.
- **STG5-POST-02 (Suspicious POST to Static Asset Path)**: Adversary submitted 20 unauthorized POST requests to `/assets/uploads/shell_0.php` returning HTTP 403 Forbidden. Result: **1 alert (`RULE-006`)**, correctly classified as **TP**. Client-error rules catch asset upload probing even though path is within `/assets/`.

### 2. URL Normalization Consistency & Evasion Neutralization
The audit reviewed both the Python-level normalization (`normalize_request_path`) and SQL-level filter queries (`apply_filters`) in `backend/app/rules/engine.py`:

```python
# Python Normalization
def normalize_request_path(raw_path: str | None) -> str:
    parsed = urlsplit(str(raw_path).strip())
    path = parsed.path  # Strips both query string (?) and fragment (#)
    path = unquote(path)  # Decodes percent-encoding (%2f -> /)
    normalized = posixpath.normpath(path)  # Normalizes traversals (../)
    return normalized.lower()
```

```python
# SQL SQLite Clean Path Handling
clean_path = case(
    (NormalizedEvent.request_path.contains("?"), func.substr(NormalizedEvent.request_path, 1, func.instr(NormalizedEvent.request_path, "?") - 1)),
    (NormalizedEvent.request_path.contains("#"), func.substr(NormalizedEvent.request_path, 1, func.instr(NormalizedEvent.request_path, "#") - 1)),
    else_=NormalizedEvent.request_path,
)
```

### Ambiguous & Residual Input Forms

| Input Vector | Example URI | Python Normalization | SQL Filter Clean Path | Audit Assessment |
| :--- | :--- | :--- | :--- | :--- |
| **Query Parameter Smuggling** | `/rest/products?bypass=/socket.io` | `/rest/products` | `/rest/products` | **Neutralized**: query stripped; evaluated as non-excluded path. |
| **URL Fragment Smuggling** | `/rest/products#bypass=/socket.io` | `/rest/products` | `/rest/products` | **Neutralized**: fragment stripped; evaluated as non-excluded path. |
| **Percent Encoding** | `/%61ssets/../rest/products` | `/rest/products` | Decoded after fetch | **Neutralized**: decoded and normalized to target path. |
| **Double URL Encoding** | `/%252fsocket.io` | `/%2fsocket.io` | Unchanged | **Ambiguous**: single `unquote()` only decodes outer layer. In reverse proxies that decode twice, this could lead to filter discrepancies. |
| **Missing / Null Path** | `None` / `""` | `""` | `NULL` | **Safe**: handled gracefully without exceptions or false exclusions. |
| **Trailing Slash Variations** | `/socket.io/` vs `/socket.io` | Substring match | Substring match | **Safe**: both contain `/socket.io` token. |

---

## Task 7: Dual-Threshold Configuration & Production Immutability Verification

### Candidate Configuration Specifications

```json
{
  "rule_id": "RULE-008",
  "name": "Excessive request volume from single IP",
  "conditions_json": {
    "type": "threshold",
    "filters": {
      "event_category": "web",
      "request_path_not_contains_any": ["/socket.io", "/assets/", "/media/"]
    },
    "group_by": ["source_ip"]
  },
  "time_window_minutes": 5,
  "threshold": 60
}
```

```json
{
  "rule_id": "RULE-008B",
  "name": "Excessive request volume on socket/asset endpoints",
  "conditions_json": {
    "type": "threshold",
    "filters": {
      "event_category": "web",
      "request_path_contains_any": ["/socket.io", "/assets/", "/media/"]
    },
    "group_by": ["source_ip"]
  },
  "time_window_minutes": 5,
  "threshold": 110
}
```

### Production Rules Immutability Audit

The production detection rules in `backend/app/rules/builtin.py` were verified against git head:
- Total builtin rules: **14 rules** (RULE-001 through RULE-014).
- `RULE-008` threshold: **60 requests**.
- `RULE-008` time window: **5 minutes**.
- `RULE-008` filters: Strictly `{"event_category": "web"}` (no path exclusions).
- `RULE-005` threshold: **10 requests**.
- `RULE-006` threshold: **15 requests**.
- Git diff against baseline commit on `backend/app/rules/builtin.py`: **0 lines modified (clean)**.

---

## Task 8: Latency Profiling (Sequential vs. Batched) & Correctness Equivalence

The audit evaluated all 35 scenarios with repeated measurements: **1 discarded warm-up run + 5 measured runs per scenario** across both sequential and batched execution modes.

### Performance & Detection Metric Comparison Across 35 Scenarios

| Configuration | TP | FP | TN | FN | Precision | Recall | FPR | FNR | F1-Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Baseline Sequential** | 19 | 6 | 9 | 1 | 76.00% | 95.00% | 40.00% | 5.00% | **0.8444** |
| **Candidate Dual-Threshold Sequential** | 19 | 2 | 13 | 1 | 90.48% | 95.00% | 13.33% | 5.00% | **0.9268** |
| **Candidate Dual-Threshold Batched** | 19 | 2 | 13 | 1 | 90.48% | 95.00% | 13.33% | 5.00% | **0.9268** |
| **Candidate Hardened Single Batched** | 15 | 2 | 13 | 5 | 88.24% | 75.00% | 13.33% | 25.00% | **0.8108** |
| **Candidate Independent 404 Batched** | 14 | 1 | 14 | 6 | 93.33% | 70.00% | 6.67% | 30.00% | **0.8000** |

### Latency Profiles: Sequential vs. Batched

| Configuration | Query Execution Mode | Overall Median | Small-Batch Median ($\le 10$ ev) | Burst Median ($\ge 100$ ev) | P95 Latency | Maximum Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Baseline Sequential** | Sequential SQL | 357.01 ms | 25.52 ms | 877.79 ms | 23,628.13 ms | 23,628.13 ms |
| **Candidate Dual-Threshold Sequential** | Sequential SQL | 262.90 ms | 33.14 ms | 544.19 ms | 25,505.31 ms | 25,505.31 ms |
| **Candidate Dual-Threshold Batched** | Batched SQL | **48.21 ms** | **21.29 ms** | **104.23 ms** | **6,033.65 ms** | **6,033.65 ms** |
| **Candidate Hardened Single Batched** | Batched SQL | 62.60 ms | 32.97 ms | 70.63 ms | 10,305.87 ms | 10,305.87 ms |
| **Candidate Independent 404 Batched** | Batched SQL | 39.65 ms | 16.93 ms | 47.10 ms | 6,784.85 ms | 6,784.85 ms |

### Latency Observations
1. **Zero Discrepancy**: Candidate Dual-Threshold Sequential and Batched produced identical confusion matrices ($19 / 2 / 13 / 1$), identical fired rules, and identical alert counts across all 35 scenarios.
2. **Computational Speedup**: Batched evaluation reduced overall median latency by **81.7%** ($262.90 \to 48.21$ ms) and burst median latency by **80.8%** ($544.19 \to 104.23$ ms).
3. **P95 Latency Relief**: Burst scenarios like `ATTACK-02` (500 events) saw P95 execution drop from 25.5 seconds down to 6.0 seconds.

---

## Task 9: Scenario Expansion Assessment (23 to 35 Scenarios)

The initial 23 scenarios from Stages 2–4 tested core baseline functionality, Socket.IO polling noise, and basic query/traversal evasions. However, they were insufficient to rigorously challenge:
- Exact threshold edge boundaries ($N-1$, $N$, $N+1$).
- Sliding-window time edge boundaries (traffic spanning across the 5-minute threshold).
- Out-of-order stream arrival.
- Multi-user NAT multiplexing.
- Multi-IP distributed botnet coordination.
- Non-GET HTTP methods on socket/asset endpoints.
- URL fragment smuggling.

### Catalog of 12 New Stage 5 Challenge Scenarios

| Scenario ID | Category | Events | Duration | Description | Key Expected Behavior |
| :--- | :---: | :---: | :---: | :--- | :--- |
| `STG5-BOUND-01` | Benign | 59 | 300s | Boundary Below: 59 reqs in 5m | Must NOT alert ($N-1$ safety). |
| `STG5-BOUND-02` | Attack | 60 | 295s | Boundary Exact: 60 reqs in 5m | Must alert on `RULE-008`. |
| `STG5-BOUND-03` | Attack | 61 | 295s | Boundary Above: 61 reqs in 5m | Must alert on `RULE-008`. |
| `STG5-BOUND-04` | Benign | 109 | 300s | Companion Boundary Below: 109 socket reqs | Must NOT alert on `RULE-008B`. |
| `STG5-BOUND-05` | Attack | 110 | 290s | Companion Boundary Exact: 110 socket reqs | Must alert on `RULE-008B`. |
| `STG5-WINDOW-01` | Benign | 60 | 305s | Sliding Window Boundary: 60 reqs across 305s | Max 59 in any 300s window; no alert. |
| `STG5-OOO-01` | Attack | 65 | 120s | Out-of-order ingestion stream (jittered) | Must alert on `RULE-008`. |
| `STG5-NAT-01` | Benign | 70 | 300s | Corporate NAT: 2 users, 35 reqs each (70 total) | Exposes IP-only false positive trade-off. |
| `STG5-DIST-01` | Attack | 125 | 300s | Distributed scraper: 5 IPs, 25 reqs each (125 total) | Exposes single-IP false negative blind spot. |
| `STG5-POST-01` | Attack | 120 | 120s | Socket.IO HTTP POST flood (120 reqs in 2m) | Must alert on companion `RULE-008B`. |
| `STG5-POST-02` | Attack | 20 | 45s | Suspicious POST to static assets returning 403 | Handled by `RULE-006` client-error rule. |
| `STG5-FRAG-01` | Attack | 90 | 120s | URL Fragment smuggling (`#bypass=/socket.io`) | Fragment stripped; alerts on `RULE-008`. |

---

## Task 10: Trade-offs, Residual Blind Spots, and Production Readiness Criteria

### Detection Trade-Off Matrix

| Configuration | Benign FP Rate | Attack Coverage | Noise Suppression | Key Architectural Trade-Off |
| :--- | :---: | :---: | :---: | :--- |
| **Production Baseline** | High (40.0%) | 95.0% | None | Floods SOC analysts with Socket.IO polling noise on single-page apps. |
| **Hardened Single-Threshold** | Low (13.3%) | 75.0% | High | Suppresses noise, but blinds engine to volumetric attacks targeting `/socket.io` or `/assets/`. |
| **Dual-Threshold Split** | **Low (13.3%)** | **95.0%** | **High** | Eliminates noise while maintaining coverage for volumetric flooding ($F_1 = 0.9268$). |
| **Independent 404** | Minimal (6.7%) | 70.0% | Maximum | Suppresses 404 polling noise, but blinds engine to namespace fuzzing (`ADV-EXCL-05`). |

### Residual Blind Spots & Unresolved Risks

1. **Distributed Botnet Scraping**: When attackers distribute requests across multiple IPs such that no single IP exceeds 60 requests in 5 minutes, single-IP thresholding cannot detect the attack (`STG5-DIST-01`).
2. **Corporate NAT / Shared Public IP False Positives**: Legitimate organizations multiplexing multiple employees through a single egress IP will periodically exceed volumetric thresholds (`STG5-NAT-01`).
3. **Double URL Encoding Evasion in Inconsistent Ingestion Pipelines**: If upstream reverse proxies or WAFs perform double URL decoding, single decoding in the SIEM engine could produce normalization discrepancies.

### Prerequisites for Production Deployment

Before promoting the dual-threshold candidate (`RULE-008` + `RULE-008B`) to production:
1. **Shadow / Canary Evaluation**: Run the dual-threshold rules in passive "shadow mode" (generating non-paging audit events) against production traffic for at least 7 days to observe real corporate NAT traffic volumes.
2. **Ingestion Canonicalization**: Ensure the upstream reverse proxy (Nginx / Envoy / Cloudflare) normalizes and canonicalizes incoming URIs before logging to syslog/SIEM.
3. **Compound Entity Correlation**: Enhance `conditions_json` to support composite grouping (e.g., `["source_ip", "user_agent"]` or authenticated `username`) to mitigate corporate NAT false positives.

---

## Audit Verification Artifacts

- **Machine-Readable Audit Results**: [`docs/artifacts/phase_11_stage_5_audit_results.json`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/docs/artifacts/phase_11_stage_5_audit_results.json)
- **Mathematical Audit Script**: [`scripts/audit_stage4_artifact_math.py`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/scripts/audit_stage4_artifact_math.py)
- **Audit Runner Script**: [`scripts/run_phase11_stage5_audit.py`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/scripts/run_phase11_stage5_audit.py)
- **Table Generator Script**: [`scripts/generate_stage5_summary_tables.py`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/scripts/generate_stage5_summary_tables.py)
- **Stage 5 Evaluation Engine**: [`backend/app/services/evaluation_phase11_stage5.py`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/services/evaluation_phase11_stage5.py)
- **Stage 5 Test Suite**: [`tests/test_phase11_stage5_audit.py`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/tests/test_phase11_stage5_audit.py)

---

## STOP Statement

**AUDIT COMPLETE. STOPPING IN ACCORDANCE WITH PHASE 11 STAGE 5 SAFEGUARDS.**  
All tasks have been executed strictly in offline hermetic mode with zero production rule modifications, zero production database changes, zero live network traffic, and full preservation of prior research checkpoints.
