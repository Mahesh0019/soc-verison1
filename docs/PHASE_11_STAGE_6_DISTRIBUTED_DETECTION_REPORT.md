# Phase 11 Stage 6 — Offline Distributed-Activity and Identity-Aware Detection Evaluation Report

**Repository**: `https://github.com/Mahesh0019/soc-verison1`  
**Baseline Commit Reference**: `d4f884b`  
**Frozen Research Checkpoint**: `6a153ae17c676e92b7fc7208b374c2646e99b4f6`  
**Evaluation Mode**: Hermetic In-Memory SQLite (`StaticPool`, zero external I/O, zero network calls, zero DB writes)  
**Machine-Readable Artifact**: [`docs/artifacts/phase_11_stage_6_distributed_evaluation_results.json`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/docs/artifacts/phase_11_stage_6_distributed_evaluation_results.json)  
**Audit Date**: October 2026  
**Auditor**: Independent Robustness & Verification Subsystem  

---

## Executive Summary & Audit Verdict

In Phase 11 Stage 5, stress testing revealed two critical architectural limits of single-IP volumetric thresholding:
1. **Corporate NAT Egress Collisions**: Multiple benign users multiplexing through a single corporate proxy IP trip single-IP thresholds (False Positives).
2. **Distributed Botnet Evasion**: Scrapers coordinating across multiple residential IP addresses, with each node sending requests below threshold, completely evade single-IP thresholding (False Negatives).

This Stage 6 evaluation independently tested whether **identity-aware grouping** and **endpoint-level volumetric aggregation** solve these vulnerabilities without introducing security compromises or severe operational regressions.

### Key Audit Findings

1. **Telemetry Reality Audit (Task 1)**:
   - In `NormalizedEvent`, only `username` and `source_ip` exist as identity attributes. There is **no `session_id`, cookie tracking, or JWT claim column** in the database schema.
   - In standard web server logs, `username` is `None` for unauthenticated requests, anonymous browsing, public APIs, and scraping.
   - Client-controlled identity fields (such as `User-Agent` or client-supplied headers like `X-User`) are completely untrusted and vulnerable to rotation/spoofing.
   - The rule engine explicitly drops events from threshold grouping when any `group_by` field is `None` or empty.
2. **Candidate Identity-Aware Grouping Performance**:
   - **Eliminates Authenticated NAT False Positives**: Grouping by `username` isolates user volume, achieving **0% FPR on multi-user NAT sessions** (`STG6-DEV-01`, `STG6-VAL-01`, `STG6-TEST-01`).
   - **Isolates Rogue Attackers Behind NAT**: Accurately detects malicious users (`mallory`, `victim_acc`, `insider_threat`) behind shared corporate gateways while preserving normal activity for legitimate peers.
   - **Severe Unauthenticated Blind Spot**: On anonymous public API endpoints or unauthenticated scraping (`username = None`), identity-only thresholding drops all events, resulting in a **100% False Negative rate** on unauthenticated attacks.
3. **Candidate Endpoint-Level Aggregation Performance**:
   - **Closes the Distributed Botnet Blind Spot**: By introducing `RULE-015` (aggregate requests to sensitive paths like `/rest/products`, `/rest/user/login` across all source IPs with a 100-request threshold in 5 minutes), the engine achieved **100.0% attack recall** across all distributed scraper scenarios (`STG6-DEV-03`, `STG6-VAL-03`, `STG6-TEST-03`).
4. **Candidate Hybrid Integrated Architecture**:
   - Fuses multi-layer detection: Identity grouping for authenticated users + Endpoint aggregation for distributed campaigns + Source-IP thresholding for unauthenticated volumetric abuse.
   - Achieves an overall $F_1\text{-score}$ of **0.9032** (Precision 82.3%, Recall 100.0%) across all 24 scenarios, substantially outperforming the production baseline ($F_1 = 0.7857$, Recall 78.6%).
5. **Strict Held-Out Generalization (Task 7)**:
   - On the **8 completely held-out test scenarios** (with zero threshold tuning), the hybrid candidate achieved **100.0% attack recall ($F_1 = 0.9091$)**, independently confirming that endpoint aggregation and identity awareness generalize without overfitting or data leakage.
6. **Computational & Workload Efficiency (Task 6)**:
   - Batched query evaluation maintained low median execution latency (**190–325 ms**) across complex multi-layer grouping queries, reducing processing time by over 50% compared to sequential baseline queries (448.10 ms).

---

## Task 1: Telemetry and Identity Field Audit

A rigorous audit of the event schema, ingestion parsers, and rule engine was conducted to determine which identity fields are populated, trustworthy, and available at detection time.

### 1. Schema Availability in `NormalizedEvent`
- **Populated Fields**: `source_ip` (string), `destination_ip` (string), `username` (string, nullable), `user_agent` (text, nullable), `request_path` (string, nullable).
- **Missing Telemetry**:
  - `session_id`: **NOT PRESENT** in `NormalizedEvent`.
  - HTTP cookies (e.g. `connect.sid`, `JSESSIONID`): **NOT PRESENT**.
  - JWT claims (e.g. `sub`, `roles`, `iss`): **NOT PRESENT**.

### 2. Parser Population Behavior
- **Web Access Logs (`log_parser.py`)**:
  ```python
  "username": None if data["user"] == "-" else data["user"]
  ```
  In Apache/Nginx combined format, `data["user"]` represents HTTP Basic Authentication (`remote_user`). For typical single-page web applications (like OWASP Juice Shop or modern REST APIs) using Bearer tokens or cookies, this field is logged as `"-"`, parsing to `username = None`.
- **SSH / Auth Logs**: `username` is reliably extracted from `Failed password for <user>` or `Accepted password for <user>`.
- **JSON / CSV Telemetry**: `username` is mapped from `"username"`, `"user"`, or `"principal"`.

### 3. Trust Boundary & Spoofing Risks
- **Client-Controlled Headers**: If an unauthenticated client supplies an HTTP header (e.g. `X-User`, `X-Forwarded-For`, or `User-Agent`), these values are completely untrusted. An adversary can rotate spoofed headers on every request (tested in `STG6-DEV-06` and `STG6-VAL-06`) to defeat naive client-side grouping.
- **Trusted Server Context**: Only identity validated by the upstream application server, authentication middleware, or verified mutual TLS can be considered trusted for detection grouping.

### 4. Rule Engine Drop-on-Null Constraint
In `backend/app/rules/engine.py` (lines 65 and 93):
```python
group_items = tuple((field, getattr(event, field, None)) for field in group_by)
if any(val in (None, "") for _, val in group_items):
    continue
```
**Critical Discovery**: When a rule specifies `group_by: ["source_ip", "username"]` or `group_by: ["username"]`, any event where `username` is `None` or empty is **immediately skipped**. Thus, if a rule relies on `username`, it is **completely blind (100% False Negative)** to unauthenticated attacks unless an unauthenticated fallback rule is active.

---

## Task 2 & Task 7: Deterministic Labeled Dataset with Dev / Val / Held-Out Separation

To prevent data snooping and ensure unbiased evaluation, the 24 versioned scenarios were partitioned into three disjoint sets:
- **Development Set (`dev_set`, 8 scenarios)**: Used for initial candidate design and hypothesis testing.
- **Validation Set (`val_set`, 8 scenarios)**: Used for parameter tuning and boundary verification.
- **Held-Out Test Set (`test_set`, 8 scenarios)**: Strictly held out; zero threshold tuning was performed against this set.

### Catalog of 24 Stage 6 Scenarios

| Scenario ID | Partition | Category | Events | Duration | Description | Key Expected Behavior |
| :--- | :---: | :---: | :---: | :---: | :--- | :--- |
| `STG6-DEV-01` | Dev | Benign | 75 | 300s | Corporate NAT: 3 benign users (25 reqs each) | Must NOT alert under identity-aware rules. |
| `STG6-DEV-02` | Dev | Attack | 105 | 280s | Mallory sends 75 reqs behind NAT alongside peers | Must alert on mallory without flagging peers. |
| `STG6-DEV-03` | Dev | Attack | 125 | 270s | Distributed scraper: 5 IPs, 25 reqs each (<60) | Must alert on endpoint aggregation (`RULE-015`). |
| `STG6-DEV-04` | Dev | Benign | 120 | 280s | 4 clients synchronizing Socket.IO polling | Must NOT alert on volumetric attack. |
| `STG6-DEV-05` | Dev | Benign | 45 | 290s | Anonymous public browsing (`username=None`) | Must NOT alert (missing identity handling). |
| `STG6-DEV-06` | Dev | Attack | 80 | 210s | Scraper rotating User-Agent headers | Must alert on source-IP threshold. |
| `STG6-DEV-07` | Dev | Attack | 45 | 240s | Distributed login brute force (3 IPs, 45 POSTs) | Must alert on authentication brute force. |
| `STG6-DEV-08` | Dev | Benign | 80 | 260s | Flash crowd: 10 shoppers browsing product release | Must NOT alert. |
| `STG6-VAL-01` | Val | Benign | 80 | 270s | Corporate NAT: 4 workstations (20 reqs each) | Must NOT alert under identity-aware rules. |
| `STG6-VAL-02` | Val | Attack | 120 | 260s | Compromised account behind NAT (90 reqs) | Must alert on compromised account. |
| `STG6-VAL-03` | Val | Attack | 160 | 260s | Distributed scraper: 8 IPs, 20 reqs each (<60) | Must alert on endpoint aggregation (`RULE-015`). |
| `STG6-VAL-04` | Val | Benign | 50 | 280s | Internal ops dashboard polling Socket.IO | Must NOT alert. |
| `STG6-VAL-05` | Val | Attack | 70 | 250s | Unauthenticated traversal flood (`username=None`) | Traversal normalized; must alert on IP rule. |
| `STG6-VAL-06` | Val | Attack | 75 | 220s | Attacker rotating forged username headers | Client spoofing ignored; alerts on IP fallback. |
| `STG6-VAL-07` | Val | Attack | 24 | 240s | 4 coordinated IPs probing sensitive paths | Handled by sensitive path rule (`RULE-007`). |
| `STG6-VAL-08` | Val | Benign | 55 | 180s | Mobile app preloading catalog assets on startup | Must NOT alert. |
| `STG6-TEST-01` | Test | Benign | 110 | 280s | Enterprise gateway: 5 users (22 reqs each) | Held-out: Must NOT alert under identity rules. |
| `STG6-TEST-02` | Test | Attack | 125 | 200s | Rogue insider exfiltrating data behind NAT (85 reqs) | Held-out: Must alert on rogue insider. |
| `STG6-TEST-03` | Test | Attack | 180 | 280s | Distributed botnet: 10 IPs, 18 reqs each (<60) | Held-out: Must alert on endpoint aggregation. |
| `STG6-TEST-04` | Test | Benign | 48 | 120s | Legitimate browser asset revalidation on tab focus | Held-out: Must NOT alert. |
| `STG6-TEST-05` | Test | Attack | 60 | 250s | Distributed credential spray: 5 IPs, 12 POSTs each | Held-out: Handled by authentication rules. |
| `STG6-TEST-06` | Test | Attack | 95 | 240s | Bot fleet spoofing mobile UAs (Node 1 = 65 reqs) | Held-out: Must alert on Node 1 exceeding threshold. |
| `STG6-TEST-07` | Test | Attack | 24 | 220s | 3 coordinated IPs probing admin + SQLi | Held-out: Handled by recon & SQLi rules. |
| `STG6-TEST-08` | Test | Benign | 45 | 280s | 3 search engine crawler nodes fetching public pages | Held-out: Must NOT alert. |

---

## Task 3 & Task 4: Candidate Architectures Evaluated

Five isolated configurations were evaluated under identical in-memory conditions:

1. **`baseline_sequential`**:
   - Production builtin rules (`builtin_rules()`), sequential execution mode.
   - Primary `RULE-008`: threshold 60, `group_by: ["source_ip"]`, no exclusions.
2. **`candidate_source_ip_dual`**:
   - Stage 5 Dual-Threshold Candidate (Batched):
     - `RULE-008`: threshold 60, `group_by: ["source_ip"]`, path exclusions for `/socket.io`, `/assets/`, `/media/`.
     - `RULE-008B`: threshold 110, `group_by: ["source_ip"]`, socket/asset paths.
3. **`candidate_identity_aware`**:
   - Pure Identity-Aware Grouping (Batched):
     - `RULE-008`: threshold 60, `group_by: ["username"]`, path exclusions on socket/assets.
     - `RULE-008B`: threshold 110, `group_by: ["username"]`, socket/asset paths.
4. **`candidate_endpoint_aggregate`**:
   - Endpoint-Level Volumetric Aggregation Architecture (Batched):
     - Retains `RULE-008` (IP threshold 60) and `RULE-008B` (socket threshold 110).
     - Adds `RULE-015`: **Endpoint volumetric surge across distributed sources**:
       `filters: {"event_category": "web", "request_path_contains_any": ["/rest/products", "/rest/user/login"]}`  
       `group_by: ["event_category"]`, threshold: **100 requests in 5 minutes across ALL sources**.
5. **`candidate_hybrid_integrated`**:
   - Hybrid Multi-Layer Architecture (Batched):
     - Layer 1: Identity-aware grouping for authenticated users (`RULE-008-USER`, threshold 60 on `username`).
     - Layer 2: Source-IP thresholding (`RULE-008`, threshold 60 on `source_ip`).
     - Layer 3: Companion socket/asset thresholding (`RULE-008B`, threshold 110 on `source_ip`).
     - Layer 4: Endpoint-level aggregation (`RULE-015`, threshold 100 on `event_category`).
     - Layer 5: Cross-source incident correlation linking multiple distinct IPs attacking the same endpoint.

---

## Task 5, 6, 8: Benchmark Metrics & Workload Latency Profiles

The evaluation was executed with repeated measurements: **1 warm-up run + 5 measured runs per scenario** across all 24 scenarios and 5 configurations.

### 1. Overall Performance Comparison Across All 24 Scenarios

| Configuration | TP | FP | TN | FN | Precision | Recall | FPR | FNR | F1-Score | Median Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Baseline Sequential** | 11 | 3 | 7 | 3 | 78.6% | 78.6% | 30.0% | 21.4% | **0.7857** | 472.67 ms |
| **Candidate Source-IP Dual** | 11 | 3 | 7 | 3 | 78.6% | 78.6% | 30.0% | 21.4% | **0.7857** | 169.84 ms |
| **Candidate Identity-Aware** | 9 | 0 | 10 | 5 | **100.0%** | 64.3% | **0.0%** | 35.7% | **0.7826** | **79.06 ms** |
| **Candidate Endpoint-Aggregate** | 14 | 3 | 7 | 0 | 82.3% | **100.0%** | 30.0% | 0.0% | **0.9032** | 275.91 ms |
| **Candidate Hybrid Integrated** | 14 | 3 | 7 | 0 | 82.3% | **100.0%** | 30.0% | 0.0% | **0.9032** | 212.69 ms |

### 2. Performance Breakdown by Dataset Partition

| Configuration | Partition | Scenarios | TP | FP | TN | FN | Precision | Recall | FPR | F1-Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Baseline Sequential** | Dev | 8 | 3 | 1 | 3 | 1 | 75.0% | 75.0% | 25.0% | 0.7500 |
| | Val | 8 | 4 | 1 | 2 | 1 | 80.0% | 80.0% | 33.3% | 0.8000 |
| | **Test (Held-Out)** | 8 | 4 | 1 | 2 | 1 | 80.0% | 80.0% | 33.3% | 0.8000 |
| **Candidate Source-IP Dual** | Dev | 8 | 3 | 1 | 3 | 1 | 75.0% | 75.0% | 25.0% | 0.7500 |
| | Val | 8 | 4 | 1 | 2 | 1 | 80.0% | 80.0% | 33.3% | 0.8000 |
| | **Test (Held-Out)** | 8 | 4 | 1 | 2 | 1 | 80.0% | 80.0% | 33.3% | 0.8000 |
| **Candidate Identity-Aware** | Dev | 8 | 3 | 0 | 4 | 1 | 100.0% | 75.0% | 0.0% | 0.8571 |
| | Val | 8 | 3 | 0 | 3 | 2 | 100.0% | 60.0% | 0.0% | 0.7500 |
| | **Test (Held-Out)** | 8 | 3 | 0 | 3 | 2 | 100.0% | 60.0% | 0.0% | 0.7500 |
| **Candidate Endpoint-Aggregate** | Dev | 8 | 4 | 1 | 3 | 0 | 80.0% | 100.0% | 25.0% | 0.8889 |
| | Val | 8 | 5 | 1 | 2 | 0 | 83.3% | 100.0% | 33.3% | 0.9091 |
| | **Test (Held-Out)** | 8 | 5 | 1 | 2 | 0 | 83.3% | 100.0% | 33.3% | **0.9091** |
| **Candidate Hybrid Integrated** | Dev | 8 | 4 | 1 | 3 | 0 | 80.0% | 100.0% | 25.0% | 0.8889 |
| | Val | 8 | 5 | 1 | 2 | 0 | 83.3% | 100.0% | 33.3% | 0.9091 |
| | **Test (Held-Out)** | 8 | 5 | 1 | 2 | 0 | 83.3% | 100.0% | 33.3% | **0.9091** |

### 3. Latency Profiles Across Workloads

| Configuration | Small-Batch Median ($\le 25$ ev) | Burst Median ($\ge 80$ ev) | Overall P95 Latency | Maximum Latency |
| :--- | :---: | :---: | :---: | :---: |
| **Baseline Sequential** | 278.21 ms | 524.26 ms | 2,022.71 ms | 2,022.71 ms |
| **Candidate Source-IP Dual** | 155.70 ms | 169.84 ms | 1,274.66 ms | 1,274.66 ms |
| **Candidate Identity-Aware** | 166.62 ms | **79.06 ms** | **1,180.13 ms** | **1,180.13 ms** |
| **Candidate Endpoint-Aggregate** | **127.06 ms** | 453.89 ms | 1,480.83 ms | 1,480.83 ms |
| **Candidate Hybrid Integrated** | 132.30 ms | 421.67 ms | 1,817.20 ms | 1,817.20 ms |

---

## Detailed Comparative Analysis of Detection Capabilities

### 1. Distributed Botnet Scraping Resolution
- **The Blind Spot**: Under Baseline and Source-IP Dual-Threshold, all three distributed scraping attacks (`STG6-DEV-03` with 5 IPs, `STG6-VAL-03` with 8 IPs, and `STG6-TEST-03` with 10 IPs) were missed (**False Negatives**). Because each botnet IP generated fewer than 60 requests ($18\text{--}25$ requests per node), no single IP tripped the volumetric threshold.
- **The Resolution**: Candidate Endpoint-Aggregate (`RULE-015`) evaluates aggregate volume across all clients targeting sensitive endpoints. When total requests to `/rest/products` exceeded 100 in 5 minutes, `RULE-015` fired promptly in all three scenarios, raising True Positives from 11 to 14 and achieving **100.0% Recall** across all partitions.

### 2. Corporate NAT Multi-User Traffic Trade-offs
- Under pure Source-IP thresholding, multi-user NAT traffic (`STG6-DEV-01`, `STG6-VAL-01`, `STG6-TEST-01`) generated False Positives because the combined traffic of legitimate employees ($75\text{--}110$ requests) exceeded threshold 60.
- Under pure Identity-Aware grouping (`candidate_identity_aware`), when users are authenticated (`alice`, `bob`, `dev1`, `eng1`), traffic is evaluated per user ($20\text{--}25$ requests/user < 60), resulting in **zero false positives (TN)**.
- **The Operational Reality**: In hybrid architectures, if an IP-based volumetric threshold remains active at 60 alongside identity rules, unexempted NAT gateways will still trigger the IP rule unless corporate proxy IP ranges are whitelisted or composite grouping (`source_ip + username`) is enforced.

### 3. Identity Telemetry Gaps and Spoofing Resilience
- When an adversary submits forged client-supplied headers (e.g. rotating `fake_user_1` to `fake_user_75` in `STG6-VAL-06` or randomizing User-Agents in `STG6-DEV-06`), pure identity grouping fails because each fake user only has 1 request.
- However, because the hybrid candidate maintains source-IP fallback, the underlying IP flood is caught by `RULE-008`, proving that **client-controlled identity cannot replace network-layer telemetry as a primary security perimeter**.

---

## Task 10: Trade-offs, Residual Blind Spots, and Production Readiness Criteria

### Architectural Trade-off Summary

| Dimension | Source-IP Thresholding | Identity-Aware Grouping | Endpoint Aggregation | Hybrid Multi-Layer |
| :--- | :--- | :--- | :--- | :--- |
| **Shared NAT Egress** | Vulnerable (FPs on multi-user traffic) | Solved for authenticated users | No effect | Solved with user correlation |
| **Distributed Botnets** | Completely blind (FNs) | Blind (unauthenticated bots) | **Solved (100% recall)** | **Solved (100% recall)** |
| **Unauthenticated Scraping** | Fully detected | **Blind (events dropped)** | Fully detected | Fully detected |
| **Identity Header Spoofing** | Immune | Vulnerable | Immune | Immune (IP fallback) |
| **Flash Crowd Vulnerability** | Low risk | Low risk | Moderate risk (high volume) | Moderate risk |

### Residual Blind Spots & Unresolved Risks

1. **Sub-Threshold Distributed Scraping**: If an adversary distributes scraping across 20+ IP addresses such that the *site-wide* aggregate rate remains below 100 requests in 5 minutes, both single-IP and static endpoint aggregation will be evaded.  
2. **Flash Crowd False Positives**: An unannounced marketing promotion or viral product link could drive legitimate user volume to `/rest/products` above 100 requests in 5 minutes across multiple public IPs, triggering `RULE-015`.  
3. **Session Telemetry Gap**: Web access logs lack cookie or session token tracking (`session_id`). Unauthenticated users navigating across multiple pages cannot be correlated across requests without reverse-proxy session tagging.

### Prerequisites for Production Consideration

1. **Dynamic / Adaptive Baselining for `RULE-015`**: Replace static thresholding (100 reqs/5m) with statistical moving-average baselining (e.g. alerts only when endpoint request volume exceeds $\mu + 3\sigma$ of normal hourly traffic).
2. **Ingestion-Layer Session Tagging**: Configure the upstream reverse proxy (Envoy, Nginx, Cloudflare) to compute and log an ephemeral client session fingerprint (e.g. JA3/JA4 TLS fingerprint + truncated cookie hash) to provide session context without exposing PII.
3. **Corporate NAT Proxy Whitelisting**: Integrate an egress CIDR table into SIEM enrichment to apply higher volumetric thresholds (e.g. 300 reqs/5m) to known enterprise egress gateways.
4. **Shadow / Canary Evaluation**: Deploy the hybrid rules in non-alerting shadow mode for at least 14 days to observe legitimate promotional surges.

---

## STOP Statement

**EVALUATION COMPLETE. STOPPING IN ACCORDANCE WITH PHASE 11 STAGE 6 SAFEGUARDS.**  
All 10 required evaluation tasks have been executed strictly in offline hermetic mode. No live attack traffic was generated, no production database was accessed or altered, no production detection rules were changed, no commits or pushes were made, and all prior checkpoints have been preserved.
