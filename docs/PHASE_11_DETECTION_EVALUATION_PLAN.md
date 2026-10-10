# Phase 11 — Detection Effectiveness Evaluation Plan

**Repository**: [https://github.com/Mahesh0019/soc-verison1](https://github.com/Mahesh0019/soc-verison1)  
**Current Phase 10C Commit**: `d4f884b`  
**Frozen Phase 0–9 Research Checkpoint**: `6a153ae17c676e92b7fc7208b374c2646e99b4f6`  
**Status**: Stage 1 Read-Only Audit & Evaluation Design (Awaiting Operator Approval)  

---

## 1. Executive Summary & Objective

The primary objective of **Phase 11** is to evaluate the effectiveness, reliability, and noise characteristics of the existing Mini-SIEM detection and correlation pipeline **before changing any production detection rules or thresholds**.

During Phase 10B/10C live operations, a critical operational anomaly was uncovered:
1. Normal user browsing on the configured victim application generated unexpected **Medium-severity alerts** (`RULE-008`: *"Large request volume burst"*, Alert IDs 232 and 233).
2. The alerting activity escalated into correlated **Incidents** categorized under the `reconnaissance` killchain stage.
3. Simultaneously, all existing automated regression tests passed with a 100% pass rate (`tests/test_detection_validation.py`, `tests/test_rules.py`).

This discrepancy illustrates a foundational security principle: **passing synthetic unit tests does not prove real-world detection effectiveness**. Synthetic tests evaluate isolated, instantaneous bursts (e.g. 65 synthetic requests within milliseconds vs. 10 requests), failing to account for sustained client-side application behaviors such as WebSocket/Socket.IO heartbeat polling, single-page application (SPA) routing, and asset loading.

To eliminate detection noise while maintaining robust coverage against real adversaries, this plan establishes:
- An empirical, reproducible evaluation methodology.
- Distinct labeled test datasets for benign browsing, idle polling, and controlled lab attacks.
- Exact formulas for Precision, Recall, False-Positive Rate (FPR), False-Negative Rate (FNR), and Event-to-Alert Latency.
- An isolated evaluation procedure for `RULE-008` that gathers measured evidence before proposing threshold changes.
- Rigorous safeguards preserving the frozen Phase 0–9 research baseline (`6a153ae`).

---

## 2. Read-Only Codebase Audit Findings

A thorough audit of the detection pipeline was conducted across seven architectural dimensions:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                DETECTION PIPELINE AUDIT                                │
│                                                                                        │
│  [1. Ingestion & Normalization]                                                        │
│   RawLog -> parse_content -> normalize_object -> NormalizedEvent (PostgreSQL)          │
│                                  │                                                     │
│                                  ▼                                                     │
│  [2. Rule Evaluation Engine]                                                           │
│   evaluate_rules_for_events -> evaluate_threshold_rule (RULE-008: 60 reqs / 5m)        │
│                                  │                                                     │
│                                  ▼                                                     │
│  [3. Alert Generation & Evidence Engine]                                               │
│   upsert_alert -> AlertEvent link -> build_evidence_package (SHA-256 hashes)           │
│                                  │                                                     │
│                                  ▼                                                     │
│  [4. Cross-Source Correlation Engine]                                                  │
│   correlate_incidents -> classify_alert_stage ("reconnaissance") -> Incident INC-xxx   │
│                                  │                                                     │
│                                  ▼                                                     │
│  [5. API & Dashboard Queries]                                                          │
│   GET /api/events (Pagination + Noise Filter) | GET /api/alerts | GET /api/incidents   │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### A. Event Ingestion and Normalization
- **Source Files**:
  - [`backend/app/services/ingestion.py:72-106`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/services/ingestion.py#L72-L106) (`persist_events`)
  - [`backend/app/parsers/__init__.py:1-60`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/parsers/__init__.py#L1-L60) (`parse_content`, `normalize_object`)
  - [`backend/app/models/event.py:10-68`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/models/event.py#L10-L68) (`NormalizedEvent`)
- **Mechanism**:
  - Ingestion occurs synchronously via API (`POST /api/ingest/events` or `POST /api/ingest/upload`).
  - Raw payloads are stored in `raw_logs`, mapped into `NormalizedEvent` records, flushed to the database, and immediately evaluated by calling [`evaluate_rules_for_events(db, events)`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/services/ingestion.py#L97).
  - Telemetry from the OWASP Juice Shop connector assigns `event_category = "web"`, `source_type = "WEB"`, and extracts `request_path`, `user_agent`, `status_code`, and `source_ip`.

### B. Detection Rules and Engine
- **Source Files**:
  - [`backend/app/rules/builtin.py:4-367`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/rules/builtin.py#L4-L367) (14 Built-in Detection Rules)
  - [`backend/app/rules/engine.py:13-64`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/rules/engine.py#L13-L64) (`evaluate_rules_for_events`, `evaluate_threshold_rule`)
- **Mechanism**:
  - Rules are categorized into four evaluation types: `threshold`, `sequence_success_after_failures`, `blacklist`, and `pattern`.
  - For `threshold` rules, the engine evaluates each incoming event matching the rule filter, queries `NormalizedEvent` records within the sliding window `[event.timestamp - time_window_minutes, event.timestamp]`, and triggers an alert if `len(related) >= rule.threshold`.
- **Audited Rule Details (`RULE-008`)**:
  - Rule ID: `RULE-008` ([`backend/app/rules/builtin.py:184-205`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/rules/builtin.py#L184-L205))
  - Name: `"Large request volume burst"`
  - Category: `"traffic_anomaly"`
  - Severity: `"medium"`
  - Sliding Window: `5 minutes`
  - Threshold: `60 requests`
  - Filter: `{"event_category": "web"}`
  - Group By: `["source_ip"]`

### C. Alert Generation and Evidence Packaging
- **Source Files**:
  - [`backend/app/rules/engine.py:130-174`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/rules/engine.py#L130-L174) (`upsert_alert`, `link_events`)
  - [`backend/app/models/alert.py:10-48`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/models/alert.py#L10-L48) (`Alert`, `AlertEvent`)
  - [`backend/app/models/evidence.py:10-27`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/models/evidence.py#L10-L27) (`Evidence`)
  - [`backend/app/services/evidence_service.py:74-220`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/services/evidence_service.py#L74-L220) (`build_evidence_package`)
- **Mechanism**:
  - When a threshold is met, `upsert_alert` either updates an existing active alert (`status in ("open", "investigating")`) within the time window or creates a new `Alert` record.
  - Linked events are associated via many-to-many `AlertEvent` join records.
  - The evidence engine builds first-class `Evidence` artifacts with deterministic SHA-256 integrity hashes (`generate_evidence_hash`) across 5 dimensions: triggering event, supporting related events, detection rule specification, entity context, and attack timeline.

### D. Cross-Source Correlation and Incident Promotion
- **Source Files**:
  - [`backend/app/rules/correlation.py:32-140`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/rules/correlation.py#L32-L140) (`classify_alert_stage`, `correlate_incidents`)
  - [`backend/app/models/incident.py:10-50`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/models/incident.py#L10-L50) (`Incident`, `IncidentAlert`)
- **Mechanism**:
  - Alerts touched during ingestion are passed to `correlate_incidents(db, touched_alert_ids)`.
  - In [`backend/app/rules/correlation.py:33-37`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/rules/correlation.py#L33-L37), `ATTACK_STAGES["reconnaissance"]` includes:
    `"large request volume burst"`, `"suspicious user agent"`, and `"high number of 404 responses"`.
  - As a result, any firing of `RULE-008` is automatically classified as the **`reconnaissance`** stage and immediately promoted into an `Incident` (`INC-xxx`) correlated by `source_ip`.

### E. PostgreSQL Persistence
- **Source Files**:
  - [`backend/app/database/base.py`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/database/base.py)
  - [`backend/app/models/event.py`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/models/event.py)
- **Schema & Indexes**:
  - `normalized_events`: Indexed on `timestamp`, `source_ip`, `event_category`, `event_type`, `severity`, `source_type`.
  - `alerts`: Indexed on `rule_id`, `status`, `source_ip`, `first_seen`, `last_seen`.
  - `alert_events`: Unique constraint on `(alert_id, event_id)`.
  - `incidents`: Indexed on `incident_number`, `status`, `severity`, `primary_ip`.

### F. Dashboard Event and Alert Queries
- **Source Files**:
  - [`backend/app/api/events.py:16-95`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/api/events.py#L16-L95) (`list_events`)
  - [`backend/app/api/alerts.py:16-59`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/api/alerts.py#L16-L59) (`list_alerts`, `get_alert`)
  - [`frontend/src/pages/EventsPage.tsx:1-250`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/frontend/src/pages/EventsPage.tsx#L1-L250) (Phase 10C pagination, refresh, and noise toggle)
- **Behavior**:
  - `GET /api/events` provides server-side pagination (`page`, `page_size`) and multi-field keyword search `q`.
  - Phase 10C implemented client-side toggle controls (`hidePollingNoise`) that allow analysts to hide `/socket.io/` events on the active page while preserving underlying telemetry in PostgreSQL.

### G. Existing Research Datasets, Metrics, and Regression Tests
- **Source Files**:
  - [`research/datasets/soc_attack_catalog.json`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/research/datasets/soc_attack_catalog.json) (Catalog of 126 test cases)
  - [`backend/app/services/experiment_service.py:8-16, 711-734`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/services/experiment_service.py#L8-L16) (M0–M6 benchmark comparison framework)
  - [`backend/app/services/validation_service.py:30-440`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/services/validation_service.py#L30-L440) (`BUILTIN_SCENARIOS`)
  - [`tests/test_detection_validation.py:49-165`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/tests/test_detection_validation.py#L49-L165)
- **Key Insight on Existing Tests**:
  - In [`validation_service.py:385-417`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/services/validation_service.py#L385-L417), `SCEN-VOLBURST-POS` tests 65 web events generated in an instantaneous loop, and `SCEN-VOLBURST-NEG` tests 10 web events.
  - The existing test catalog does **not** contain scenarios that simulate sustained 5-minute browser sessions with background polling. Hence, `test_detection_validation.py` passes completely while production experiences false alerts on ordinary browsing.

---

## 3. Labeled Evaluation Scenarios

To evaluate the detection pipeline rigorously, we define standardized, repeatable evaluation scenarios categorized into **Labeled Benign Scenarios** and **Controlled Lab Attack Scenarios**.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                LABELED SCENARIO MATRIX                                 │
├─────────────┬───────────────────────────────────────┬────────────┬─────────────────────┤
│ Scenario ID │ Description                           │ Class      │ Expected Alert      │
├─────────────┼───────────────────────────────────────┼────────────┼─────────────────────┤
│ BENIGN-01   │ Standard browsing + Socket.IO (5m)    │ Benign     │ NONE (RULE-008 = FP)│
│ BENIGN-02   │ Standby tab Socket.IO polling (10m)   │ Benign     │ NONE                │
│ BENIGN-03   │ Rapid static asset loading (60+ imgs) │ Benign     │ NONE                │
│ BENIGN-04   │ Routine admin lookups (/api/users)    │ Benign     │ NONE                │
├─────────────┼───────────────────────────────────────┼────────────┼─────────────────────┤
│ ATTACK-01   │ Aggressive web scraper (>300 reqs/5m) │ Malicious  │ RULE-008            │
│ ATTACK-02   │ Directory brute force / fuzzer (500r) │ Malicious  │ RULE-006 + RULE-008 │
│ ATTACK-03   │ SQL injection search & login payloads │ Malicious  │ RULE-012            │
│ ATTACK-04   │ Path traversal (/ftp/../../etc/passwd)│ Malicious  │ RULE-013            │
│ ATTACK-05   │ Suspicious scanner user agent (sqlmap)│ Malicious  │ RULE-009            │
│ ATTACK-06   │ Multi-stage killchain (crawl -> SQLi) │ Malicious  │ INC-xxx Correlated  │
└─────────────┴───────────────────────────────────────┴────────────┴─────────────────────┘
```

### A. Labeled Benign Scenarios

#### Scenario `BENIGN-01`: Standard User Browsing with Background Polling
- **Description**: A legitimate user visits the victim application, browses the product catalog, submits 2 benign search queries (`"apple"`, `"orange"`), views 3 product details pages, and stays on the page for 5 minutes.
- **Traffic Profile**:
  - 1 initial HTML load + 8 CSS/JS bundles.
  - 15 product image thumbnail requests (`GET /assets/public/images/products/*`).
  - 2 search API calls (`GET /rest/products/search?q=apple`, `GET /rest/products/search?q=orange`).
  - 3 product detail API calls (`GET /rest/products/1`, etc.).
  - 50 Socket.IO polling heartbeats (`GET /health/socket.io/?EIO=4&transport=polling&t=...` every 6 seconds for 300s).
- **Total Requests**: 79 requests in a 5-minute sliding window.
- **Expected Pipeline Behavior**:
  - Ingested Events: 79 `NormalizedEvent` records (`event_category = "web"`).
  - Expected Detections: **0 alerts**. (Current pipeline triggers `RULE-008` as a False Positive).
  - Expected Incidents: **0 incidents**.
  - Evidence Package: None generated.

#### Scenario `BENIGN-02`: Standby / Idle Tab Background Polling
- **Description**: A user leaves an application tab open in the background for 10 minutes without performing any clicks, navigations, or searches.
- **Traffic Profile**:
  - 0 user-initiated navigation or API requests.
  - 100 Socket.IO polling requests (`GET /health/socket.io/?...`) at 6-second intervals over 10 minutes (50 requests per 5-minute sliding sub-window).
- **Total Requests**: 100 requests over 10 minutes (peak 50 req / 5m window).
- **Expected Pipeline Behavior**:
  - Ingested Events: 100 `NormalizedEvent` records.
  - Expected Detections: **0 alerts**. (Must NOT trigger `RULE-008` since 50 < 60 threshold; must NOT trigger `RULE-005` or `RULE-007`).
  - Expected Incidents: **0 incidents**.

#### Scenario `BENIGN-03`: Rapid Static Asset Loading
- **Description**: A user with an empty browser cache visits a gallery or catalog page containing 65 static media resources (icons, badges, images) loaded concurrently within 15 seconds.
- **Traffic Profile**:
  - 65 HTTP `GET` requests to static asset endpoints (`/assets/...`, `/media/...`).
  - HTTP status: 200 OK or 304 Not Modified.
  - Standard browser User-Agent (`Mozilla/5.0...`).
- **Total Requests**: 65 requests within 15 seconds.
- **Expected Pipeline Behavior**:
  - Ingested Events: 65 `NormalizedEvent` records.
  - Expected Detections: **0 alerts**. High-speed loading of legitimate application assets should not be classified as a DoS or scraper attack.

#### Scenario `BENIGN-04`: Benign Administrative Navigation
- **Description**: An authenticated internal administrator performs routine status checks and user account lookups via standard administrative UI screens.
- **Traffic Profile**:
  - `GET /api/users` (200 OK)
  - `GET /health` (200 OK)
  - `GET /rest/admin/application-version` (200 OK)
- **Total Requests**: 5 requests within 2 minutes.
- **Expected Pipeline Behavior**:
  - Ingested Events: 5 `NormalizedEvent` records.
  - Expected Detections: **0 alerts**. Must NOT trip `RULE-007` (sensitive path access threshold is 4 within 10m for specific sensitive paths).

---

### B. Controlled Lab Attack Scenarios (Authorized Lab Only)

#### Scenario `ATTACK-01`: High-Rate Content Scraper / Product Crawler
- **Description**: An automated scraper rapidly enumerates product IDs and downloads catalog data at a rate of 10 requests per second for 30 seconds.
- **Traffic Profile**:
  - 300 sequential HTTP `GET` requests targeting `/rest/products/1` through `/rest/products/300`.
  - User-Agent: Custom scraper or default Python client.
  - Total Duration: 30 seconds (well within 5-minute window).
- **Expected Pipeline Behavior**:
  - Ingested Events: 300 `NormalizedEvent` records (`event_category = "web"`).
  - Expected Detections: **`RULE-008` ("Large request volume burst") MUST FIRE**.
  - Expected Alerts: 1 Alert (Severity: Medium, `event_count >= 60`).
  - Evidence: Anchor triggering event #300, 60+ related events, SHA-256 integrity hash.
  - Incident Correlation: Promoted to `Incident` under stage `reconnaissance`.

#### Scenario `ATTACK-02`: Directory Brute Force and Endpoint Fuzzing
- **Description**: An automated directory fuzzer checks for common backup files, configuration files, and exposed administration portals, generating a high volume of 4xx client errors.
- **Traffic Profile**:
  - 500 HTTP `GET` requests to paths like `/backup.zip`, `/config.json`, `/.git/config`, `/admin.php`, `/wp-login.php`.
  - HTTP status: 404 Not Found and 403 Forbidden.
  - Total Duration: 60 seconds.
- **Expected Pipeline Behavior**:
  - Ingested Events: 500 `NormalizedEvent` records.
  - Expected Detections:
    - **`RULE-005` ("High number of 404 responses") MUST FIRE** (Threshold: 10 in 10m).
    - **`RULE-006` ("Possible directory brute force") MUST FIRE** (Threshold: 15 in 10m).
    - **`RULE-008` ("Large request volume burst") MUST FIRE** (Threshold: 60 in 5m).
  - Expected Alerts: 3 Alerts linked to the fuzzer source IP.
  - Incident Correlation: Multi-alert incident correlated under stages `reconnaissance` and `probing` with correlation strength $\ge 0.70$.

#### Scenario `ATTACK-03`: Web Application SQL Injection Probes
- **Description**: An attacker sends targeted SQL injection payloads via product search queries and authentication endpoints.
- **Traffic Profile**:
  - `GET /rest/products/search?q=' UNION SELECT 1,username,password FROM users--`
  - `POST /rest/user/login` with body `{"email": "' OR '1'='1", "password": "x"}`
  - Status Code: 500 Internal Server Error or 200 OK.
- **Expected Pipeline Behavior**:
  - Ingested Events: 2 `NormalizedEvent` records (`event_category = "web"`).
  - Expected Detections: **`RULE-012` ("SQL injection attempt detected") MUST FIRE**.
  - Expected Alerts: 1 Critical Alert (`event_count >= 1`).
  - Evidence: Triggering event containing SQL signature, payload pattern matching record, confidence 0.95.

#### Scenario `ATTACK-04`: Directory Path Traversal Probes
- **Description**: An attacker attempts to retrieve arbitrary files from the filesystem via parameter manipulation.
- **Traffic Profile**:
  - `GET /ftp/../../../../etc/passwd`
  - `GET /public/images/..%2f..%2f..%2fwin.ini`
- **Expected Pipeline Behavior**:
  - Ingested Events: 2 `NormalizedEvent` records.
  - Expected Detections: **`RULE-013` ("Path traversal attempt detected") MUST FIRE**.
  - Expected Alerts: 1 High severity Alert.

#### Scenario `ATTACK-05`: Automated Vulnerability Scanner User Agent
- **Description**: An automated scanner probes web endpoints using distinct security tool User-Agent headers.
- **Traffic Profile**:
  - 3 HTTP `GET` requests with `User-Agent: sqlmap/1.6#stable (https://sqlmap.org)`.
- **Expected Pipeline Behavior**:
  - Ingested Events: 3 `NormalizedEvent` records.
  - Expected Detections: **`RULE-009` ("Suspicious user agent") MUST FIRE**.
  - Expected Alerts: 1 High severity Alert.

#### Scenario `ATTACK-06`: Multi-Stage Progression Killchain
- **Description**: An attacker executes a chained sequence from reconnaissance to exploitation over 15 minutes:
  1. Content scraping (100 requests in 1m) -> Stage: Reconnaissance
  2. Directory fuzzing (30 404s in 2m) -> Stage: Probing
  3. SQL Injection probe in search -> Stage: Exploitation
  4. Authentication brute force (6 failed logins) -> Stage: Credential Testing
- **Expected Pipeline Behavior**:
  - Expected Alerts: 4 alerts (`RULE-008`, `RULE-005`/`RULE-006`, `RULE-012`, `RULE-001`).
  - Expected Incidents: Exactly 1 single consolidated `Incident` (`INC-xxx`) grouping all 4 alerts by `source_ip`.
  - Multi-stage Progression: Incident reflects stages `["reconnaissance", "probing", "exploitation", "credential_testing"]`.
  - Incident Correlation Strength: $\ge 0.85$.

---

## 4. Evaluation Metrics & Measurement Methodology

### A. Statistical Confusion Matrix Definitions

For each scenario evaluated by the pipeline:
- **True Positive (TP)**: An attack scenario correctly results in the expected alert.
- **False Positive (FP)**: A benign scenario incorrectly results in an alert.
- **True Negative (TN)**: A benign scenario correctly generates zero alerts.
- **False Negative (FN)**: An attack scenario passes through without triggering the expected alert.

### B. Core Evaluation Formulations

$$\text{Precision} = \frac{TP}{TP + FP}$$

$$\text{Recall (Sensitivity)} = \frac{TP}{TP + FN}$$

$$\text{False-Positive Rate (FPR)} = \frac{FP}{FP + TN}$$

$$\text{False-Negative Rate (FNR)} = \frac{FN}{TP + FN} = 1 - \text{Recall}$$

$$F_1\text{-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$

### C. Latency Measurement Breakdown

Detection latency must be decomposed into its constituent stages:

$$T_{\text{total}} = T_{\text{ingest}} + T_{\text{eval}} + T_{\text{evidence}} + T_{\text{correlate}}$$

Where:
- $T_{\text{ingest}}$: Time to parse, normalize, and commit the raw log to `normalized_events` (target: $< 25\,\text{ms}$).
- $T_{\text{eval}}$: Time to evaluate all active rules against the sliding window (target: $< 15\,\text{ms}$).
- $T_{\text{evidence}}$: Time to generate cryptographic evidence records and compute SHA-256 hashes (target: $< 10\,\text{ms}$).
- $T_{\text{correlate}}$: Time to update or create incident entities and recalculate multi-stage progression (target: $< 20\,\text{ms}$).
- **Target Overall Event-to-Alert Latency**: $T_{\text{total}} \le 70\,\text{ms}$ per batch.

---

## 5. Isolated Evaluation Methodology for RULE-008

`RULE-008` is the specific rule responsible for operational noise during Phase 10C. However, **per strict safeguards, its production threshold (60 requests / 5 minutes) must not be changed during this stage**.

### A. Mathematical Analysis of the Existing Noise Phenomenon
The Juice Shop Angular client sends polling requests every **6 seconds**:

$$\text{Polling Rate} = \frac{60\,\text{seconds}}{6\,\text{seconds}} = 10\,\text{requests/minute}$$

Over a 5-minute sliding window:

$$\text{Polling Volume}_{5\text{m}} = 10 \times 5 = 50\,\text{requests}$$

When a user browses the product catalog:
- 1 search query (`/rest/products/search`)
- 15 product image thumbnails (`/assets/public/images/products/*`)
- 5 configuration and scoreboard APIs (`/rest/admin/application-version`, etc.)
- **User Web Requests**: $\sim 21\,\text{requests}$

Total Web Requests in 5 minutes:

$$\text{Total Web Requests} = 50 + 21 = 71\,\text{requests} \ge 60\,\text{threshold}$$

Since `RULE-008` currently filters solely on `event_category == "web"`, ordinary browsing exceeds the threshold by 11 requests, producing an alert and initiating an incident.

### B. Isolated Testing Protocol for RULE-008
Without modifying `backend/app/rules/builtin.py`, the evaluation harness will test `RULE-008` across four distinct parameter axes in a read-only offline test harness:

1. **Baseline Evaluation (Current Production Rule)**:
   - Run `BENIGN-01` (Browsing + Polling): Confirm and record FP = 1.
   - Run `BENIGN-02` (Idle Polling): Record FP = 0 (since 50 < 60).
   - Run `ATTACK-01` (Scraper, 300 reqs): Confirm and record TP = 1.
   - Compute Baseline Metrics: Precision = 0.50, Recall = 1.00, FPR = 0.50.

2. **Offline Parameter Sweep (Simulation Only — No Code Changes)**:
   Evaluate candidate thresholds $T \in \{60, 90, 120, 180, 240, 300\}$:
   - For each threshold $T$, measure:
     - Does `BENIGN-01` (79 reqs) trigger? ($79 \ge T$)
     - Does `ATTACK-01` (300 reqs) trigger? ($300 \ge T$)
     - Does `ATTACK-02` (500 reqs) trigger? ($500 \ge T$)

3. **Offline Filter Hypothesis Evaluation (Simulation Only)**:
   - **Hypothesis 1 (Path Exclusion)**: Exclude paths containing `/socket.io/` or `/health/socket.io/`.
     - `BENIGN-01` non-polling count = 29 reqs ($< 60 \rightarrow \text{TN}$).
     - `ATTACK-01` non-polling count = 300 reqs ($\ge 60 \rightarrow \text{TP}$).
   - **Hypothesis 2 (Rate Derivative / Burst Density)**: Require 60 requests in 60 seconds (1 req/sec) instead of 5 minutes (0.2 req/sec).
     - `BENIGN-01` peak 1-minute volume = 31 reqs ($< 60 \rightarrow \text{TN}$).
     - `ATTACK-01` peak 1-minute volume = 300 reqs ($\ge 60 \rightarrow \text{TP}$).

4. **Explicit Principle**:
   No claim of threshold optimality will be made without measured empirical data from these offline simulation sweeps.

---

## 6. Background Polling Noise Testing Framework

To isolate the specific contribution of Socket.IO polling to system noise:

### A. Polling Duration Test Matrix

| Test ID | Standby Duration | Total Polling Requests | User Requests | Total Volume | Expected RULE-008 (Current) | Expected RULE-008 (Refined) |
|---|---|---|---|---|---|---|
| `POLL-01` | 1 minute | 10 | 0 | 10 | No Alert | No Alert |
| `POLL-02` | 3 minutes | 30 | 0 | 30 | No Alert | No Alert |
| `POLL-03` | 5 minutes | 50 | 0 | 50 | No Alert | No Alert |
| `POLL-04` | 6 minutes | 60 | 0 | 60 | **Edge (60)** | No Alert |
| `POLL-05` | 10 minutes | 100 (50/window) | 0 | 100 | No Alert | No Alert |
| `POLL-06` | 5m + Browsing | 50 | 25 | 75 | **ALERT (FP)** | No Alert |

### B. Health Endpoint Failure Test (`POLL-ERR`)
- Test whether intermittent 404 or 502 responses on `/health/socket.io/?...` cause false alerts under:
  - `RULE-005` ("High number of 404 responses", threshold: 10 in 10m).
  - Inject 15 synthetic 404 responses to `/health/socket.io/` over 5 minutes.
  - Measure whether the rule attributes network/proxy downtime as an active attack.

---

## 7. Test Execution Environments: Offline vs. Live Integration

### A. Offline Testing Harness (Automated, Hermetic, Local)
- **Engine**: `pytest` / Python standard `unittest`.
- **Database**: Isolated in-memory SQLite (`DATABASE_URL=sqlite:///:memory:`).
- **Execution**:
  - Deterministic timestamps generated relative to test fixture time (`t_0`).
  - Zero network access required; completely detached from production Render/Vercel environments.
  - Zero side effects on production PostgreSQL or existing datasets.
- **Harness Scope**:
  - Ingestion parsing validation.
  - Multi-rule condition matching.
  - Parameter sweep simulations for `RULE-008`.
  - Confusion matrix and latency computations.

### B. Separately Authorized Live Integration Tests (Staged, Gated)
- **Scope**: Live testing against the configured victim application (`demo-victim-1.onrender.com`).
- **Prerequisites & Safeguards**:
  - Explicit operator authorization required prior to starting live runs.
  - Restrict traffic origin strictly to authorized IP addresses.
  - Enforce maximum request rate limit ($\le 15\,\text{requests/second}$) to prevent denial-of-service on free-tier Render instances.
  - Automated safety kill switch: Abort test suite immediately if victim application returns HTTP 503/504 for $> 5$ consecutive requests.
  - Use tagged request headers (`X-SOC-Test-Run: Phase-11-Eval-001`) to allow clean segregation of live test telemetry.

---

## 8. Reproducibility, Dataset Labeling, Safety Constraints, and Limitations

### A. Dataset Schema Specification
All evaluation scenarios will be stored in deterministic JSON schema format:

```json
{
  "schema_version": "1.0",
  "scenario_id": "BENIGN-01",
  "name": "Standard Browsing with Polling",
  "ground_truth_label": "benign",
  "duration_seconds": 300,
  "events": [
    {
      "timestamp_offset_ms": 0,
      "source_ip": "198.51.100.101",
      "method": "GET",
      "path": "/",
      "status_code": 200,
      "user_agent": "Mozilla/5.0 ...",
      "event_category": "web"
    }
  ],
  "expected_detections": {
    "alerts_expected": [],
    "should_trigger_rule_008": false,
    "should_promote_incident": false
  }
}
```

### B. Strict Safety Constraints
1. **Zero External Scanning**: No traffic will be directed toward any host outside the explicitly authorized victim lab domain (`demo-victim-1.onrender.com`).
2. **Read-Only Codebase Guarantee**: No source code, rule definitions, configuration files, or database tables will be altered during Stage 1.
3. **No Threshold Declarations Without Measurement**: No rule threshold will be claimed as optimal without documented empirical metrics.
4. **Preserve Production State**: Deployed Render backend and Vercel dashboard must not receive unauthorized synthetic bursts during evaluation design.

### C. Limitations of Synthetic and Offline Testing
- **Unit Test Limitations**: A unit test with 10 synthetic requests cannot reflect the temporal density and varied paths of an actual interactive browser session.
- **Clock Drift & Network Jitter**: In offline tests, event timestamps are mathematically exact; in live environments, network buffering and batch ingestion may cause events to arrive in micro-bursts.
- **Single-Host Topology**: In the current free-tier environment, victim traffic originates from client IPs that may be shared across multiple simulated users if behind NAT.

---

## 9. Regression Checks Against Frozen Phase 0–9 Research Artifacts

To maintain academic and operational integrity, all research artifacts created during Phases 0–9 are frozen at checkpoint `6a153ae17c676e92b7fc7208b374c2646e99b4f6`.

### A. Protected Artifact Inventory
The following directories and files must remain byte-for-byte identical to commit `6a153ae`:
- `research/datasets/soc_attack_catalog.json`
- `research/datasets/adversarial_v1/`
- `research/datasets/ai_analyst_v1/`
- `research/datasets/cross_source_v1/`
- `research/datasets/dataset_v2/`
- `research/datasets/network_v1/`
- `research/datasets/sysmon_v1/`
- `research/datasets/threat_hunting_v1/`
- `research/scripts/`
- `research/results/`

### B. Automated Verification Command
Before and after any subsequent test execution, run:
```powershell
git diff --exit-code 6a153ae17c676e92b7fc7208b374c2646e99b4f6 HEAD -- research/
```
If this command outputs any diff or exits with a non-zero status code, execution must **immediately halt**.

---

## 10. Phase 11 Stage 1 Inspection Summary

### A. Source Files Audited
| Category | File Path | Lines Inspected | Key Architectural Observation |
|---|---|---|---|
| **Ingestion** | `backend/app/services/ingestion.py` | L40–L106 | Synchronous rule evaluation upon event insertion |
| **Rules Engine** | `backend/app/rules/builtin.py` | L184–L205 | `RULE-008`: 60 web requests / 5m by `source_ip` |
| **Rules Engine** | `backend/app/rules/engine.py` | L43–L64, L130–L174 | Sliding window event query and alert upsert logic |
| **Correlation** | `backend/app/rules/correlation.py` | L32–L67, L113–L140 | `RULE-008` mapped to stage `reconnaissance` |
| **Evidence** | `backend/app/services/evidence_service.py` | L74–L220 | Cryptographic SHA-256 evidence package generation |
| **Validation** | `backend/app/services/validation_service.py` | L385–L417 | Synthetic burst test (65 vs 10 reqs) misses sustained sessions |
| **Research** | `backend/app/services/experiment_service.py` | L690–L735 | TP, FP, TN, FN, Precision, Recall, and Latency math |
| **API** | `backend/app/api/events.py` | L16–L95 | Server-side pagination and multi-field keyword filtering |
| **Frontend** | `frontend/src/pages/EventsPage.tsx` | L26–L110 | Phase 10C pagination, manual refresh, and noise toggle |

### B. Summary of Empirical Evidence
1. **Audit Evidence**: Normal browsing creates ~71 requests in 5 minutes (50 polling + 21 browsing), triggering `RULE-008` (threshold 60).
2. **Correlation Evidence**: `RULE-008` alerts escalate directly into multi-stage Incidents (`reconnaissance`).
3. **Testing Evidence**: Existing validation tests (`test_detection_validation.py`) pass with 100% success because they test 10 requests (synthetic negative) or 65 requests in 1 second (synthetic positive), never evaluating sustained 5-minute sessions.
4. **Research Baseline Evidence**: `git diff 6a153ae17c676e92b7fc7208b374c2646e99b4f6 HEAD -- research/` produces 0 diff lines, confirming the baseline remains intact.

---

## 11. Acceptance Criteria & Approval Gate

The following criteria must be reviewed and accepted prior to advancing to Stage 2 (Evaluation Execution):

1. **Scenario Definitions**: Benign scenarios (`BENIGN-01` to `BENIGN-04`) and attack scenarios (`ATTACK-01` to `ATTACK-06`) accurately capture production operational realities.
2. **Evaluation Metrics**: Definitions of Precision, Recall, FPR, FNR, and Latency are accepted as the standard scorecard.
3. **RULE-008 Isolation**: Clear agreement that `RULE-008` remains untouched in production and will be evaluated via offline simulation sweeps.
4. **Safety & Research Guardrails**: Zero modifications to production, zero attacks against public hosts, and 100% preservation of frozen checkpoint `6a153ae`.

> **STOP**: Stage 1 design is complete. Awaiting user review and authorization before proceeding to Stage 2 execution.
