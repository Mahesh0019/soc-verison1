# THREAT_HUNTING_V1: Controlled Threat Hunting and Closed-Loop Detection Engineering Lifecycle

## 1. Architecture

Phase 9 establishes a closed-loop Detection Engineering Lifecycle operating on top of the multi-source Mini-SIEM platform. The architecture couples retrospective threat hunting with rigorous detection engineering, empirical quality gates, and regression protection:

```
[ Multi-Source Telemetry (Web, Auth, Zeek, Sysmon) ]
                       │
                       ▼
            [ Real-Time Detection Engine ]
                       │
                       ▼
           [ Incident Correlation & Graph ]
                       │
                       ▼
          [ Analyst Investigation Workspace ]
                       │
                       ▼
             [ Threat Hunting Engine ]
          (HUNT-001..010, Parameterized Queries)
                       │
                       ▼
              [ Detection Gap Model ]
             (Identified, Scoped, Audited)
                       │
                       ▼
        [ Candidate Rule Generation (DRAFT) ]
                       │
                       ▼
           [ Detection Quality Gate ]
       (Positive, Negative, Mutation, Fields)
                       │
                       ▼
        [ Historical Regression Verification ]
 (Dataset V2, Network V1, Sysmon V1, Cross-Source V1)
                       │
                       ▼
       [ Versioned Production Rule (ACTIVE) ]
                       │
                       ▼
       [ Immutable Version History (Audit) ]
```

The system preserves strict separation between exploratory hunting queries and production rule deployment:
- **Threat Hunting Layer**: Executes bounded, parameterized search queries without side effects on production alerts.
- **Gap Identification**: Captures observed behaviors supported by telemetry that lack active detection capabilities.
- **Candidate Detections**: Created exclusively in `DRAFT` status; cannot be promoted directly to `ACTIVE`.
- **Validation & Regression Gate**: Enforces quantitative precision, recall, FPR thresholds, and checks against frozen historical corpora before promotion.
- **Rule Lifecycle & Versioning**: Maintains immutable version lineage (`RuleVersionHistory`), ensuring all activations, mutations, and deprecations are auditable.

---

## 2. Threat-Hunting Methodology

Threat hunting is conducted via structured, hypothesis-driven exploration rather than unconstrained ad-hoc queries:
1. **Hypothesis Formulation**: Formulates clear pre-conditions describing potential adversary behaviors, affected telemetry data sources, and expected observable indicators.
2. **Telemetry Scope & Query Bounding**:
   - Parameterized SQL / ORM filters prevent code execution or SQL injection.
   - Strict time bounding (maximum sliding window of 30 days, default 7 days).
   - Strict result bounding (maximum 200 records returned).
   - Cross-incident isolation: when scoped to an incident, only telemetry bound to that incident's correlation chain is queryable.
   - RBAC: restricted to users with `analyst`, `secops`, or `admin` authorization.
3. **Observation & Evidence Extraction**: Correlates returned events with existing alerts and incidents to extract concrete forensic evidence references.
4. **Deterministic Classification**: Evaluates telemetry against the taxonomy in Section 5 to separate true gaps from false leads or existing rule coverage.

---

## 3. Hunt Hypotheses (HUNT-001 through HUNT-010)

The evaluation defines 10 controlled hunting scenarios grounded in realistic telemetry:

| Hunt ID | Title | Telemetry Sources | Hypothesis |
| :--- | :--- | :--- | :--- |
| **HUNT-001** | Suspicious PowerShell followed by network connection | `SYSMON`, `ZEEK` | Adversaries leverage `powershell.exe` to execute staging commands and immediately initiate outbound socket connections to unknown external IPs. |
| **HUNT-002** | Web exploitation followed by child process creation | `WEB`, `SYSMON` | Web shell or remote command execution exploits on IIS or Nginx spawn child command interpreters (`cmd.exe`, `powershell.exe`). |
| **HUNT-003** | Rare process communicating with uncommon destination port | `ZEEK`, `SYSMON` | Command-and-control backdoors bind to non-standard high ports (e.g., 8443, 9001, 31337) to evade egress filtering. |
| **HUNT-004** | DNS anomaly followed by outbound connection | `ZEEK` | DNS tunneling or fast-flux domains resolve suspicious hostnames immediately preceding outbound data exfiltration. |
| **HUNT-005** | Repeated authentication failures followed by successful login | `AUTH` | Brute force or password spraying attacks exhibit multiple failed authentication events before achieving a successful logon. |
| **HUNT-006** | Process creation in temporary directories | `SYSMON` | Malware droppers, unpackers, and weaponized attachments frequently execute secondary payloads from `AppData\Local\Temp` or `/tmp`. |
| **HUNT-007** | Suspicious parent-child process relationship | `SYSMON` | Office documents or scripting hosts spawning interactive shells indicate weaponized macro execution. |
| **HUNT-008** | Multiple low-severity alerts forming a higher-level sequence | `ALERT`, `INCIDENT` | Low-and-slow reconnaissance and probing behaviors individually produce low-severity alerts that aggregate into a coordinated intrusion. |
| **HUNT-009** | Potential attack behavior with incomplete telemetry | `SYSMON`, `ZEEK` | Events indicating anomalous activity lack executable names, hashes, or destination endpoints due to logging pipeline dropouts. |
| **HUNT-010** | Benign administrative behavior resembling an attack | `SYSMON`, `AUTH` | Routine enterprise maintenance, backup jobs, and PowerShell diagnostic commands mimic adversary execution patterns. |

---

## 4. Dataset Methodology

The benchmark dataset is deterministically generated under `research/datasets/threat_hunting_v1/`:
- **Total Scenarios**: 60 controlled scenarios across 10 evaluation categories (6 scenarios per category).
- **Split Distribution**:
  - `dev_scenarios.json`: 30 scenarios (DEV)
  - `validation_scenarios.json`: 15 scenarios (VALIDATION)
  - `held_out_test_scenarios.json`: 15 scenarios (HELD_OUT_TEST — strictly frozen; not used for rule tuning)
- **Manifest Integrity**: SHA-256 digests recorded in `manifest.json`.
- **Evaluation Categories**:
  1. `covered_behavior`: Threats already detected by active baseline rules (e.g., SQLi, repeated failed logins).
  2. `genuine_detection_gap`: Real threat activity supported by telemetry but missed by all baseline rules.
  3. `false_lead`: Benign administrative diagnostic commands resembling attack commands.
  4. `insufficient_telemetry`: Events with dropped or truncated core fields (null process, null port).
  5. `benign_lookalike`: Legitimate updater or background software mimicking dropper execution.
  6. `multi_source_sequence`: Correlated multi-stage events across web and endpoint layers.
  7. `adversarial_mutation`: Path separator and casing evasions attempting to bypass static keyword filters.
  8. `existing_rule_duplication`: Test cases verifying that candidate rule generation detects existing rules.
  9. `weak_evidence`: Transient single-event anomalies lacking secondary confirmation.
  10. `conflicting_telemetry`: Contradictory telemetry signals between endpoint and network layers.

---

## 5. Detection-Gap Definition

A **Detection Gap** is formally defined as:
> *Observed telemetry supports malicious or anomalous behavior consistent with a known attack technique, but existing active detection rules do not adequately identify or alert on the activity.*

A formal detection gap record requires:
- `gap_id`: Unique identifier (e.g., `GAP-HUNT-006`)
- `hunt_id`: Originating threat hunt
- `affected_source`: Telemetry source (e.g., `SYSMON`)
- `affected_behavior`: Description of unmonitored behavior
- `severity`: Assessed impact (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- `existing_rule_ids`: List of active rules evaluated that failed to trigger
- `missing_detection_capability`: Technical root-cause specification
- `evidence_refs`: Pointers to observed telemetry events
- `mitre_mapping`: Technique ID, name, and tactic
- `candidate_rule_id`: Associated candidate detection once engineered
- `status`: Lifecycle state (`IDENTIFIED`, `UNDER_REVIEW`, `CANDIDATE`, `VALIDATING`, `ACCEPTED`, `REJECTED`, `DUPLICATE`)

Duplicate protection ensures that redundant gap requests for previously analyzed behaviors are marked `DUPLICATE` rather than creating redundant rules.

---

## 6. Candidate-Rule Methodology

When a detection gap is confirmed, the engineering pipeline synthesizes a candidate detection specification:
- Rule identifier: `CAND-{gap_id}`
- Status: Strictly initialized to `DRAFT`.
- Metadata: Name, description, source, category, severity, author, confidence, MITRE mapping.
- Detection logic: Declarative condition structure (`pattern`, `threshold`, or `sequence`).
- Test suite:
  - `positive_cases`: Attack scenarios that must trigger detection.
  - `negative_cases`: Benign baseline operations that must not trigger detection.
  - `missing_field_cases`: Partial telemetry schemas that must be handled gracefully without exceptions.
  - `mutation_cases`: Casing and syntax variations to ensure robust matching.

Candidate detections remain inert in `DRAFT` until they satisfy the validation gate.

---

## 7. Rule Lifecycle

The detection engineering state machine enforces sequential quality progression:

```
[ DRAFT ] ──────────► [ TESTING ] ──────────► [ VALIDATING ] ──────────► [ ACTIVE ]
    │                     │                         │                         │
    ▼                     ▼                         ▼                         ▼
[ DEPRECATED ] ◄──────────────────────────────────────────────────────────────┘
```

- **DRAFT**: Initial formulation from a confirmed gap. Inactive in SIEM engine.
- **TESTING**: Deployed to staging test harness for automated unit testing.
- **VALIDATING**: Evaluated against the Quality Gate test suite and historical regression corpora.
- **ACTIVE**: Promoted to production detection engine with incremented version and active database rule.
- **DEPRECATED**: Retired from production when superseded or obsolete; disables alerts from the rule.

Transitions require explicit authorized analyst requests and record immutable audit records in `RuleVersionHistory`.

---

## 8. Quality Gates

Before any candidate rule transitions from `VALIDATING` to `ACTIVE`, it must pass the automated Quality Gate:
1. **Positive Attack Cases**: Recall on positive attack cases must be 1.0 (0 false negatives).
2. **Negative Benign Cases**: FPR on benign lookalikes must be 0.0 (0 false positives).
3. **Missing-Field Cases**: Must process null or truncated telemetry fields gracefully without raising exceptions.
4. **Adversarial Mutation Cases**: Must correctly trigger on syntax-mutated variants.
5. **Quantitative Thresholds**:
   - Precision $\ge 0.90$
   - Recall $\ge 0.90$
   - FPR $\le 0.05$
   - Detection latency $\le 50.0\text{ ms}$

Rules failing any quality check cannot be activated.

---

## 9. Regression Methodology

To prevent detection engineering from introducing alert fatigue or breaking baseline fidelity, all candidate rules are evaluated against historical corpora:
- `Dataset V2` (Web/Auth baseline)
- `Network V1` (Zeek telemetry)
- `Sysmon V1` (Windows endpoint telemetry)
- `Cross-Source V1` (Unified correlation)
- `Adversarial V1` (Evasion benchmarks)

The regression engine measures before vs. after deltas:
$$\Delta\text{TP},\quad \Delta\text{FP},\quad \Delta\text{FN},\quad \Delta\text{TN},\quad \Delta\text{F1},\quad \Delta\text{FPR},\quad \Delta\text{Latency}$$

**Acceptance Criteria**:
- $\Delta\text{FP} \le 1$
- $\Delta\text{FPR} \le 0.02$
- $\Delta\text{F1} \ge 0.000$

If a candidate rule increases recall on new attacks but introduces false positive alarms on benign baseline traffic, the trade-off is recorded in a `RegressionEvaluationRecord` and promotion is blocked.

---

## 10. Results: System A vs. System B

The controlled experiment evaluated System A (Baseline SIEM rules only) against System B (Closed-Loop Hunting + Validated Candidate Rules):

### DEV + VALIDATION Split (45 Scenarios)

| Metric | System A (Baseline) | System B (Closed-Loop) | Delta ($\Delta$) |
| :--- | :---: | :---: | :---: |
| **True Positives (TP)** | 16 | 22 | **+6** |
| **False Positives (FP)** | 0 | 0 | **0** |
| **False Negatives (FN)** | 6 | 0 | **-6** |
| **True Negatives (TN)** | 23 | 23 | **0** |
| **Precision** | 1.0000 | 1.0000 | **0.0000** |
| **Recall** | 0.7273 | 1.0000 | **+0.2727** |
| **F1 Score** | 0.8421 | 1.0000 | **+0.1579** |
| **False Positive Rate (FPR)** | 0.0000 | 0.0000 | **0.0000** |
| **Mean Latency (ms)** | 5.630 ms | 8.586 ms | **+2.956 ms** |
| **Detection Coverage** | 75.0% | 83.3% | **+8.3%** |

### HELD_OUT_TEST Split (15 Scenarios — Frozen)

| Metric | System A (Baseline) | System B (Closed-Loop) | Delta ($\Delta$) |
| :--- | :---: | :---: | :---: |
| **True Positives (TP)** | 5 | 8 | **+3** |
| **False Positives (FP)** | 0 | 0 | **0** |
| **False Negatives (FN)** | 3 | 0 | **-3** |
| **True Negatives (TN)** | 7 | 7 | **0** |
| **Precision** | 1.0000 | 1.0000 | **0.0000** |
| **Recall** | 0.6250 | 1.0000 | **+0.3750** |
| **F1 Score** | 0.7692 | 1.0000 | **+0.2308** |
| **False Positive Rate (FPR)** | 0.0000 | 0.0000 | **0.0000** |
| **Mean Latency (ms)** | 5.167 ms | 6.550 ms | **+1.383 ms** |

### Threat Hunting Quality Metrics

| Lifecycle Metric | Measured Value | Description |
| :--- | :---: | :--- |
| **Total Hunts Evaluated** | 10 | HUNT-001 through HUNT-010 |
| **Hunt Precision** | 1.0000 | Confirmed true findings / all positive findings |
| **Detection Gap Yield** | 0.1000 | Valid detection gaps / completed hunts |
| **Candidate Acceptance Rate** | 1.0000 | Validated candidates promoted to ACTIVE / generated candidates |
| **Candidate Regression Failure Rate** | 0.0000 | Candidate rules failing regression / validated candidates |
| **False Lead Rate** | 0.1000 | False leads / completed hunts |
| **Insufficient Data Rate** | 0.4000 | Insufficient telemetry hunts / completed hunts |
| **Duplicate Candidates Prevented** | 1 | Guard against redundant candidate generation |
| **Mean Time: Hunt &rarr; Candidate** | 0.0286 s | Automated gap discovery to draft specification |
| **Mean Time: Candidate &rarr; Validation** | 0.0076 s | Automated test-case quality assertion |
| **Mean Time: Validation &rarr; Activation** | 0.0121 s | Regression evaluation and production rule deployment |

---

## 11. Closed-Loop Research Hypotheses Evaluation

| Hypothesis | Proposition | Status | Empirical Evidence |
| :--- | :--- | :---: | :--- |
| **H1** | Threat hunting identifies detection gaps not covered by the existing active rule set. | **ACCEPTED** | Identified gap `GAP-HUNT-006` (process execution in temporary directories). System A recall improved from 0.7273 to 1.0000 on DEV+VAL and from 0.6250 to 1.0000 on HELD_OUT_TEST. |
| **H2** | Validated detection engineering can improve coverage without unacceptable false-positive degradation. | **ACCEPTED** | Recall improved by +0.2727 on DEV+VAL with an FPR delta of 0.0000 ($\le 0.02$ threshold). |
| **H3** | Versioned rule validation reduces regression risk compared with direct rule activation. | **ACCEPTED** | Candidate rule `CAND-GAP-HUNT-006` was validated against positive, negative, mutation, missing-field, and 5 historical corpora before activation. |
| **H4** | The hunting feedback loop can identify both genuine detection gaps and false leads. | **ACCEPTED** | Produced both `DETECTION_GAP` (HUNT-006) and `FALSE_LEAD` (HUNT-010) classifications without forcing positive findings. |
| **H5** | Adversarial evaluation exposes weaknesses that are not visible in nominal detection benchmarks. | **ACCEPTED** | Mutated temp directory executions bypassed baseline rules but triggered candidate detection mutation tests. |

---

## 12. Failure Cases and Discovered Trade-Offs

1. **Static Keyword Matching vs. Cross-Process Sequences**:
   - Initial hunt HUNT-001 targeting PowerShell download cradles revealed that simple command line matching already existed for `downloadstring(`, but lacked visibility into un-obfuscated script invocations using raw TCP sockets or custom .NET reflection.
2. **Missing Field Dropouts (HUNT-009)**:
   - When endpoint telemetry drops image path or command line attributes, the hunting query correctly classifies the observation as `INSUFFICIENT_DATA` rather than forcing a false positive alert.
3. **Detection Latency Impact**:
   - Adding candidate rule `CAND-GAP-HUNT-006` to the active rule set increased mean evaluation latency by +2.956 ms per scenario due to regex inspection across command line strings.

---

## 13. Limitations

1. **Controlled Telemetry**:
   - Telemetry scenarios are evaluated within synthetic and replayed datasets. Real-world corporate environments will present significantly higher event volumes and software installer noise.
2. **Deterministic Heuristics**:
   - All hunting query classifications use parameterized deterministic rules. The system does not employ autonomous or black-box LLM decision-making for rule promotion.
3. **No Destructive Autonomous Actions**:
   - In accordance with research integrity constraints, candidate rule activation requires explicit authorization and executes purely within detection and alerting pipelines.

---

## 14. Reproducibility

To reproduce all dataset generation, benchmark evaluation, and test suites:

```bash
# 1. Regenerate Threat Hunting Benchmark Dataset V1 (60 scenarios)
python research/generate_threat_hunting_v1.py

# 2. Run Closed-Loop Research Experiment (System A vs System B)
python research/evaluate_threat_hunting_v1.py

# 3. Run Complete Backend Test Suite (176 passing tests)
python -m pytest tests/ -q

# 4. Build Frontend Workspace
cd frontend && npm.cmd run build
```

---

## 15. Research Implications

Phase 9 establishes that threat hunting provides the greatest value to SOC operations when formalized as a closed-loop engineering pipeline rather than an isolated investigative task. By translating retrospective hunt observations into versioned detection candidates with mandatory quality gates and regression checks, organizations can incrementally expand coverage while mathematically bounding false-alarm degradation.
