# Detection Quality Model Documentation

**Framework:** Detection-Quality-Aware SOC Platform  
**Engine:** `backend/app/services/detection_quality_service.py`  

---

## 1. Mathematical Formulation

The composite Detection Quality score ($Q_{composite} \in [0.0, 1.0]$) is computed as an explainable weighted linear combination of five distinct analytical factor scores:

$$Q_{composite} = w_e F_{evid} + w_c F_{corr} + w_r F_{rule} + w_b F_{behav} + w_x F_{context}$$

Where the weights satisfy $\sum w_i = 1.0$:
- $w_e = 0.25$ (Evidence Completeness)
- $w_c = 0.20$ (Correlation Strength)
- $w_r = 0.20$ (Rule Confidence)
- $w_b = 0.15$ (Behavioral Confidence)
- $w_x = 0.20$ (Context Confidence)

---

## 2. Factor Decomposition

### Factor 1: Evidence Completeness ($F_{evid}$, Weight: 25%)
- **Definition:** Quantifies the presence of structured forensic evidence dimensions required for root cause analysis.
- **Range:** $[0.0, 1.0]$
- **Input Dimensions & Weights:**
  - `triggering_event`: 0.25 (Anchor event payload presence)
  - `related_events`: 0.25 (Correlated event links)
  - `detection_rule`: 0.20 (Rule conditions & threshold)
  - `entity_context`: 0.15 (Attributed IP and user identity)
  - `timeline`: 0.15 (Start/end activity duration)
  - *Bonus:* +0.10 for active threat intelligence IOC or behavioral ML evidence match (capped at 1.0).

### Factor 2: Correlation Strength ($F_{corr}$, Weight: 20%)
- **Definition:** Measures multi-event temporal density and entity linkage.
- **Range:** $[0.0, 1.0]$
- **Calculation:**
  - For incidents linked across $N$ component alerts: computed via `calculate_correlation_metrics(incident_alerts)`.
  - For single alerts: $F_{corr} = 0.50$ if event count $> 1$, else $0.30$.

### Factor 3: Rule Confidence ($F_{rule}$, Weight: 20%)
- **Definition:** Deterministic rule specificity based on historical false-positive rates and signature precision.
- **Range:** $[0.60, 0.98]$
- **Lookup Table:**
  - Threat Intel Blacklist Match: 0.98
  - SQL Injection Attempt: 0.95
  - Path Traversal Attempt: 0.92
  - Cross-Site Scripting Probe: 0.90
  - Successful Login After Failures: 0.90
  - Suspicious Admin Login: 0.88
  - Repeated Sensitive Path Access: 0.85
  - Directory Brute Force / Failed Login Spike: 0.80
  - Unusual Country / Suspicious User Agent: 0.75
  - Firewall Denied Spike: 0.70
  - High 404 Responses / Volume Burst: 0.60–0.65

### Factor 4: Behavioral Confidence ($F_{behav}$, Weight: 15%)
- **Definition:** Evaluates statistical deviation using unsupervised `IsolationForest` machine learning combined with heuristic volume baselines.
- **Range:** $[0.0, 1.0]$
- **Formulation:** 50% Isolation Forest anomaly depth + 50% feature deviation score.
- **Missing Data / Fallback:** If ML model is uncalibrated or dataset is sparse, falls back to heuristic severity/event-volume baseline score ($[0.60, 0.85]$).

### Factor 5: Context Confidence ($F_{context}$, Weight: 20%)
- **Definition:** Evaluates source IP attribution, user identity clarity, and Threat Intelligence IOC match status.
- **Range:** $[0.0, 1.0]$
- **Scoring Rules:**
  - Non-loopback/valid IP: +0.40
  - Non-anonymous user identity: +0.30
  - Active Threat Intel match: +0.20
  - Event count $> 1$: +0.10

---

## 3. Tier Classification & Explanation

The composite score $Q_{composite}$ maps to 3 explainable quality tiers displayed in the React frontend:

| Quality Range | Tier | Analyst Interpretation |
|:---:|:---:|:---|
| $Q \ge 0.80$ | **HIGH** | Fully corroborated detection backed by complete evidence, high rule specificity, and multi-event correlation. |
| $0.55 \le Q < 0.80$ | **MEDIUM** | Moderate confidence detection. Requires analyst inspection of missing evidence or ambiguous context. |
| $Q < 0.55$ | **LOW** | Low confidence detection. Likely false positive or sparse single-event anomaly. |

---

## 4. REST API Endpoint

- `GET /api/detection-quality/alert/{alert_id}`
- Returns full factor JSON breakdown:
  ```json
  {
    "overall_quality": 0.92,
    "evidence_completeness": 1.0,
    "correlation_strength": 0.85,
    "rule_confidence": 0.95,
    "behavioral_confidence": 0.88,
    "context_confidence": 0.90,
    "explanation": "High-confidence detection (Quality: 0.92)..."
  }
  ```
