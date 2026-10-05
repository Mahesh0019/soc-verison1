# Publication Results Summary: Detection-Quality-Aware SOC Evaluation

**Title:** Empirical Evaluation of a Detection-Quality-Aware Security Operations Center Framework  
**Dataset Version:** `v1.0` | **Verified Main Commit:** `1800ca80f91d092a292afcb60b3041853595f93e`  
**Target Repository:** `https://github.com/Mahesh0019/soc-verison1`  

---

## 1. Research Objective

To evaluate whether progressively adding multi-event correlation, cryptographic evidence bundling, explainable 5-factor detection quality scoring, Isolation Forest behavioral anomaly detection, and evidence-grounded AI triage simulation to a rule-based SOC reduces un-actionable false-positive investigation tickets and mean time to investigate (MTTI) without compromising genuine attack detection.

---

## 2. Experimental Design & Dataset

- **Environment:** Controlled OWASP Juice Shop victim container (`https://demo-victim-1.onrender.com/`) and deterministic SQLite benchmark engine.
- **Dataset:** 22 scenarios (33 telemetry events): 11 genuine attack scenarios and 11 benign/noise scenarios.
- **Ground Truth:** Pre-assigned immutable labels (`is_attack=True` vs `is_attack=False`).

---

## 3. Verified Benchmark Results Table

| Mode | Architecture | Precision | Recall | F1 Score | False Positive Rate | FP Reduction | Attack Retention (Dataset) | MTTI (min) | Evidence Latency |
|:---:|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **M0** | Raw Telemetry Baseline | 0.00 | 0.00 | 0.00 | 0.00 | 0.0% | 0.0% | 45.0m | 3500.0ms |
| **M1** | Static Rule SIEM | 0.83 | 0.91 | 0.87 | 0.18 | 0.0% | 90.9% | 18.5m | 1450.0ms |
| **M2** | Correlated SIEM | 0.83 | 0.91 | 0.87 | 0.18 | 0.0% | 90.9% | 12.0m | 850.0ms |
| **M3** | Evidence-Packaged SIEM | 0.83 | 0.91 | 0.87 | 0.18 | 0.0% | 90.9% | 7.5m | 45.0ms |
| **M4** | Detection-Quality SOC | 1.00 | 0.91 | 0.95 | 0.00 | 100.0% | 90.9% | 4.8m | 40.0ms |
| **M5** | Quality SOC + Behavioral ML | 1.00 | 1.00 | 1.00 | 0.00 | 100.0% | 100.0% | 3.8m | 35.0ms |
| **M6** | Full Hybrid SOC | 1.00 | 1.00 | 1.00 | 0.00 | 100.0% | 100.0% | 2.1m | 28.0ms |

---

## 4. Key Findings

1. **False Positive Reduction:** Explainable 5-factor detection quality gating ($Q \ge 0.40, Risk \ge 40.0$) eliminated all 2 false-positive lookalike tickets present in the rule-based baseline (**100.0% FP reduction within the evaluated dataset**).
2. **Detection Retention & Recall:** Behavioral anomaly detection (Isolation Forest in M5) detected a low-and-slow API enumeration evasion (`BENCH-SLOW-ANOMALY-01`), raising recall from $0.91$ to $1.00$ and achieving **100.0% genuine attack retention within the evaluated dataset**.
3. **Investigation Time (MTTI):** Cumulative architecture progression reduced measured MTTI from 18.5 minutes (M1) to 2.1 minutes (M6), representing an **88.6% cumulative reduction**. The transition specifically attributable to M6 triage/feedback reduced MTTI from 3.8 to 2.1 minutes (a **44.7% transition reduction**).
4. **Evidence Retrieval Latency:** Cryptographic evidence bundling (M3) dropped evidence retrieval latency from 1,450ms (M1) to 45ms (M3) and 28ms (M6), representing a **98.1% latency reduction**.
5. **AI Grounding & Claims Verification:** The AI triage component operates as a **`RULE_BASED_SIMULATION`** (deterministic SLM Grounding Engine). Evaluated triage claims achieved **94.8% agreement** with analyst ground truth and **0.0% unsupported claims within the dataset**.

---

## 5. Threats to Validity & Limitations

- **AI Scope:** The evaluated AI triage engine is a deterministic rule-based simulation engine (`RULE_BASED_SIMULATION`) rather than a live external LLM API.
- **Dataset Scale:** Evaluated across 22 synthetic scenarios rather than multi-terabyte enterprise logs.
- **Data Leakage:** Rules and quality thresholds were evaluated against benchmark scenarios designed alongside the framework (**MEDIUM data leakage risk**).

---

## 6. Research Contributions & Conclusion

This work empirically demonstrates that combining explainable quality scoring, multi-event correlation, evidence packaging, and behavioral ML reduces analyst investigation workload and latency while maintaining complete attack detection fidelity within a controlled benchmark environment.
