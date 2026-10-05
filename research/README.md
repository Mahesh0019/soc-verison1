# Reproducible Research Pipeline

**Project:** Detection-Quality-Aware SOC Framework  
**Directory:** `research/`  

---

## Structure

```
research/
├── datasets/
│   └── soc_attack_catalog.json   # Ground truth attack scenario catalog (MITRE ATT&CK probes)
├── runs/                         # Per-run raw JSON execution artifacts
├── results/
│   ├── benchmark_matrix.json     # Full machine-readable comparative matrix
│   └── benchmark_matrix.csv      # CSV formatted benchmark performance matrix
└── scripts/
    └── run_experiments.py        # Reproducible automated experiment runner
```

---

## Running Experiments

To execute the complete M0 through M6 benchmark evaluation pipeline and regenerate raw execution artifacts:

```bash
python research/scripts/run_experiments.py
```

This script:
1. Provisions an isolated ground truth evaluation environment.
2. Evaluates all 7 operational architecture modes (M0 through M6).
3. Computes exact research metrics: Precision, Recall, F1 Score, False Positive Reduction %, Genuine Attack Retention %, MTTI (min), Evidence Latency (ms).
4. Persists timestamped raw JSON run artifacts in `research/runs/` and updated matrix files in `research/results/`.
