# RESEARCH DATASET V2 SPECIFICATION & BENCHMARK METHODOLOGY

- **Dataset Name:** `RESEARCH_DATASET_V2`
- **Version:** `v2.0`
- **Release Date:** 2026-10-08
- **Target Architecture:** Mini-SIEM / Detection-Quality-Aware SOC Platform
- **Dataset Artifact Directory:** `research/datasets/dataset_v2/`
- **Generator Script:** [`research/scripts/generate_dataset_v2.py`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/research/scripts/generate_dataset_v2.py)
- **Validator Script:** [`research/scripts/validate_dataset_v2.py`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/research/scripts/validate_dataset_v2.py)
- **Automated Test Suite:** [`tests/test_dataset_v2.py`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/tests/test_dataset_v2.py)

---

## 1. Overview & Research Objective

Dataset V1 served as the initial proof-of-concept benchmark (22 scenarios, 33 events; 11 attack, 11 benign) against a single OWASP Juice Shop target. While sufficient for baseline feasibility demonstration, Dataset V1's limited scale and reliance on static scenario templates introduced data leakage risks and could not provide statistical power across edge cases.

**Research Dataset V2** expands the benchmark into **200 fully curated, multi-event scenarios comprising 827 telemetry events**. It delivers a perfectly balanced $50.0\% / 50.0\%$ split between genuine attacks and benign traffic, explicitly incorporating deceptive benign lookalikes, borderline failures, truncated records, and evasive low-and-slow timing patterns.

---

## 2. Dataset Partitioning & Split Architecture

To uphold rigorous scientific separation and prevent data leakage or overfitting during rule engineering and ML model training, Dataset V2 is partitioned into three disjoint sets:

| Dataset Split | Scenario Count | Attack Count | Benign Count | Ground Truth Balance | Purpose & Access Guard | IP Subnet Partition |
|:---|:---:|:---:|:---:|:---:|:---|:---:|
| **Development (`dev_set.json`)** | 100 | 50 | 50 | 50.0% / 50.0% | Rule creation, feature extraction, and ML training. Visible to engineers. | `198.51.100.10` – `198.51.100.99` |
| **Validation (`val_set.json`)** | 40 | 20 | 20 | 50.0% / 50.0% | Hyperparameter tuning, correlation window calibration, and regression testing. | `203.0.113.10` – `203.0.113.99` |
| **Test (`test_set.json`)** | 60 | 30 | 30 | 50.0% / 50.0% | **Strictly held-out.** Unbiased evaluation of final M0–M6 and V2 detection models. | `192.0.2.10` – `192.0.2.99` |
| **Full Dataset (`dataset_v2.json`)** | **200** | **100** | **100** | **50.0% / 50.0%** | Authoritative master benchmark suite. | All partitions |

---

## 3. Coverage Across 20 Required Categories

Dataset V2 encompasses 20 distinct behavioral categories, representing standard traffic, hostile offensive probes, and high-noise edge cases:

| # | Behavioral Category | Ground Truth | Total Scenarios | Dev | Val | Test | Typical Indicators / Payloads |
|:---:|:---|:---:|:---:|:---:|:---:|:---:|:---|
| 1 | **Normal browsing** | `BENIGN` | 18 | 9 | 4 | 5 | Legitimate HTTP GET requests to assets, product pages, about/contact forms. |
| 2 | **Normal authentication** | `BENIGN` | 12 | 6 | 2 | 4 | Successful single-attempt logins from legitimate corporate accounts. |
| 3 | **Failed authentication** | `BENIGN` | 10 | 5 | 2 | 3 | Borderline: 1–2 mistyped password attempts; well below brute-force threshold. |
| 4 | **Repeated authentication failures** | `ATTACK` | 8 | 4 | 2 | 2 | Brute-force bursts (6–9 consecutive failed logins within 2 minutes). |
| 5 | **SQL injection** | `ATTACK` | 10 | 5 | 2 | 3 | Exploitation probes: `UNION SELECT`, boolean blind, `SLEEP()`, error-based. |
| 6 | **XSS** | `ATTACK` | 10 | 5 | 2 | 3 | Injections: `<script>`, `<img onerror=...>`, `javascript:`, SVG onload. |
| 7 | **Path traversal** | `ATTACK` | 8 | 4 | 2 | 2 | Directory traversal sequences: `../`, `%2e%2e%2f`, `/etc/passwd`, `win.ini`. |
| 8 | **Suspicious HTTP requests** | `ATTACK` | 8 | 4 | 2 | 2 | Sensitive hidden file discovery: `/.env`, `/config/database.yml`, `/.git`. |
| 9 | **Reconnaissance** | `ATTACK` | 8 | 4 | 2 | 2 | Automated crawler bursts: 12 rapid 404 responses from fuzzers and Nikto. |
| 10 | **Abnormal request rate** | `ATTACK` | 6 | 3 | 1 | 2 | High-velocity scrapers: 65 requests within 2 minutes flooding endpoints. |
| 11 | **Suspicious user-agent behavior** | `ATTACK` | 6 | 3 | 1 | 2 | Offensive automation user agents: `sqlmap/1.7`, `nikto/2.1.5`, `curl/7.88`. |
| 12 | **Suspicious source-IP behavior** | `ATTACK` | 6 | 3 | 1 | 2 | Connections originating from blacklisted threat intelligence IOC IPs. |
| 13 | **Multi-step attacks** | `ATTACK` | 6 | 3 | 1 | 2 | Multi-stage chain: Recon probe $\to$ SQLi parameter probe $\to$ privileged login. |
| 14 | **Privilege-related behavior** | `ATTACK` | 6 | 3 | 1 | 2 | Unauthorized external administrative portal logins (`admin` role). |
| 15 | **Account-related anomalies** | `ATTACK` | 6 | 3 | 1 | 2 | Geographic anomaly: Logins originating from anomalous countries (`CN`). |
| 16 | **Mixed attack/benign sequences** | `ATTACK` | 6 | 3 | 1 | 2 | Stealth evasion: Malicious SQLi payload embedded within legitimate browsing. |
| 17 | **Benign behavior resembling attacks** | `BENIGN` | 22 | 11 | 5 | 6 | Tricky lookalikes: Book title searches ("O'Reilly SQL Guide"), public admin docs, double slashes. |
| 18 | **Missing/partial telemetry** | `BENIGN` | 12 | 6 | 2 | 4 | Truncated logs: Missing User-Agent or null HTTP status code from proxies. |
| 19 | **Duplicate telemetry** | `BENIGN` | 14 | 7 | 3 | 4 | Twin retransmitted logs generated by reverse proxy network retries. |
| 20 | **Timing variations** | `BOTH` | 18 | 9 | 3 | 6 | 6 low-and-slow stealth attacks (15-min spacing) + 12 slow human reading sessions. |
| **Total** | | | **200** | **100** | **40** | **60** | **827 total telemetry events** |

---

## 4. Scenario Schema & Visible vs. Ground-Truth Fields

To eliminate unintentional data leakage, the benchmark enforces a strict architectural boundary between **Operational Telemetry** and **Evaluation Metadata**:

```
Scenario Object (Master)
├── Evaluation-Only Ground Truth (HIDDEN from Detection Engine)
│   ├── scenario_id          (e.g., "V2-SCEN-SQLI-001")
│   ├── scenario_version     ("v2.0")
│   ├── split                ("development" | "validation" | "test")
│   ├── ground_truth         ("ATTACK" | "BENIGN")
│   ├── attack_category      ("SQL injection")
│   ├── expected_detection   (True | False)
│   ├── expected_severity    ("critical" | "high" | "medium" | "low" | "none")
│   ├── difficulty           ("direct" | "obfuscated" | "low_and_slow" | "benign_lookalike")
│   └── mitre_technique      ("T1190")
│
└── Operational Telemetry (VISIBLE to Ingestion / Detection Engine)
    └── events: [
          {
            "timestamp":       "2026-10-08T08:00:15+00:00",
            "source_ip":       "198.51.100.71",
            "destination_ip":  "10.0.0.15",
            "username":        null,
            "hostname":        "web-01",
            "event_type":      "web_attack",
            "event_category":  "web",
            "severity":        "critical",
            "message":         "SQL injection attempt with payload: ' or '1'='1",
            "request_path":    "/rest/products/search?q=' UNION SELECT 1,email,password,4 FROM Users-- -",
            "http_method":     "GET",
            "status_code":     500,
            "user_agent":      "Mozilla/5.0 ...",
            "geo_country":     "US",
            "raw_log":         "198.51.100.71 - - [2026-10-08T08:00:15+00:00] \"GET /rest/...\" 500"
          }
        ]
```

### Detection Engine Input Rule:
When evaluating detection models or scoring accuracy:
- The detection engine is fed **only** the `events` array (or formatted raw log lines).
- All labels (`ground_truth`, `expected_detection`, `expected_severity`, `split`) are isolated from the detector and referenced solely by the scoring harness.

---

## 5. Data Leakage Risk Assessment & Mitigation

| Potential Leakage Vector | Risk Level | Mitigation Implemented |
|:---|:---:|:---|
| **Entity IP Memorization** | High | **IP Subnet Isolation:** Dev uses `198.51.100.x`, Val uses `203.0.113.x`, and Test uses `192.0.2.x`. Test IPs never appear in Dev training. |
| **Exact Payload Memorization** | Medium | **Payload Variation:** Test set incorporates mutated and alternative injection syntax (e.g., error-based SQLi, mixed-case script payloads, obfuscated traversals) not present verbatim in Dev. |
| **Scenario Metadata Bleed** | High | **Schema Encapsulation:** All labels are stored at top-level scenario metadata, which is stripped before forwarding events to ingestion parsers. |
| **Test Set Tuning (P-Hacking)** | High | **Held-Out Test Policy:** Test set evaluation is restricted to final validation runs; rule thresholds are calibrated only against Dev and Val. |

---

## 6. Machine-Readable Artifacts & Cryptographic Checksums

All dataset files have been generated and validated with SHA-256 hashes:

- **Full Dataset Master:** [`research/datasets/dataset_v2/dataset_v2.json`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/research/datasets/dataset_v2/dataset_v2.json)  
  `SHA-256: 6d2d7ddfdb8bb2674d7705917d289486f1d9d6cddd8eecaa09d20340adc6b95c`
- **Development Partition:** [`research/datasets/dataset_v2/dev_set.json`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/research/datasets/dataset_v2/dev_set.json)  
  `SHA-256: 3c5a6104f21dca93766a59600a98f1a14187e14a2432a76f2f9db1c5a96aa500`
- **Validation Partition:** [`research/datasets/dataset_v2/val_set.json`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/research/datasets/dataset_v2/val_set.json)  
  `SHA-256: a70327e57c6b4543b5f9ce02b0c6183ef9da3080ff52fa20c99f92e47854e4df`
- **Test Partition:** [`research/datasets/dataset_v2/test_set.json`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/research/datasets/dataset_v2/test_set.json)  
  `SHA-256: a91834923e4ea30fe71fb2c263dae20be7c77c68a44b8296a2ca58dcfa7d0ea4`
- **Manifest File:** [`research/datasets/dataset_v2/dataset_v2_manifest.json`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/research/datasets/dataset_v2/dataset_v2_manifest.json)

---

## 7. Preservation of Dataset V1

In strict adherence to the project charter:
- [`soc_attack_catalog.json`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/soc_attack_catalog.json) remains unmodified.
- [`research/results/verified_benchmark_matrix.json`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/research/results/verified_benchmark_matrix.json) remains unmodified.
- Historical M0–M6 validation metrics remain untouched.
