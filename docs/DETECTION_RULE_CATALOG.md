# Detection Rule Catalog

**Framework:** Detection-Quality-Aware SOC Platform  
**Total Production Rules:** 14  
**Status:** All 14 Active Rules VERIFIED with Positive and Negative Scenarios  

---

## Production Rule Matrix

| Rule ID | Name | Severity | Type | MITRE Tactic | MITRE Technique | Threshold / Window | Source Location | Validation Status |
|:---:|:---|:---:|:---:|:---|:---|:---:|:---|:---:|
| 1 | Multiple failed login attempts from same IP | HIGH | threshold | Credential Access | T1110 (Brute Force) | 5 events / 10m | `backend/app/rules/builtin.py` | VERIFIED |
| 2 | Successful login after failed attempts | CRITICAL | sequence | Credential Access / Persistence | T1110, T1078 (Valid Accounts) | 3 fails + 1 succ / 15m | `backend/app/rules/builtin.py` | VERIFIED |
| 3 | Suspicious admin login | HIGH | threshold | Privilege Escalation | T1078.004 (Domain Accounts) | 1 event / 30m | `backend/app/rules/builtin.py` | VERIFIED |
| 4 | Login attempt from unusual country | MEDIUM | Initial Access | T1078 (Valid Accounts) | 1 event / 20m | `backend/app/rules/builtin.py` | VERIFIED |
| 5 | High number of 404 responses | MEDIUM | Reconnaissance | T1595.002 (Vulnerability Scanning) | 10 events / 10m | `backend/app/rules/builtin.py` | VERIFIED |
| 6 | Possible directory brute force | HIGH | Reconnaissance | T1595.003 (Wordlist Scanning) | 15 events / 10m | `backend/app/rules/builtin.py` | VERIFIED |
| 7 | Repeated sensitive path access | HIGH | Discovery | T1083 (File and Directory Discovery) | 4 events / 10m | `backend/app/rules/builtin.py` | VERIFIED |
| 8 | Large request volume burst | MEDIUM | Impact / Recon | T1499 (Endpoint Denial of Service) | 60 events / 5m | `backend/app/rules/builtin.py` | VERIFIED |
| 9 | Suspicious user agent | HIGH | Reconnaissance | T1595 (Active Scanning) | 1 event / 10m | `backend/app/rules/builtin.py` | VERIFIED |
| 10 | Firewall denied traffic spike | MEDIUM | Reconnaissance | T1595 (Active Scanning) | 20 events / 10m | `backend/app/rules/builtin.py` | VERIFIED |
| 11 | Repeated access from blacklisted indicator | CRITICAL | Command and Control | T1071 (Application Layer Protocol) | 1 event / 60m | `backend/app/rules/builtin.py` | VERIFIED |
| 12 | SQL injection attempt detected | CRITICAL | Initial Access | T1190 (Exploit Public-Facing App) | 1 event / 15m | `backend/app/rules/builtin.py` | VERIFIED |
| 13 | Path traversal attempt detected | HIGH | Initial Access | T1190 (Exploit Public-Facing App) | 1 event / 15m | `backend/app/rules/builtin.py` | VERIFIED |
| 14 | Cross-site scripting probe detected | HIGH | Initial Access | T1190 (Exploit Public-Facing App) | 1 event / 15m | `backend/app/rules/builtin.py` | VERIFIED |

---

## Rule Specifications & Regression Harness

### Rule 1: Multiple failed login attempts from same IP
- **Description:** Detects repeated authentication failures from one source IP.
- **Enabled:** True
- **Implementation:** `evaluate_threshold_rule()` in `backend/app/rules/engine.py`
- **Positive Scenario (SCEN-FAILLOGIN-POS):** 6 consecutive failed logins from `198.51.100.207` within 10 minutes.
  - *Expected Result:* True (Alert Triggered)
  - *Observed Result:* True (PASS)
- **Negative Scenario (SCEN-FAILLOGIN-NEG):** 1 accidental failed login from `198.51.100.208`.
  - *Expected Result:* False (No Alert)
  - *Observed Result:* False (PASS)

### Rule 2: Successful login after failed attempts
- **Description:** Detects a successful login following several failures from the same IP and user.
- **Enabled:** True
- **Implementation:** `evaluate_success_after_failures()` in `backend/app/rules/engine.py`
- **Positive Scenario (SCEN-SEQAUTH-POS):** 3 failed login attempts followed by 1 successful login for user `admin`.
  - *Expected Result:* True (Alert Triggered)
  - *Observed Result:* True (PASS)
- **Negative Scenario (SCEN-SEQAUTH-NEG):** 1 direct successful login without preceding failures.
  - *Expected Result:* False (No Alert)
  - *Observed Result:* False (PASS)

### Rule 3: Suspicious admin login
- **Description:** Flags successful privileged account logins for analyst review.
- **Enabled:** True
- **Implementation:** `evaluate_threshold_rule()` in `backend/app/rules/engine.py`
- **Positive Scenario (SCEN-ADMIN-POS):** Successful login event for username `admin`.
  - *Expected Result:* True (Alert Triggered)
  - *Observed Result:* True (PASS)
- **Negative Scenario (SCEN-ADMIN-NEG):** Successful login event for regular user `regular_alice`.
  - *Expected Result:* False (No Alert)
  - *Observed Result:* False (PASS)

### Rule 4: Login attempt from unusual country
- **Description:** Detects authentication attempts from countries outside the expected demo baseline.
- **Enabled:** True
- **Implementation:** `evaluate_threshold_rule()` in `backend/app/rules/engine.py`
- **Positive Scenario (SCEN-GEO-POS):** Login event originating from country code `RU`.
  - *Expected Result:* True (Alert Triggered)
  - *Observed Result:* True (PASS)
- **Negative Scenario (SCEN-GEO-NEG):** Login event originating from baseline country code `US`.
  - *Expected Result:* False (No Alert)
  - *Observed Result:* False (PASS)

### Rule 5: High number of 404 responses
- **Description:** Detects many HTTP 404 responses from a single source IP.
- **Enabled:** True
- **Implementation:** `evaluate_threshold_rule()` in `backend/app/rules/engine.py`
- **Positive Scenario (SCEN-404-POS):** 12 HTTP 404 error responses from IP `198.51.100.215` in 10 minutes.
  - *Expected Result:* True (Alert Triggered)
  - *Observed Result:* True (PASS)
- **Negative Scenario (SCEN-404-NEG):** 2 HTTP 404 responses from IP `198.51.100.216`.
  - *Expected Result:* False (No Alert)
  - *Observed Result:* False (PASS)

### Rule 6: Possible directory brute force
- **Description:** Detects repeated misses and sensitive path probing from one source IP.
- **Enabled:** True
- **Implementation:** `evaluate_threshold_rule()` in `backend/app/rules/engine.py`
- **Positive Scenario (SCEN-DIRBRUTE-POS):** 16 web 4xx status responses from IP `198.51.100.217` in 10 minutes.
  - *Expected Result:* True (Alert Triggered)
  - *Observed Result:* True (PASS)
- **Negative Scenario (SCEN-DIRBRUTE-NEG):** 2 web 4xx status responses from IP `198.51.100.218`.
  - *Expected Result:* False (No Alert)
  - *Observed Result:* False (PASS)

### Rule 7: Repeated sensitive path access
- **Description:** Detects repeated requests to paths such as `/admin`, `/login`, `/wp-admin`, and `/.env`.
- **Enabled:** True
- **Implementation:** `evaluate_threshold_rule()` in `backend/app/rules/engine.py`
- **Positive Scenario (SCEN-SENSPATH-POS):** 5 web requests to `/admin/dashboard` from IP `198.51.100.219`.
  - *Expected Result:* True (Alert Triggered)
  - *Observed Result:* True (PASS)
- **Negative Scenario (SCEN-SENSPATH-NEG):** 1 web request to `/admin/dashboard` (below threshold 4).
  - *Expected Result:* False (No Alert)
  - *Observed Result:* False (PASS)

### Rule 8: Large request volume burst
- **Description:** Detects a large number of web requests in a short time window.
- **Enabled:** True
- **Implementation:** `evaluate_threshold_rule()` in `backend/app/rules/engine.py`
- **Positive Scenario (SCEN-VOLBURST-POS):** 65 web requests from IP `198.51.100.221` within 5 minutes.
  - *Expected Result:* True (Alert Triggered)
  - *Observed Result:* True (PASS)
- **Negative Scenario (SCEN-VOLBURST-NEG):** 10 web requests from IP `198.51.100.222`.
  - *Expected Result:* False (No Alert)
  - *Observed Result:* False (PASS)

### Rule 9: Suspicious user agent
- **Description:** Detects tool-like user agents including `curl`, `sqlmap`, `nikto`, and `python-requests`.
- **Enabled:** True
- **Implementation:** `evaluate_threshold_rule()` in `backend/app/rules/engine.py`
- **Positive Scenario (SCEN-USERAGENT-POS):** Request with User-Agent `sqlmap/1.6#stable`.
  - *Expected Result:* True (Alert Triggered)
  - *Observed Result:* True (PASS)
- **Negative Scenario (SCEN-USERAGENT-NEG):** Request with User-Agent `Mozilla/5.0 (Windows NT 10.0; Chrome/120.0)`.
  - *Expected Result:* False (No Alert)
  - *Observed Result:* False (PASS)

### Rule 10: Firewall denied traffic spike
- **Description:** Detects repeated denied firewall events from one source IP.
- **Enabled:** True
- **Implementation:** `evaluate_threshold_rule()` in `backend/app/rules/engine.py`
- **Positive Scenario (SCEN-FWDENY-POS):** 22 firewall_denied events from IP `198.51.100.225` in 10 minutes.
  - *Expected Result:* True (Alert Triggered)
  - *Observed Result:* True (PASS)
- **Negative Scenario (SCEN-FWDENY-NEG):** 3 firewall_denied events from IP `198.51.100.226`.
  - *Expected Result:* False (No Alert)
  - *Observed Result:* False (PASS)

### Rule 11: Repeated access from blacklisted indicator
- **Description:** Matches events against the local threat intelligence blacklist.
- **Enabled:** True
- **Implementation:** `evaluate_blacklist()` in `backend/app/rules/engine.py`
- **Positive Scenario (SCEN-BLACKLIST-POS):** Request from source IP `203.0.113.66` matching ThreatIndicator entry.
  - *Expected Result:* True (Alert Triggered)
  - *Observed Result:* True (PASS)
- **Negative Scenario (SCEN-BLACKLIST-NEG):** Request from clean unlisted source IP `198.51.100.227`.
  - *Expected Result:* False (No Alert)
  - *Observed Result:* False (PASS)

### Rule 12: SQL injection attempt detected
- **Description:** Detects SQL injection signatures in HTTP request paths or messages.
- **Enabled:** True
- **Implementation:** `evaluate_pattern_rule()` in `backend/app/rules/engine.py`
- **Positive Scenario (SCEN-SQLI-POS):** GET request with path `/rest/products/search?q=' UNION SELECT 1,username,password FROM users--`.
  - *Expected Result:* True (Alert Triggered)
  - *Observed Result:* True (PASS)
- **Negative Scenario (SCEN-SQLI-NEG):** GET request with path `/rest/products/search?q=apple_juice`.
  - *Expected Result:* False (No Alert)
  - *Observed Result:* False (PASS)

### Rule 13: Path traversal attempt detected
- **Description:** Detects directory traversal sequences in requested URLs or query parameters.
- **Enabled:** True
- **Implementation:** `evaluate_pattern_rule()` in `backend/app/rules/engine.py`
- **Positive Scenario (SCEN-TRAV-POS):** GET request with path `/ftp/../../etc/passwd`.
  - *Expected Result:* True (Alert Triggered)
  - *Observed Result:* True (PASS)
- **Negative Scenario (SCEN-TRAV-NEG):** GET request with path `/assets/public/images/logo.png`.
  - *Expected Result:* False (No Alert)
  - *Observed Result:* False (PASS)

### Rule 14: Cross-site scripting probe detected
- **Description:** Detects common XSS payload signatures in HTTP parameters.
- **Enabled:** True
- **Implementation:** `evaluate_pattern_rule()` in `backend/app/rules/engine.py`
- **Positive Scenario (SCEN-XSS-POS):** GET request with path `/profile?name=<script>alert(document.cookie)</script>`.
  - *Expected Result:* True (Alert Triggered)
  - *Observed Result:* True (PASS)
- **Negative Scenario (SCEN-XSS-NEG):** GET request with path `/profile?name=AliceSmith`.
  - *Expected Result:* False (No Alert)
  - *Observed Result:* False (PASS)
