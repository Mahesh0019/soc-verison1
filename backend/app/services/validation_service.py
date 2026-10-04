"""
backend/app/services/validation_service.py

Detection Validation Engine (Phase 10):
- Automated rule regression testing and detection-as-code CI/CD guardrails.
- Curates positive (attack payload) and negative (benign baseline) test scenarios
  for all 14 built-in detection rules.
- Measures detection accuracy, latency (ms), and rule regression health.
- Persists all validation assertions to the validation_tests table for continuous audit.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import Alert, AlertEvent, DetectionRule, NormalizedEvent, ThreatIndicator, ValidationTest
from app.rules.engine import (
    evaluate_blacklist,
    evaluate_pattern_rule,
    evaluate_success_after_failures,
    evaluate_threshold_rule,
)


# Standard Scenario Catalog for all 14 Built-in Rules
BUILTIN_SCENARIOS: list[dict[str, Any]] = [
    # 1. SQL Injection
    {
        "rule_keyword": "sql injection",
        "scenario_id": "SCEN-SQLI-POS",
        "test_name": "SQL Injection exploitation probe with UNION SELECT",
        "expected_result": True,
        "burst_count": 1,
        "events": [
            {
                "event_type": "web_attack",
                "event_category": "web",
                "severity": "critical",
                "source_ip": "198.51.100.201",
                "username": "attacker",
                "message": "SQLi probe: SELECT * FROM users WHERE '1'='1'",
                "request_path": "/rest/products/search?q=' UNION SELECT 1,username,password FROM users--",
                "http_method": "GET",
                "status_code": 500,
            }
        ],
    },
    {
        "rule_keyword": "sql injection",
        "scenario_id": "SCEN-SQLI-NEG",
        "test_name": "Benign search query with alphanumeric parameters",
        "expected_result": False,
        "burst_count": 1,
        "events": [
            {
                "event_type": "web_request",
                "event_category": "web",
                "severity": "low",
                "source_ip": "198.51.100.202",
                "username": "customer_alice",
                "message": "Product search query",
                "request_path": "/rest/products/search?q=apple_juice",
                "http_method": "GET",
                "status_code": 200,
            }
        ],
    },
    # 2. Path Traversal
    {
        "rule_keyword": "path traversal",
        "scenario_id": "SCEN-TRAV-POS",
        "test_name": "Directory path traversal targeting system files",
        "expected_result": True,
        "burst_count": 1,
        "events": [
            {
                "event_type": "web_attack",
                "event_category": "web",
                "severity": "high",
                "source_ip": "198.51.100.203",
                "username": "attacker",
                "message": "Path traversal attempt: ../../etc/passwd",
                "request_path": "/ftp/../../etc/passwd",
                "http_method": "GET",
                "status_code": 403,
            }
        ],
    },
    {
        "rule_keyword": "path traversal",
        "scenario_id": "SCEN-TRAV-NEG",
        "test_name": "Benign static asset request",
        "expected_result": False,
        "burst_count": 1,
        "events": [
            {
                "event_type": "web_request",
                "event_category": "web",
                "severity": "low",
                "source_ip": "198.51.100.204",
                "username": "customer_bob",
                "message": "Fetch logo image",
                "request_path": "/assets/public/images/logo.png",
                "http_method": "GET",
                "status_code": 200,
            }
        ],
    },
    # 3. Cross-Site Scripting
    {
        "rule_keyword": "cross-site scripting",
        "scenario_id": "SCEN-XSS-POS",
        "test_name": "Reflected XSS script payload injection",
        "expected_result": True,
        "burst_count": 1,
        "events": [
            {
                "event_type": "web_attack",
                "event_category": "web",
                "severity": "high",
                "source_ip": "198.51.100.205",
                "username": "attacker",
                "message": "XSS attack: <script>alert(document.cookie)</script>",
                "request_path": "/profile?name=<script>alert(document.cookie)</script>",
                "http_method": "GET",
                "status_code": 200,
            }
        ],
    },
    {
        "rule_keyword": "cross-site scripting",
        "scenario_id": "SCEN-XSS-NEG",
        "test_name": "Standard profile view request",
        "expected_result": False,
        "burst_count": 1,
        "events": [
            {
                "event_type": "web_request",
                "event_category": "web",
                "severity": "low",
                "source_ip": "198.51.100.206",
                "username": "alice",
                "message": "Profile view",
                "request_path": "/profile?name=AliceSmith",
                "http_method": "GET",
                "status_code": 200,
            }
        ],
    },
    # 4. Multiple failed login attempts
    {
        "rule_keyword": "failed login attempts",
        "scenario_id": "SCEN-FAILLOGIN-POS",
        "test_name": "Repeated failed login attempts exceeding threshold",
        "expected_result": True,
        "burst_count": 6,
        "events": [
            {
                "event_type": "failed_login",
                "event_category": "authentication",
                "severity": "high",
                "source_ip": "198.51.100.207",
                "username": "target_user",
                "message": "Authentication failed for user target_user",
                "request_path": "/api/auth/login",
                "status_code": 401,
            }
        ],
    },
    {
        "rule_keyword": "failed login attempts",
        "scenario_id": "SCEN-FAILLOGIN-NEG",
        "test_name": "Single accidental mistyped password below threshold",
        "expected_result": False,
        "burst_count": 1,
        "events": [
            {
                "event_type": "failed_login",
                "event_category": "authentication",
                "severity": "medium",
                "source_ip": "198.51.100.208",
                "username": "normal_user",
                "message": "Authentication failed",
                "request_path": "/api/auth/login",
                "status_code": 401,
            }
        ],
    },
    # 5. Successful login after failed attempts
    {
        "rule_keyword": "successful login after failed",
        "scenario_id": "SCEN-SEQAUTH-POS",
        "test_name": "Brute force sequence culminating in successful authentication",
        "expected_result": True,
        "custom_sequence": [
            {"event_type": "failed_login", "username": "admin", "source_ip": "198.51.100.209"},
            {"event_type": "failed_login", "username": "admin", "source_ip": "198.51.100.209"},
            {"event_type": "failed_login", "username": "admin", "source_ip": "198.51.100.209"},
            {"event_type": "successful_login", "username": "admin", "source_ip": "198.51.100.209"},
        ],
    },
    {
        "rule_keyword": "successful login after failed",
        "scenario_id": "SCEN-SEQAUTH-NEG",
        "test_name": "Direct successful login without preceding failures",
        "expected_result": False,
        "burst_count": 1,
        "events": [
            {
                "event_type": "successful_login",
                "username": "admin",
                "source_ip": "198.51.100.210",
                "message": "Login success",
            }
        ],
    },
    # 6. Suspicious admin login
    {
        "rule_keyword": "suspicious admin login",
        "scenario_id": "SCEN-ADMIN-POS",
        "test_name": "Successful admin login event trigger",
        "expected_result": True,
        "burst_count": 1,
        "events": [
            {
                "event_type": "successful_login",
                "username": "admin",
                "source_ip": "198.51.100.211",
                "message": "Admin session created",
            }
        ],
    },
    {
        "rule_keyword": "suspicious admin login",
        "scenario_id": "SCEN-ADMIN-NEG",
        "test_name": "Standard user session login",
        "expected_result": False,
        "burst_count": 1,
        "events": [
            {
                "event_type": "successful_login",
                "username": "regular_alice",
                "source_ip": "198.51.100.212",
                "message": "User login success",
            }
        ],
    },
    # 7. Unusual country login
    {
        "rule_keyword": "unusual country",
        "scenario_id": "SCEN-GEO-POS",
        "test_name": "Login from outside established geographic baseline",
        "expected_result": True,
        "burst_count": 1,
        "events": [
            {
                "event_category": "authentication",
                "event_type": "login",
                "geo_country": "RU",
                "source_ip": "198.51.100.213",
                "username": "user1",
                "message": "Remote login from non-baseline country",
            }
        ],
    },
    {
        "rule_keyword": "unusual country",
        "scenario_id": "SCEN-GEO-NEG",
        "test_name": "Login from standard baseline country (US)",
        "expected_result": False,
        "burst_count": 1,
        "events": [
            {
                "event_category": "authentication",
                "event_type": "login",
                "geo_country": "US",
                "source_ip": "198.51.100.214",
                "username": "user1",
                "message": "Baseline login",
            }
        ],
    },
    # 8. High number of 404 responses
    {
        "rule_keyword": "high number of 404",
        "scenario_id": "SCEN-404-POS",
        "test_name": "Burst of 404 responses exceeding threshold",
        "expected_result": True,
        "burst_count": 12,
        "events": [
            {
                "status_code": 404,
                "event_type": "web_request",
                "source_ip": "198.51.100.215",
                "message": "Resource not found 404",
                "request_path": "/missing/endpoint",
            }
        ],
    },
    {
        "rule_keyword": "high number of 404",
        "scenario_id": "SCEN-404-NEG",
        "test_name": "Occasional 404 below threshold",
        "expected_result": False,
        "burst_count": 2,
        "events": [
            {
                "status_code": 404,
                "event_type": "web_request",
                "source_ip": "198.51.100.216",
                "message": "Single 404",
                "request_path": "/favicon.ico",
            }
        ],
    },
    # 9. Possible directory brute force
    {
        "rule_keyword": "directory brute force",
        "scenario_id": "SCEN-DIRBRUTE-POS",
        "test_name": "Directory enumeration burst in 4xx range",
        "expected_result": True,
        "burst_count": 16,
        "events": [
            {
                "event_category": "web",
                "status_code": 404,
                "source_ip": "198.51.100.217",
                "message": "Web probe miss",
                "request_path": "/hidden/admin_panel",
            }
        ],
    },
    {
        "rule_keyword": "directory brute force",
        "scenario_id": "SCEN-DIRBRUTE-NEG",
        "test_name": "Low volume web 4xx below threshold",
        "expected_result": False,
        "burst_count": 2,
        "events": [
            {
                "event_category": "web",
                "status_code": 404,
                "source_ip": "198.51.100.218",
                "message": "Minor 404",
                "request_path": "/blog/old-post",
            }
        ],
    },
    # 10. Repeated sensitive path access
    {
        "rule_keyword": "sensitive path access",
        "scenario_id": "SCEN-SENSPATH-POS",
        "test_name": "Repeated probing of sensitive administration endpoints",
        "expected_result": True,
        "burst_count": 5,
        "events": [
            {
                "request_path": "/admin/dashboard",
                "source_ip": "198.51.100.219",
                "event_type": "web_request",
                "message": "Probe /admin",
            }
        ],
    },
    {
        "rule_keyword": "sensitive path access",
        "scenario_id": "SCEN-SENSPATH-NEG",
        "test_name": "Single sensitive path access below threshold",
        "expected_result": False,
        "burst_count": 1,
        "events": [
            {
                "request_path": "/admin/dashboard",
                "source_ip": "198.51.100.220",
                "event_type": "web_request",
                "message": "Probe /admin",
            }
        ],
    },
    # 11. Large request volume burst
    {
        "rule_keyword": "large request volume",
        "scenario_id": "SCEN-VOLBURST-POS",
        "test_name": "Extreme traffic volume burst exceeding threshold",
        "expected_result": True,
        "burst_count": 65,
        "events": [
            {
                "event_category": "web",
                "source_ip": "198.51.100.221",
                "event_type": "web_request",
                "message": "High rate web traffic",
                "request_path": "/api/feed",
            }
        ],
    },
    {
        "rule_keyword": "large request volume",
        "scenario_id": "SCEN-VOLBURST-NEG",
        "test_name": "Standard volume web traffic below threshold",
        "expected_result": False,
        "burst_count": 10,
        "events": [
            {
                "event_category": "web",
                "source_ip": "198.51.100.222",
                "event_type": "web_request",
                "message": "Normal web traffic",
                "request_path": "/api/feed",
            }
        ],
    },
    # 12. Suspicious user agent
    {
        "rule_keyword": "suspicious user agent",
        "scenario_id": "SCEN-USERAGENT-POS",
        "test_name": "Automated attack tool user agent signature",
        "expected_result": True,
        "burst_count": 1,
        "events": [
            {
                "user_agent": "sqlmap/1.6#stable (https://sqlmap.org)",
                "source_ip": "198.51.100.223",
                "event_type": "web_request",
                "message": "Automated scan request",
            }
        ],
    },
    {
        "rule_keyword": "suspicious user agent",
        "scenario_id": "SCEN-USERAGENT-NEG",
        "test_name": "Standard browser user agent",
        "expected_result": False,
        "burst_count": 1,
        "events": [
            {
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                "source_ip": "198.51.100.224",
                "event_type": "web_request",
                "message": "Browser request",
            }
        ],
    },
    # 13. Firewall denied traffic spike
    {
        "rule_keyword": "firewall denied traffic",
        "scenario_id": "SCEN-FWDENY-POS",
        "test_name": "Firewall drops spike exceeding threshold",
        "expected_result": True,
        "burst_count": 22,
        "events": [
            {
                "event_type": "firewall_denied",
                "source_ip": "198.51.100.225",
                "message": "Drop incoming connection on port 22",
            }
        ],
    },
    {
        "rule_keyword": "firewall denied traffic",
        "scenario_id": "SCEN-FWDENY-NEG",
        "test_name": "Isolated firewall drops below threshold",
        "expected_result": False,
        "burst_count": 3,
        "events": [
            {
                "event_type": "firewall_denied",
                "source_ip": "198.51.100.226",
                "message": "Drop port 80",
            }
        ],
    },
    # 14. Blacklist indicator match
    {
        "rule_keyword": "blacklisted indicator",
        "scenario_id": "SCEN-BLACKLIST-POS",
        "test_name": "Traffic originating from active Threat Intelligence IOC",
        "expected_result": True,
        "burst_count": 1,
        "requires_ti": True,
        "events": [
            {
                "source_ip": "203.0.113.66",
                "event_type": "web_request",
                "message": "Connection from blacklisted IP",
            }
        ],
    },
    {
        "rule_keyword": "blacklisted indicator",
        "scenario_id": "SCEN-BLACKLIST-NEG",
        "test_name": "Traffic from clean unlisted source IP",
        "expected_result": False,
        "burst_count": 1,
        "events": [
            {
                "source_ip": "198.51.100.227",
                "event_type": "web_request",
                "message": "Clean traffic",
            }
        ],
    },
]


def evaluate_single_rule(db: Session, rule: DetectionRule, events: list[NormalizedEvent]) -> bool:
    """Evaluates a single DetectionRule against a sequence of events and returns whether an alert fired."""
    rule_type = rule.conditions_json.get("type", "threshold")
    alert_ids: set[int] = set()

    if rule_type == "sequence_success_after_failures":
        alert_ids = evaluate_success_after_failures(db, rule, events)
    elif rule_type == "blacklist":
        alert_ids = evaluate_blacklist(db, rule, events)
    elif rule_type == "pattern":
        alert_ids = evaluate_pattern_rule(db, rule, events)
    else:
        alert_ids = evaluate_threshold_rule(db, rule, events)

    return len(alert_ids) > 0


def run_validation_test(
    db: Session,
    rule: DetectionRule,
    scenario: dict[str, Any],
) -> ValidationTest:
    """
    Executes a specific validation test scenario against a DetectionRule,
    measuring accuracy and execution latency.
    """
    now = datetime.now(UTC)
    events_to_create = []

    # Ensure TI indicator if required
    if scenario.get("requires_ti"):
        ti = db.query(ThreatIndicator).filter(ThreatIndicator.value == "203.0.113.66").first()
        if not ti:
            db.add(ThreatIndicator(type="ip", value="203.0.113.66", threat_type="botnet", confidence=0.9))
            db.flush()

    if "custom_sequence" in scenario:
        for i, raw in enumerate(scenario["custom_sequence"]):
            ev = NormalizedEvent(
                timestamp=now - timedelta(seconds=(len(scenario["custom_sequence"]) - i) * 5),
                source_ip=raw.get("source_ip", "198.51.100.200"),
                destination_ip=raw.get("destination_ip"),
                username=raw.get("username", "test_user"),
                event_type=raw.get("event_type", "web_request"),
                event_category=raw.get("event_category", "web"),
                severity=raw.get("severity", "medium"),
                message=raw.get("message", "Validation test event"),
                request_path=raw.get("request_path"),
                http_method=raw.get("http_method", "GET"),
                status_code=raw.get("status_code", 200),
                user_agent=raw.get("user_agent"),
                geo_country=raw.get("geo_country"),
            )
            db.add(ev)
            db.flush()
            events_to_create.append(ev)
    else:
        burst_count = scenario.get("burst_count", 1)
        base_events = scenario.get("events", [])
        for i in range(burst_count):
            for raw in base_events:
                ev = NormalizedEvent(
                    timestamp=now - timedelta(seconds=(burst_count - i) * 2),
                    source_ip=raw.get("source_ip", "198.51.100.200"),
                    destination_ip=raw.get("destination_ip"),
                    username=raw.get("username", "test_user"),
                    event_type=raw.get("event_type", "web_request"),
                    event_category=raw.get("event_category", "web"),
                    severity=raw.get("severity", "medium"),
                    message=raw.get("message", "Validation test event"),
                    request_path=raw.get("request_path"),
                    http_method=raw.get("http_method", "GET"),
                    status_code=raw.get("status_code", 200),
                    user_agent=raw.get("user_agent"),
                    geo_country=raw.get("geo_country"),
                )
                db.add(ev)
                db.flush()
                events_to_create.append(ev)

    # Measure evaluation latency
    start_time = time.perf_counter()
    triggered = evaluate_single_rule(db, rule, events_to_create)
    duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

    expected = bool(scenario.get("expected_result", True))
    passed = (triggered == expected)

    details = {
        "event_count": len(events_to_create),
        "rule_type": rule.conditions_json.get("type", "threshold"),
        "rule_threshold": rule.threshold,
        "rule_window_minutes": rule.time_window_minutes,
        "scenario_events_snippet": [e.message[:50] for e in events_to_create[:3]],
    }

    test_record = ValidationTest(
        rule_id=rule.id,
        rule_version="1.0",
        test_name=scenario.get("test_name", f"Validation of {rule.name}"),
        test_scenario_id=scenario.get("scenario_id", f"SCEN-{rule.id}-{int(time.time())}"),
        expected_result=expected,
        observed_result=triggered,
        passed=passed,
        execution_time_ms=duration_ms,
        details_json=details,
    )
    db.add(test_record)
    db.commit()
    db.refresh(test_record)
    return test_record


def run_rule_validation_suite(db: Session, rule_id: int) -> dict[str, Any]:
    """Runs all matching positive and negative scenarios for a specific rule."""
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise ValueError(f"DetectionRule {rule_id} not found")

    matching_scenarios = []
    rule_name_lower = rule.name.lower()
    for sc in BUILTIN_SCENARIOS:
        keyword = sc.get("rule_keyword", "").lower()
        if keyword and keyword in rule_name_lower:
            matching_scenarios.append(sc)

    # If no specific keyword scenario matches, synthesize standard positive/negative tests
    if not matching_scenarios:
        matching_scenarios = [
            {
                "scenario_id": f"GEN-POS-{rule.id}",
                "test_name": f"Generic Positive Validation for {rule.name}",
                "expected_result": True,
                "burst_count": max(rule.threshold, 2),
                "events": [
                    {
                        "event_type": "security_test",
                        "severity": rule.severity,
                        "source_ip": "198.51.100.220",
                        "message": f"Simulated trigger for {rule.name}",
                        "request_path": "/test/trigger",
                    }
                ],
            }
        ]

    results = [run_validation_test(db, rule, sc) for sc in matching_scenarios]
    passed_count = sum(1 for r in results if r.passed)
    total_count = len(results)

    return {
        "rule_id": rule.id,
        "rule_name": rule.name,
        "total_tests": total_count,
        "passed_tests": passed_count,
        "failed_tests": total_count - passed_count,
        "pass_rate": round(passed_count / max(1, total_count), 2),
        "results": results,
    }


def run_all_validation_tests(db: Session) -> dict[str, Any]:
    """Executes the complete regression test harness across all active DetectionRules."""
    rules = db.query(DetectionRule).filter(DetectionRule.enabled.is_(True)).all()
    all_results: list[ValidationTest] = []
    total_start = time.perf_counter()

    for rule in rules:
        suite = run_rule_validation_suite(db, rule.id)
        all_results.extend(suite["results"])

    total_time_ms = round((time.perf_counter() - total_start) * 1000.0, 2)
    passed_count = sum(1 for r in all_results if r.passed)
    total_count = len(all_results)
    pass_rate = round(passed_count / max(1, total_count), 2)

    return {
        "total_tests": total_count,
        "passed_tests": passed_count,
        "failed_tests": total_count - passed_count,
        "pass_rate": pass_rate,
        "execution_time_ms_total": total_time_ms,
        "results": all_results,
    }


def get_validation_summary(db: Session) -> dict[str, Any]:
    """Computes overall detection health, test history, and rule regression metrics."""
    records = db.query(ValidationTest).all()
    total_runs = len(records)
    if total_runs == 0:
        run_all = run_all_validation_tests(db)
        records = run_all["results"]
        total_runs = len(records)

    total_passed = sum(1 for r in records if r.passed)
    total_failed = total_runs - total_passed
    overall_pass_rate = round(total_passed / max(1, total_runs), 2)

    # Per-rule health breakdown
    rules = db.query(DetectionRule).all()
    rule_health = []
    for rule in rules:
        rule_tests = [r for r in records if r.rule_id == rule.id]
        if rule_tests:
            p_count = sum(1 for t in rule_tests if t.passed)
            t_count = len(rule_tests)
            rate = round(p_count / t_count, 2)
            status = "HEALTHY" if rate >= 0.85 else "DEGRADED" if rate >= 0.50 else "REGRESSED"
            rule_health.append({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "total_tests": t_count,
                "passed_tests": p_count,
                "pass_rate": rate,
                "status": status,
            })

    return {
        "total_runs": total_runs,
        "overall_pass_rate": overall_pass_rate,
        "total_passed": total_passed,
        "total_failed": total_failed,
        "rules_tested_count": len(rule_health),
        "rule_health": rule_health,
    }
