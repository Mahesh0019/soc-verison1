"""
backend/app/services/evaluation_phase11.py

Phase 11 Stage 2: Offline Detection Evaluation Engine.
Performs hermetic, isolated evaluation of existing detection rules,
Socket.IO polling noise, and RULE-008 candidate parameter sweeps.
Guaranteed to run in-memory with zero production side effects.
"""

from __future__ import annotations

import json
import statistics
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.models import (
    Alert,
    AlertEvent,
    DetectionRule,
    Evidence,
    Incident,
    IncidentAlert,
    NormalizedEvent,
    ThreatIndicator,
)
from app.rules.builtin import builtin_rules
from app.rules.correlation import correlate_incidents
from app.rules.engine import evaluate_rules_for_events, event_matches_filters
from app.services.evidence_service import build_evidence_package
from app.services.seed import ensure_builtin_rules, ensure_indicators


@dataclass
class ScenarioEvent:
    offset_seconds: float
    source_ip: str
    method: str
    path: str
    status_code: int = 200
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    event_category: str = "web"
    event_type: str = "web_request"
    severity: str = "low"
    message: str = ""
    username: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LabeledScenario:
    scenario_id: str
    name: str
    category: str  # "benign" or "attack"
    duration_seconds: float
    description: str
    expected_rule_ids: List[str]
    should_alert: bool
    events: List[ScenarioEvent]


@dataclass
class StageLatency:
    t_ingest_ms: float
    t_eval_ms: float
    t_evidence_ms: float
    t_correlate_ms: float
    t_total_ms: float


@dataclass
class ScenarioRunResult:
    scenario_id: str
    category: str
    event_count: int
    duration_seconds: float
    fired_rule_ids: List[str]
    alert_count: int
    incident_count: int
    classification: str  # "TP", "FP", "TN", "FN"
    duplicate_alerts: int
    missed_rule_ids: List[str]
    latency: StageLatency
    details: str = ""


@dataclass
class ConfusionMatrixMetrics:
    total_scenarios: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    false_positive_rate: float
    false_negative_rate: float
    f1_score: float
    duplicate_alerts: int
    median_latency_ms: float
    p95_latency_ms: float


# ---------------------------------------------------------------------------
# Scenario Definitions
# ---------------------------------------------------------------------------

def generate_benign_01() -> LabeledScenario:
    """BENIGN-01: Standard User Browsing with Background Polling (5m, 79 reqs)"""
    events: List[ScenarioEvent] = []
    ip = "198.51.100.101"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    # Initial HTML & bundles
    events.append(ScenarioEvent(0.0, ip, "GET", "/", 200, ua, message="Initial page load"))
    for i in range(1, 9):
        events.append(ScenarioEvent(0.5 * i, ip, "GET", f"/assets/bundle_{i}.js", 200, ua, message="Asset load"))

    # Product image thumbnails
    for i in range(1, 16):
        events.append(ScenarioEvent(5.0 + (i * 0.4), ip, "GET", f"/assets/public/images/products/item_{i}.png", 200, ua, message="Image thumbnail"))

    # Browsing actions
    events.append(ScenarioEvent(30.0, ip, "GET", "/rest/products/search?q=apple", 200, ua, message="Product search apple"))
    events.append(ScenarioEvent(45.0, ip, "GET", "/rest/products/1", 200, ua, message="View product 1"))
    events.append(ScenarioEvent(70.0, ip, "GET", "/rest/products/search?q=orange", 200, ua, message="Product search orange"))
    events.append(ScenarioEvent(90.0, ip, "GET", "/rest/products/2", 200, ua, message="View product 2"))
    events.append(ScenarioEvent(120.0, ip, "GET", "/rest/products/3", 200, ua, message="View product 3"))
    events.append(ScenarioEvent(150.0, ip, "GET", "/rest/admin/application-version", 200, ua, message="App version check"))

    # 50 Socket.IO polling requests every 6 seconds from t=6 to t=300
    for i in range(1, 51):
        t = 6.0 * i
        events.append(ScenarioEvent(t, ip, "GET", f"/health/socket.io/?EIO=4&transport=polling&t={int(t*1000)}", 200, ua, message="Socket.IO heartbeat poll"))

    # Sort deterministically by offset
    events.sort(key=lambda e: e.offset_seconds)

    return LabeledScenario(
        scenario_id="BENIGN-01",
        name="Standard User Browsing with Background Polling",
        category="benign",
        duration_seconds=300.0,
        description="Standard 5-minute user browsing session with 50 Socket.IO heartbeats and 29 web requests (79 total).",
        expected_rule_ids=[],
        should_alert=False,
        events=events,
    )


def generate_benign_02() -> LabeledScenario:
    """BENIGN-02: Standby / Idle Tab Background Polling (10m, 100 reqs, max 50 / 5m)"""
    events: List[ScenarioEvent] = []
    ip = "198.51.100.102"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    for i in range(1, 101):
        t = 6.0 * i
        events.append(ScenarioEvent(t, ip, "GET", f"/health/socket.io/?EIO=4&transport=polling&t={int(t*1000)}", 200, ua, message="Socket.IO standby poll"))

    return LabeledScenario(
        scenario_id="BENIGN-02",
        name="Standby / Idle Tab Background Polling",
        category="benign",
        duration_seconds=600.0,
        description="User leaves tab idle for 10 minutes. Generates 100 polling requests (50 per 5m window).",
        expected_rule_ids=[],
        should_alert=False,
        events=events,
    )


def generate_benign_03() -> LabeledScenario:
    """BENIGN-03: Rapid Static Asset Loading (15s, 65 reqs)"""
    events: List[ScenarioEvent] = []
    ip = "198.51.100.103"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    for i in range(1, 66):
        t = 0.2 * i
        events.append(ScenarioEvent(t, ip, "GET", f"/assets/public/images/products/photo_{i}.jpg", 200, ua, message="Rapid image load"))

    return LabeledScenario(
        scenario_id="BENIGN-03",
        name="Rapid Static Asset Loading",
        category="benign",
        duration_seconds=15.0,
        description="Browser loads 65 static catalog thumbnails concurrently within 15 seconds.",
        expected_rule_ids=[],
        should_alert=False,
        events=events,
    )


def generate_benign_04() -> LabeledScenario:
    """BENIGN-04: Routine Admin Lookups (2m, 5 reqs)"""
    events: List[ScenarioEvent] = []
    ip = "198.51.100.104"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    events.append(ScenarioEvent(10.0, ip, "GET", "/api/users", 200, ua, message="List users"))
    events.append(ScenarioEvent(30.0, ip, "GET", "/health", 200, ua, message="Health check"))
    events.append(ScenarioEvent(50.0, ip, "GET", "/rest/admin/application-version", 200, ua, message="Version check"))
    events.append(ScenarioEvent(70.0, ip, "GET", "/rest/products/1", 200, ua, message="Product inspect"))
    events.append(ScenarioEvent(100.0, ip, "GET", "/api/system/status", 200, ua, message="System status"))

    return LabeledScenario(
        scenario_id="BENIGN-04",
        name="Routine Admin Navigation",
        category="benign",
        duration_seconds=120.0,
        description="Authenticated admin performs 5 routine lookups over 2 minutes.",
        expected_rule_ids=[],
        should_alert=False,
        events=events,
    )


def generate_poll_scenarios() -> List[LabeledScenario]:
    """POLL-01 to POLL-06: Polling Duration & Mixed Traffic Matrix"""
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    scenarios: List[LabeledScenario] = []

    # POLL-01: 1 minute (10 polling requests)
    e1 = [ScenarioEvent(6.0 * i, "198.51.100.111", "GET", f"/health/socket.io/?t={i}", 200, ua) for i in range(1, 11)]
    scenarios.append(LabeledScenario("POLL-01", "Standby Polling 1 Minute", "benign", 60.0, "10 polling requests", [], False, e1))

    # POLL-02: 3 minutes (30 polling requests)
    e2 = [ScenarioEvent(6.0 * i, "198.51.100.112", "GET", f"/health/socket.io/?t={i}", 200, ua) for i in range(1, 31)]
    scenarios.append(LabeledScenario("POLL-02", "Standby Polling 3 Minutes", "benign", 180.0, "30 polling requests", [], False, e2))

    # POLL-03: 5 minutes (50 polling requests)
    e3 = [ScenarioEvent(6.0 * i, "198.51.100.113", "GET", f"/health/socket.io/?t={i}", 200, ua) for i in range(1, 51)]
    scenarios.append(LabeledScenario("POLL-03", "Standby Polling 5 Minutes", "benign", 300.0, "50 polling requests", [], False, e3))

    # POLL-04: 6 minutes (60 polling requests, 50 in last 5m)
    e4 = [ScenarioEvent(6.0 * i, "198.51.100.114", "GET", f"/health/socket.io/?t={i}", 200, ua) for i in range(1, 61)]
    scenarios.append(LabeledScenario("POLL-04", "Standby Polling 6 Minutes", "benign", 360.0, "60 polling requests over 6m", [], False, e4))

    # POLL-05: 10 minutes (100 polling requests, max 50 per 5m)
    e5 = [ScenarioEvent(6.0 * i, "198.51.100.115", "GET", f"/health/socket.io/?t={i}", 200, ua) for i in range(1, 101)]
    scenarios.append(LabeledScenario("POLL-05", "Standby Polling 10 Minutes", "benign", 600.0, "100 polling requests over 10m", [], False, e5))

    # POLL-06: 5m + Browsing (50 polling + 25 browsing = 75 requests)
    e6: List[ScenarioEvent] = []
    ip6 = "198.51.100.116"
    for i in range(1, 51):
        e6.append(ScenarioEvent(6.0 * i, ip6, "GET", f"/health/socket.io/?t={i}", 200, ua))
    for i in range(1, 26):
        e6.append(ScenarioEvent(10.0 * i, ip6, "GET", f"/rest/products/{i}", 200, ua))
    e6.sort(key=lambda e: e.offset_seconds)
    scenarios.append(LabeledScenario("POLL-06", "5m Polling with Light Browsing", "benign", 300.0, "50 polling + 25 browsing requests in 5m", [], False, e6))

    # POLL-ERR: 15 404s on health endpoint (transient upstream failure)
    e_err = [ScenarioEvent(15.0 * i, "198.51.100.117", "GET", f"/health/socket.io/?t={i}", 404, ua, message="404 Not Found") for i in range(1, 16)]
    scenarios.append(LabeledScenario("POLL-ERR", "Intermittent 404s on Health Socket", "benign", 300.0, "15 404 responses to /health/socket.io/ over 5m", [], False, e_err))

    return scenarios


def generate_attack_01() -> LabeledScenario:
    """ATTACK-01: High-Rate Content Scraper / Product Crawler (30s, 300 reqs)"""
    events: List[ScenarioEvent] = []
    ip = "198.51.100.201"
    ua = "Python-urllib/3.11"

    for i in range(1, 301):
        t = 0.1 * i
        events.append(ScenarioEvent(t, ip, "GET", f"/rest/products/{i}", 200, ua, message=f"Product scrape {i}"))

    return LabeledScenario(
        scenario_id="ATTACK-01",
        name="High-Rate Content Scraper / Product Crawler",
        category="attack",
        duration_seconds=30.0,
        description="Automated scraper enumerates 300 product IDs at 10 req/s within 30 seconds.",
        expected_rule_ids=["RULE-008"],
        should_alert=True,
        events=events,
    )


def generate_attack_02() -> LabeledScenario:
    """ATTACK-02: Directory Brute Force and Endpoint Fuzzing (60s, 500 reqs)"""
    events: List[ScenarioEvent] = []
    ip = "198.51.100.202"
    ua = "gobuster/3.1.0"
    paths = [
        "/backup.zip", "/.git/config", "/admin.php", "/wp-login.php",
        "/config.json", "/.env", "/secret.key", "/db_dump.sql",
        "/test.php", "/api/v1/debug"
    ]

    for i in range(1, 501):
        t = 0.12 * i
        target_path = paths[i % len(paths)]
        code = 403 if ".env" in target_path or "secret" in target_path else 404
        events.append(ScenarioEvent(t, ip, "GET", target_path, code, ua, message=f"Fuzzing path {target_path}"))

    return LabeledScenario(
        scenario_id="ATTACK-02",
        name="Directory Brute Force and Endpoint Fuzzing",
        category="attack",
        duration_seconds=60.0,
        description="Automated fuzzer generates 500 4xx client errors probing for hidden files in 60s.",
        expected_rule_ids=["RULE-005", "RULE-006", "RULE-008"],
        should_alert=True,
        events=events,
    )


def generate_attack_03() -> LabeledScenario:
    """ATTACK-03: Web Application SQL Injection Probes"""
    events: List[ScenarioEvent] = []
    ip = "198.51.100.203"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

    events.append(ScenarioEvent(
        1.0, ip, "GET",
        "/rest/products/search?q=' UNION SELECT 1,username,password FROM users--",
        500, ua,
        event_type="web_attack",
        message="SQLi probe in search: UNION SELECT 1,username,password FROM users--"
    ))
    events.append(ScenarioEvent(
        5.0, ip, "POST",
        "/rest/user/login",
        200, ua,
        event_type="web_attack",
        message="SQLi login bypass: ' OR '1'='1",
        extra={"body": '{"email": "\' OR \'1\'=\'1", "password": "x"}'}
    ))

    return LabeledScenario(
        scenario_id="ATTACK-03",
        name="Web Application SQL Injection Probes",
        category="attack",
        duration_seconds=10.0,
        description="Targeted SQL injection queries against product search and login endpoints.",
        expected_rule_ids=["RULE-012"],
        should_alert=True,
        events=events,
    )


def generate_attack_04() -> LabeledScenario:
    """ATTACK-04: Directory Path Traversal Probes"""
    events: List[ScenarioEvent] = []
    ip = "198.51.100.204"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

    events.append(ScenarioEvent(
        2.0, ip, "GET",
        "/ftp/../../../../etc/passwd",
        403, ua,
        event_type="web_attack",
        message="Path traversal attempt: ../../../../etc/passwd"
    ))
    events.append(ScenarioEvent(
        6.0, ip, "GET",
        "/public/images/..%2f..%2f..%2fwin.ini",
        404, ua,
        event_type="web_attack",
        message="Encoded path traversal: ..%2f..%2f..%2fwin.ini"
    ))

    return LabeledScenario(
        scenario_id="ATTACK-04",
        name="Directory Path Traversal Probes",
        category="attack",
        duration_seconds=10.0,
        description="Path traversal requests targeting Unix and Windows sensitive system files.",
        expected_rule_ids=["RULE-013"],
        should_alert=True,
        events=events,
    )


def generate_attack_05() -> LabeledScenario:
    """ATTACK-05: Automated Vulnerability Scanner User Agent"""
    events: List[ScenarioEvent] = []
    ip = "198.51.100.205"
    ua = "sqlmap/1.6#stable (https://sqlmap.org)"

    for i in range(1, 4):
        events.append(ScenarioEvent(
            i * 1.5, ip, "GET", f"/rest/products/{i}", 200, ua,
            message="Scanner reconnaissance request"
        ))

    return LabeledScenario(
        scenario_id="ATTACK-05",
        name="Automated Vulnerability Scanner User Agent",
        category="attack",
        duration_seconds=10.0,
        description="Reconnaissance requests utilizing recognizable offensive scanner User-Agent.",
        expected_rule_ids=["RULE-009"],
        should_alert=True,
        events=events,
    )


def generate_attack_06() -> LabeledScenario:
    """ATTACK-06: Multi-Stage Progression Killchain (900s, 140 reqs)"""
    events: List[ScenarioEvent] = []
    ip = "198.51.100.206"
    ua = "Mozilla/5.0 (X11; Linux x86_64)"

    # Stage 1: Reconnaissance (Content Crawl - 100 requests in 60s)
    for i in range(1, 101):
        events.append(ScenarioEvent(0.5 * i, ip, "GET", f"/rest/products/{i}", 200, ua, message=f"Crawl product {i}"))

    # Stage 2: Probing (Directory fuzzing - 30 404s from t=120 to t=240)
    fuzz_paths = ["/.env", "/admin.php", "/config.json", "/backup.tar.gz", "/private.key"]
    for i in range(1, 31):
        events.append(ScenarioEvent(120.0 + (i * 3.5), ip, "GET", fuzz_paths[i % len(fuzz_paths)], 404, ua, message="Probing admin path"))

    # Stage 3: Exploitation (SQLi probe in search at t=300)
    events.append(ScenarioEvent(
        300.0, ip, "GET",
        "/rest/products/search?q=' UNION SELECT 1,2,3--",
        500, ua,
        event_type="web_attack",
        message="SQLi exploitation attempt"
    ))

    # Stage 4: Credential Testing (6 failed logins from t=400 to t=460)
    for i in range(1, 7):
        events.append(ScenarioEvent(
            400.0 + (i * 10.0), ip, "POST",
            "/rest/user/login",
            401, ua,
            event_type="failed_login",
            message=f"Failed login attempt {i} for admin",
            username="admin"
        ))

    events.sort(key=lambda e: e.offset_seconds)

    return LabeledScenario(
        scenario_id="ATTACK-06",
        name="Multi-Stage Progression Killchain",
        category="attack",
        duration_seconds=900.0,
        description="Comprehensive killchain executing Recon (100 reqs) -> Probing (30 404s) -> Exploitation (SQLi) -> Credential Access (6 failed logins).",
        expected_rule_ids=["RULE-008", "RULE-005", "RULE-012", "RULE-001"],
        should_alert=True,
        events=events,
    )


def get_all_evaluation_scenarios() -> List[LabeledScenario]:
    """Returns the complete set of standardized evaluation scenarios."""
    scenarios: List[LabeledScenario] = [
        generate_benign_01(),
        generate_benign_02(),
        generate_benign_03(),
        generate_benign_04(),
    ]
    scenarios.extend(generate_poll_scenarios())
    scenarios.extend([
        generate_attack_01(),
        generate_attack_02(),
        generate_attack_03(),
        generate_attack_04(),
        generate_attack_05(),
        generate_attack_06(),
    ])
    return scenarios


# ---------------------------------------------------------------------------
# Isolated Test Database & Scenario Runner
# ---------------------------------------------------------------------------

class IsolatedEvaluationRunner:
    """
    Executes scenarios against an isolated in-memory SQLite database.
    Measures latency per stage and gathers confusion matrix data.
    """

    def __init__(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        self.SessionLocal = sessionmaker(bind=self.engine, autoflush=False, autocommit=False)
        Base.metadata.create_all(bind=self.engine)
        self._init_database()

    def _init_database(self):
        db = self.SessionLocal()
        try:
            ensure_builtin_rules(db)
            ensure_indicators(db)
            db.commit()
        finally:
            db.close()

    def reset_data_tables(self):
        """Wipes alerts, incidents, evidence, and normalized events while preserving rules."""
        db = self.SessionLocal()
        try:
            db.query(IncidentAlert).delete()
            db.query(Incident).delete()
            db.query(Evidence).delete()
            db.query(AlertEvent).delete()
            db.query(Alert).delete()
            db.query(NormalizedEvent).delete()
            db.commit()
        finally:
            db.close()

    def run_scenario(self, scenario: LabeledScenario, base_time: Optional[datetime] = None) -> ScenarioRunResult:
        """
        Executes a single scenario through the real ingestion and detection pipeline.
        Measures exact duration for ingest, eval, evidence, and correlate.
        """
        self.reset_data_tables()
        db = self.SessionLocal()
        t_ref = base_time or datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)

        try:
            # 1. Stage: Ingest & Normalization
            t_ingest_start = time.perf_counter()
            norm_events: List[NormalizedEvent] = []
            for ev in scenario.events:
                evt_time = t_ref + timedelta(seconds=ev.offset_seconds)
                ne = NormalizedEvent(
                    timestamp=evt_time,
                    source_ip=ev.source_ip,
                    http_method=ev.method,
                    request_path=ev.path,
                    status_code=ev.status_code,
                    user_agent=ev.user_agent,
                    username=ev.username,
                    event_type=ev.event_type,
                    event_category=ev.event_category,
                    severity=ev.severity,
                    message=ev.message or f"{ev.method} {ev.path}",
                    source_type="WEB",
                )
                db.add(ne)
                norm_events.append(ne)
            db.flush()
            t_ingest_ms = (time.perf_counter() - t_ingest_start) * 1000.0

            # 2. Stage: Rule Evaluation Engine
            t_eval_start = time.perf_counter()
            # Evaluate rules with auto_correlate=False so we measure correlation separately
            evaluate_rules_for_events(db, norm_events, auto_correlate=False)
            db.flush()
            t_eval_ms = (time.perf_counter() - t_eval_start) * 1000.0

            # Inspect alerts generated
            alerts = db.query(Alert).all()
            alert_rule_ids = [a.rule.rule_id if a.rule else f"RULE-{a.rule_id}" for a in alerts]
            touched_alert_ids = {a.id for a in alerts}

            # 3. Stage: Evidence Packaging
            t_evidence_start = time.perf_counter()
            evidence_count = 0
            for alert in alerts:
                ev_items = build_evidence_package(db, alert)
                evidence_count += len(ev_items)
            db.flush()
            t_evidence_ms = (time.perf_counter() - t_evidence_start) * 1000.0

            # 4. Stage: Cross-Source Incident Correlation
            t_correlate_start = time.perf_counter()
            if touched_alert_ids:
                correlate_incidents(db, touched_alert_ids)
                db.flush()
            t_correlate_ms = (time.perf_counter() - t_correlate_start) * 1000.0

            incidents = db.query(Incident).all()
            t_total_ms = t_ingest_ms + t_eval_ms + t_evidence_ms + t_correlate_ms

            # Duplicate alert detection (multiple alerts created for same rule & source_ip)
            seen_combos: Set[Tuple[str, str]] = set()
            duplicates = 0
            for a in alerts:
                r_id = a.rule.rule_id if a.rule else str(a.rule_id)
                key = (r_id, a.source_ip or "")
                if key in seen_combos:
                    duplicates += 1
                seen_combos.add(key)

            # Confusion matrix categorization
            fired_rules = sorted(list(set(alert_rule_ids)))
            has_alert = len(alerts) > 0

            if scenario.category == "attack":
                if has_alert:
                    classification = "TP"
                else:
                    classification = "FN"
            else:  # benign
                if has_alert:
                    classification = "FP"
                else:
                    classification = "TN"

            # Check missed rules
            missed = [r for r in scenario.expected_rule_ids if r not in fired_rules]

            return ScenarioRunResult(
                scenario_id=scenario.scenario_id,
                category=scenario.category,
                event_count=len(scenario.events),
                duration_seconds=scenario.duration_seconds,
                fired_rule_ids=fired_rules,
                alert_count=len(alerts),
                incident_count=len(incidents),
                classification=classification,
                duplicate_alerts=duplicates,
                missed_rule_ids=missed,
                latency=StageLatency(
                    t_ingest_ms=round(t_ingest_ms, 2),
                    t_eval_ms=round(t_eval_ms, 2),
                    t_evidence_ms=round(t_evidence_ms, 2),
                    t_correlate_ms=round(t_correlate_ms, 2),
                    t_total_ms=round(t_total_ms, 2),
                ),
                details=f"Alerts: {fired_rules}; Incidents: {len(incidents)}",
            )

        finally:
            db.close()


# ---------------------------------------------------------------------------
# Simulation Parameter Sweeps for RULE-008
# ---------------------------------------------------------------------------

@dataclass
class Rule008SweepResult:
    threshold: int
    filter_mode: str  # "none", "exclude_socketio", "exclude_static", "exclude_both"
    window_minutes: int
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    false_positive_rate: float
    false_negative_rate: float
    f1_score: float
    benign_01_fired: bool
    benign_03_fired: bool
    poll_06_fired: bool
    attack_01_fired: bool
    attack_06_fired: bool


def simulate_rule_008_evaluation(
    scenario: LabeledScenario,
    threshold: int,
    filter_mode: str = "none",
    window_minutes: int = 5,
) -> bool:
    """
    Evaluates whether RULE-008 would fire on a given scenario under a simulated
    (threshold, filter_mode, window_minutes) configuration without modifying production code.
    """
    # 1. Filter events matching rule conditions
    filtered_events: List[ScenarioEvent] = []
    for ev in scenario.events:
        if ev.event_category != "web":
            continue

        p_lower = (ev.path or "").lower()

        # Apply exclusion filters
        if filter_mode in ("exclude_socketio", "exclude_both"):
            if "/socket.io" in p_lower:
                continue

        if filter_mode in ("exclude_static", "exclude_both"):
            if "/assets/" in p_lower or "/media/" in p_lower or p_lower.endswith((".png", ".jpg", ".jpeg", ".css", ".js", ".svg", ".ico", ".woff", ".woff2")):
                continue

        filtered_events.append(ev)

    if not filtered_events:
        return False

    # Group by source_ip
    grouped: Dict[str, List[ScenarioEvent]] = {}
    for ev in filtered_events:
        grouped.setdefault(ev.source_ip, []).append(ev)

    window_seconds = window_minutes * 60.0

    for ip, ip_events in grouped.items():
        ip_events.sort(key=lambda e: e.offset_seconds)
        # Check sliding window ending at each event
        for i, anchor in enumerate(ip_events):
            t_end = anchor.offset_seconds
            t_start = t_end - window_seconds
            count_in_window = sum(1 for e in ip_events if t_start <= e.offset_seconds <= t_end)
            if count_in_window >= threshold:
                return True

    return False


def run_rule_008_parameter_sweeps(scenarios: List[LabeledScenario]) -> List[Rule008SweepResult]:
    """
    Evaluates all combinations of thresholds and path exclusion filters.
    """
    thresholds = [60, 90, 120, 180, 240, 300]
    filter_modes = ["none", "exclude_socketio", "exclude_static", "exclude_both"]
    results: List[Rule008SweepResult] = []

    # Map key scenarios for inspection
    scenario_map = {s.scenario_id: s for s in scenarios}

    for f_mode in filter_modes:
        for thresh in thresholds:
            tp = fp = tn = fn = 0

            # Evaluate against all scenarios
            for sc in scenarios:
                fired = simulate_rule_008_evaluation(sc, thresh, f_mode, window_minutes=5)
                # In this sub-sweep, "attack" targeting volume bursts (ATTACK-01, ATTACK-02, ATTACK-06)
                # represents ground truth positive for volume anomaly.
                is_volume_attack = sc.scenario_id in ("ATTACK-01", "ATTACK-02", "ATTACK-06")

                if is_volume_attack:
                    if fired:
                        tp += 1
                    else:
                        fn += 1
                else:  # All benign and non-volume attack scenarios
                    if fired:
                        fp += 1
                    else:
                        tn += 1

            precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
            recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
            fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
            fnr = round(fn / (tp + fn), 4) if (tp + fn) > 0 else 0.0
            f1 = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0

            b1_fired = simulate_rule_008_evaluation(scenario_map["BENIGN-01"], thresh, f_mode, 5)
            b3_fired = simulate_rule_008_evaluation(scenario_map["BENIGN-03"], thresh, f_mode, 5)
            p6_fired = simulate_rule_008_evaluation(scenario_map["POLL-06"], thresh, f_mode, 5)
            a1_fired = simulate_rule_008_evaluation(scenario_map["ATTACK-01"], thresh, f_mode, 5)
            a6_fired = simulate_rule_008_evaluation(scenario_map["ATTACK-06"], thresh, f_mode, 5)

            results.append(
                Rule008SweepResult(
                    threshold=thresh,
                    filter_mode=f_mode,
                    window_minutes=5,
                    tp=tp,
                    fp=fp,
                    tn=tn,
                    fn=fn,
                    precision=precision,
                    recall=recall,
                    false_positive_rate=fpr,
                    false_negative_rate=fnr,
                    f1_score=f1,
                    benign_01_fired=b1_fired,
                    benign_03_fired=b3_fired,
                    poll_06_fired=p6_fired,
                    attack_01_fired=a1_fired,
                    attack_06_fired=a6_fired,
                )
            )

    # Also evaluate 1-minute burst density hypothesis (e.g. 30, 45, 60 in 1 min)
    for thresh in [30, 45, 60]:
        tp = fp = tn = fn = 0
        for sc in scenarios:
            fired = simulate_rule_008_evaluation(sc, thresh, "none", window_minutes=1)
            is_volume_attack = sc.scenario_id in ("ATTACK-01", "ATTACK-02", "ATTACK-06")
            if is_volume_attack:
                if fired:
                    tp += 1
                else:
                    fn += 1
            else:
                if fired:
                    fp += 1
                else:
                    tn += 1

        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
        fnr = round(fn / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        f1 = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0

        results.append(
            Rule008SweepResult(
                threshold=thresh,
                filter_mode="1min_burst_none",
                window_minutes=1,
                tp=tp,
                fp=fp,
                tn=tn,
                fn=fn,
                precision=precision,
                recall=recall,
                false_positive_rate=fpr,
                false_negative_rate=fnr,
                f1_score=f1,
                benign_01_fired=simulate_rule_008_evaluation(scenario_map["BENIGN-01"], thresh, "none", 1),
                benign_03_fired=simulate_rule_008_evaluation(scenario_map["BENIGN-03"], thresh, "none", 1),
                poll_06_fired=simulate_rule_008_evaluation(scenario_map["POLL-06"], thresh, "none", 1),
                attack_01_fired=simulate_rule_008_evaluation(scenario_map["ATTACK-01"], thresh, "none", 1),
                attack_06_fired=simulate_rule_008_evaluation(scenario_map["ATTACK-06"], thresh, "none", 1),
            )
        )

    return results


# ---------------------------------------------------------------------------
# Metric Aggregation Helper
# ---------------------------------------------------------------------------

def calculate_aggregate_metrics(results: List[ScenarioRunResult]) -> ConfusionMatrixMetrics:
    tp = sum(1 for r in results if r.classification == "TP")
    fp = sum(1 for r in results if r.classification == "FP")
    tn = sum(1 for r in results if r.classification == "TN")
    fn = sum(1 for r in results if r.classification == "FN")
    total = len(results)

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
    fnr = round(fn / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1 = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0
    duplicates = sum(r.duplicate_alerts for r in results)

    latencies = [r.latency.t_total_ms for r in results]
    median_lat = round(statistics.median(latencies), 2) if latencies else 0.0
    # 95th percentile
    if latencies:
        sorted_lat = sorted(latencies)
        idx_p95 = int(len(sorted_lat) * 0.95)
        p95_lat = round(sorted_lat[min(idx_p95, len(sorted_lat) - 1)], 2)
    else:
        p95_lat = 0.0

    return ConfusionMatrixMetrics(
        total_scenarios=total,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        f1_score=f1,
        duplicate_alerts=duplicates,
        median_latency_ms=median_lat,
        p95_latency_ms=p95_lat,
    )
