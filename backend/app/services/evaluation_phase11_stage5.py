"""
backend/app/services/evaluation_phase11_stage5.py

Phase 11 Stage 5: Independent Robustness and Reproducibility Audit Engine.
Evaluates 35 comprehensive scenarios (23 existing + 12 new robustness/boundary challenge scenarios)
across Baseline, Hardened Single-Threshold, Dual-Threshold Split Architecture, and Independent 404 configurations.
"""

from __future__ import annotations

import copy
import json
import platform
import random
import statistics
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

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
from app.rules.engine import evaluate_rules_for_events
from app.services.evaluation_phase11 import (
    LabeledScenario,
    ScenarioEvent,
    StageLatency,
)
from app.services.evaluation_phase11_stage4 import get_all_stage4_scenarios
from app.services.evidence_service import build_evidence_package
from app.services.seed import ensure_builtin_rules, ensure_indicators


# ---------------------------------------------------------------------------
# 12 New Stage 5 Robustness Challenge Scenarios
# ---------------------------------------------------------------------------

def generate_stg5_bound_01() -> LabeledScenario:
    """STG5-BOUND-01: Threshold Boundary Below (59 requests in 5 minutes)"""
    ip = "198.51.100.111"
    events = [
        ScenarioEvent(offset_seconds=i * 5.0, source_ip=ip, method="GET", path=f"/rest/products/{i}")
        for i in range(59)
    ]
    return LabeledScenario(
        scenario_id="STG5-BOUND-01",
        name="Threshold Boundary Below (59 reqs in 5m)",
        category="benign",
        duration_seconds=300.0,
        description="Boundary test: exactly 59 requests in 5 minutes (immediately below threshold 60). Must NOT alert.",
        expected_rule_ids=[],
        should_alert=False,
        events=events,
    )


def generate_stg5_bound_02() -> LabeledScenario:
    """STG5-BOUND-02: Threshold Boundary Exact (60 requests in 5 minutes)"""
    ip = "198.51.100.112"
    events = [
        ScenarioEvent(offset_seconds=i * 4.9, source_ip=ip, method="GET", path=f"/rest/products/{i}")
        for i in range(60)
    ]
    return LabeledScenario(
        scenario_id="STG5-BOUND-02",
        name="Threshold Boundary Exact (60 reqs in 5m)",
        category="attack",
        duration_seconds=295.0,
        description="Boundary test: exactly 60 requests in 5 minutes (immediately at threshold 60). MUST alert.",
        expected_rule_ids=["RULE-008"],
        should_alert=True,
        events=events,
    )


def generate_stg5_bound_03() -> LabeledScenario:
    """STG5-BOUND-03: Threshold Boundary Above (61 requests in 5 minutes)"""
    ip = "198.51.100.113"
    events = [
        ScenarioEvent(offset_seconds=i * 4.8, source_ip=ip, method="GET", path=f"/rest/products/{i}")
        for i in range(61)
    ]
    return LabeledScenario(
        scenario_id="STG5-BOUND-03",
        name="Threshold Boundary Above (61 reqs in 5m)",
        category="attack",
        duration_seconds=295.0,
        description="Boundary test: exactly 61 requests in 5 minutes (immediately above threshold 60). MUST alert.",
        expected_rule_ids=["RULE-008"],
        should_alert=True,
        events=events,
    )


def generate_stg5_bound_04() -> LabeledScenario:
    """STG5-BOUND-04: Companion Boundary Below (109 socket/asset requests in 5 minutes)"""
    ip = "198.51.100.114"
    events = [
        ScenarioEvent(offset_seconds=i * 2.7, source_ip=ip, method="GET", path=f"/health/socket.io/?EIO=4&t={i}")
        for i in range(109)
    ]
    return LabeledScenario(
        scenario_id="STG5-BOUND-04",
        name="Companion Boundary Below (109 socket reqs in 5m)",
        category="benign",
        duration_seconds=300.0,
        description="Companion boundary test: exactly 109 socket requests (immediately below threshold 110). Must NOT alert.",
        expected_rule_ids=[],
        should_alert=False,
        events=events,
    )


def generate_stg5_bound_05() -> LabeledScenario:
    """STG5-BOUND-05: Companion Boundary Exact (110 socket/asset requests in 5 minutes)"""
    ip = "198.51.100.115"
    events = [
        ScenarioEvent(offset_seconds=i * 2.6, source_ip=ip, method="GET", path=f"/health/socket.io/?EIO=4&t={i}")
        for i in range(110)
    ]
    return LabeledScenario(
        scenario_id="STG5-BOUND-05",
        name="Companion Boundary Exact (110 socket reqs in 5m)",
        category="attack",
        duration_seconds=290.0,
        description="Companion boundary test: exactly 110 socket requests (at threshold 110). MUST alert on RULE-008B.",
        expected_rule_ids=["RULE-008B"],
        should_alert=True,
        events=events,
    )


def generate_stg5_window_01() -> LabeledScenario:
    """STG5-WINDOW-01: Time Window Boundary (60 requests across 305 seconds)"""
    ip = "198.51.100.116"
    # Evenly spaced across 305 seconds (1 req every 5.16s). Maximum in any 300s window is 59 requests.
    events = [
        ScenarioEvent(offset_seconds=i * 5.16, source_ip=ip, method="GET", path=f"/rest/products/{i}")
        for i in range(60)
    ]
    return LabeledScenario(
        scenario_id="STG5-WINDOW-01",
        name="Sliding Window Boundary (60 reqs across 305s)",
        category="benign",
        duration_seconds=305.0,
        description="Window boundary test: 60 requests spread across 305s so that max in any 300s sliding window is 59. Must NOT alert.",
        expected_rule_ids=[],
        should_alert=False,
        events=events,
    )


def generate_stg5_ooo_01() -> LabeledScenario:
    """STG5-OOO-01: Out-of-Order Telemetry Arrival (65 requests with jittered ingestion)"""
    ip = "198.51.100.117"
    raw_events: List[ScenarioEvent] = []
    # 65 events within 120 seconds, but inserted out-of-order
    for i in range(65):
        raw_events.append(
            ScenarioEvent(offset_seconds=i * 1.8, source_ip=ip, method="GET", path=f"/rest/products/{i}")
        )
    # Pseudo-random scramble of list ordering to simulate asynchronous pipeline arrival
    rng = random.Random(42)
    scrambled = list(raw_events)
    rng.shuffle(scrambled)

    return LabeledScenario(
        scenario_id="STG5-OOO-01",
        name="Out-of-Order Telemetry Stream (65 reqs jittered)",
        category="attack",
        duration_seconds=120.0,
        description="Robustness test: 65 requests within 120s ingested out-of-order. Sliding window must evaluate correctly and alert.",
        expected_rule_ids=["RULE-008"],
        should_alert=True,
        events=scrambled,
    )


def generate_stg5_nat_01() -> LabeledScenario:
    """STG5-NAT-01: Corporate NAT Multi-User Traffic (2 users, 35 reqs each = 70 total)"""
    ip = "203.0.113.50"
    events: List[ScenarioEvent] = []
    # User 1: alice (35 requests in 5m)
    for i in range(35):
        events.append(
            ScenarioEvent(offset_seconds=i * 8.0, source_ip=ip, method="GET", path=f"/rest/products/{i}", username="alice")
        )
    # User 2: bob (35 requests in 5m)
    for i in range(35):
        events.append(
            ScenarioEvent(offset_seconds=i * 8.0 + 3.0, source_ip=ip, method="GET", path=f"/rest/basket/{i}", username="bob")
        )
    events.sort(key=lambda e: e.offset_seconds)

    return LabeledScenario(
        scenario_id="STG5-NAT-01",
        name="Corporate NAT Multi-User Session (2 users, 70 reqs)",
        category="benign",
        duration_seconds=300.0,
        description="NAT robustness test: 2 legitimate users sharing a public gateway IP, generating 70 total requests. Highlights IP-only grouping risk.",
        expected_rule_ids=[],
        should_alert=False,
        events=events,
    )


def generate_stg5_dist_01() -> LabeledScenario:
    """STG5-DIST-01: Distributed Low-and-Slow Scraper (5 IPs, 25 reqs each = 125 total)"""
    events: List[ScenarioEvent] = []
    for ip_idx in range(1, 6):
        ip = f"198.51.100.{210 + ip_idx}"
        for i in range(25):
            events.append(
                ScenarioEvent(offset_seconds=i * 10.0 + ip_idx, source_ip=ip, method="GET", path=f"/rest/products/{i}")
            )
    events.sort(key=lambda e: e.offset_seconds)

    return LabeledScenario(
        scenario_id="STG5-DIST-01",
        name="Distributed Low-and-Slow Scraper (5 IPs, 125 reqs)",
        category="attack",
        duration_seconds=300.0,
        description="Distributed attack test: Botnet fleet of 5 IPs scraping 125 items, each sending 25 reqs (<60). Tests per-IP aggregation limits.",
        expected_rule_ids=["RULE-008"],
        should_alert=True,
        events=events,
    )


def generate_stg5_post_01() -> LabeledScenario:
    """STG5-POST-01: Socket.IO HTTP POST Flood (120 POST requests in 2m)"""
    ip = "198.51.100.118"
    events = [
        ScenarioEvent(offset_seconds=i * 1.0, source_ip=ip, method="POST", path="/health/socket.io/?EIO=4&transport=polling", status_code=200)
        for i in range(120)
    ]
    return LabeledScenario(
        scenario_id="STG5-POST-01",
        name="Socket.IO HTTP POST Flood (120 POST reqs in 2m)",
        category="attack",
        duration_seconds=120.0,
        description="HTTP method test: 120 POST requests transmitting payloads over Socket.IO polling. Must alert on RULE-008B.",
        expected_rule_ids=["RULE-008B"],
        should_alert=True,
        events=events,
    )


def generate_stg5_post_02() -> LabeledScenario:
    """STG5-POST-02: Suspicious POST to Static Asset Path (20 POST requests returning 403)"""
    ip = "198.51.100.119"
    events = [
        ScenarioEvent(offset_seconds=i * 2.0, source_ip=ip, method="POST", path=f"/assets/uploads/shell_{i}.php", status_code=403)
        for i in range(20)
    ]
    return LabeledScenario(
        scenario_id="STG5-POST-02",
        name="Suspicious POST to Static Asset Path (20 POSTs 403)",
        category="attack",
        duration_seconds=45.0,
        description="HTTP method test: Adversary attempts unauthenticated file uploads into /assets/, receiving 403 Forbidden. Handled by client-error rules.",
        expected_rule_ids=["RULE-006"],
        should_alert=True,
        events=events,
    )


def generate_stg5_frag_01() -> LabeledScenario:
    """STG5-FRAG-01: URL Fragment Smuggling Scraper (90 requests with #bypass=/socket.io)"""
    ip = "198.51.100.120"
    events = [
        ScenarioEvent(offset_seconds=i * 1.3, source_ip=ip, method="GET", path=f"/rest/products/search#bypass=/socket.io")
        for i in range(90)
    ]
    return LabeledScenario(
        scenario_id="STG5-FRAG-01",
        name="URL Fragment Smuggling Scraper (90 reqs with #)",
        category="attack",
        duration_seconds=120.0,
        description="Evasion challenge: Adversary attempts URL fragment smuggling (#bypass=/socket.io) to evade detection. Must alert on RULE-008.",
        expected_rule_ids=["RULE-008"],
        should_alert=True,
        events=events,
    )


def get_all_stage5_scenarios() -> List[LabeledScenario]:
    """Returns all 35 standardized scenarios for Phase 11 Stage 5 evaluation."""
    base_23 = get_all_stage4_scenarios()
    challenge_12 = [
        generate_stg5_bound_01(),
        generate_stg5_bound_02(),
        generate_stg5_bound_03(),
        generate_stg5_bound_04(),
        generate_stg5_bound_05(),
        generate_stg5_window_01(),
        generate_stg5_ooo_01(),
        generate_stg5_nat_01(),
        generate_stg5_dist_01(),
        generate_stg5_post_01(),
        generate_stg5_post_02(),
        generate_stg5_frag_01(),
    ]
    return base_23 + challenge_12


# ---------------------------------------------------------------------------
# Rule Configurations for Stage 5
# ---------------------------------------------------------------------------

def build_stage5_rules(config_name: str) -> List[dict[str, Any]]:
    raw_rules = copy.deepcopy(builtin_rules())

    if config_name == "baseline":
        return raw_rules

    if config_name == "candidate_hardened_single":
        for r in raw_rules:
            if r["rule_id"] == "RULE-008":
                r["conditions_json"]["filters"]["request_path_not_contains_any"] = [
                    "/socket.io", "/assets/", "/media/"
                ]
        return raw_rules

    if config_name == "candidate_dual_threshold":
        for r in raw_rules:
            if r["rule_id"] == "RULE-008":
                r["conditions_json"]["filters"]["request_path_not_contains_any"] = [
                    "/socket.io", "/assets/", "/media/"
                ]
        companion_rule = {
            "rule_id": "RULE-008B",
            "name": "Excessive request volume on socket/asset endpoints",
            "description": "Detects high-rate volumetric flooding targeting Socket.IO or static assets indicative of connection pool DoS.",
            "category": "traffic_anomaly",
            "severity": "medium",
            "version": "1.0",
            "status": "ACTIVE",
            "source": "candidate_stage5",
            "owner": "secops-team",
            "mitre_technique": "T1499.001",
            "confidence": 0.70,
            "false_positive_notes": "High concurrency CDN cache warming or massive parallel asset preloading.",
            "expected_data_source": "web_telemetry",
            "enabled": True,
            "conditions_json": {
                "type": "threshold",
                "filters": {
                    "event_category": "web",
                    "request_path_contains_any": ["/socket.io", "/assets/", "/media/"],
                },
                "group_by": ["source_ip"],
            },
            "time_window_minutes": 5,
            "threshold": 110,
        }
        raw_rules.append(companion_rule)
        return raw_rules

    if config_name == "candidate_independent_404":
        for r in raw_rules:
            if r["rule_id"] == "RULE-008":
                r["conditions_json"]["filters"]["request_path_not_contains_any"] = [
                    "/socket.io", "/assets/", "/media/"
                ]
            elif r["rule_id"] == "RULE-005":
                r["conditions_json"]["filters"]["request_path_not_contains_any"] = ["/socket.io"]
            elif r["rule_id"] == "RULE-006":
                r["conditions_json"]["filters"]["request_path_not_contains_any"] = ["/socket.io"]
        return raw_rules

    return raw_rules


# ---------------------------------------------------------------------------
# Stage 5 Audit Models & Runner
# ---------------------------------------------------------------------------

@dataclass
class Stage5ScenarioResult:
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
    blind_spot_flag: bool
    median_latency_ms: float
    p95_latency_ms: float
    max_latency_ms: float
    per_event_median_ms: float


@dataclass
class Stage5Scorecard:
    configuration_name: str
    description: str
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
    total_duplicate_alerts: int
    blind_spots_count: int
    overall_median_latency_ms: float
    small_batch_median_ms: float
    burst_median_ms: float
    overall_p95_latency_ms: float
    overall_max_latency_ms: float
    scenario_results: List[Stage5ScenarioResult]


class Stage5AuditRunner:
    def __init__(self, config_name: str = "baseline", use_batched_threshold: bool = False):
        self.config_name = config_name
        self.use_batched_threshold = use_batched_threshold

        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        self.SessionLocal = sessionmaker(
            bind=self.engine, autoflush=False, autocommit=False, expire_on_commit=False
        )
        Base.metadata.create_all(bind=self.engine)
        self._init_rules()

    def _init_rules(self):
        db = self.SessionLocal()
        try:
            db.query(AlertEvent).delete()
            db.query(Alert).delete()
            db.query(DetectionRule).delete()
            db.query(ThreatIndicator).delete()

            rule_defs = build_stage5_rules(self.config_name)
            for idx, item in enumerate(rule_defs, start=1):
                rule = DetectionRule(
                    id=idx,
                    name=item["name"],
                    description=item.get("description", ""),
                    category=item.get("category", "generic"),
                    severity=item.get("severity", "medium"),
                    version=item.get("version", "1.0"),
                    status=item.get("status", "ACTIVE"),
                    source=item.get("source", "builtin"),
                    owner=item.get("owner", "secops"),
                    mitre_technique=item.get("mitre_technique"),
                    confidence=item.get("confidence", 0.7),
                    enabled=item.get("enabled", True),
                    conditions_json=item.get("conditions_json", {}),
                    time_window_minutes=item.get("time_window_minutes", 10),
                    threshold=item.get("threshold", 5),
                )
                db.add(rule)

            ensure_indicators(db)
            db.commit()
        finally:
            db.close()

    def reset_data_tables(self):
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

    def execute_single_run(
        self, scenario: LabeledScenario, base_time: datetime
    ) -> Tuple[List[Alert], List[Incident], float]:
        self.reset_data_tables()
        db = self.SessionLocal()
        try:
            t0 = time.perf_counter()
            norm_events: List[NormalizedEvent] = []
            for ev in scenario.events:
                evt_time = base_time + timedelta(seconds=ev.offset_seconds)
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

            evaluate_rules_for_events(
                db,
                norm_events,
                auto_correlate=False,
                use_batched_threshold=self.use_batched_threshold,
            )
            db.flush()

            alerts = db.query(Alert).all()
            touched_ids = {a.id for a in alerts}

            for alert in alerts:
                build_evidence_package(db, alert)
            db.flush()

            if touched_ids:
                correlate_incidents(db, touched_ids)
                db.flush()

            incidents = db.query(Incident).all()
            total_duration_ms = (time.perf_counter() - t0) * 1000.0
            return alerts, incidents, total_duration_ms
        finally:
            db.close()

    def evaluate_scenario(
        self,
        scenario: LabeledScenario,
        measured_runs: int = 5,
    ) -> Stage5ScenarioResult:
        t_ref = datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)

        # 1. Warm-up
        self.execute_single_run(scenario, t_ref)

        # 2. Measured runs
        durations: List[float] = []
        final_alerts: List[Alert] = []
        final_incidents: List[Incident] = []

        for _ in range(measured_runs):
            alerts, incidents, dur_ms = self.execute_single_run(scenario, t_ref)
            durations.append(dur_ms)
            final_alerts = alerts
            final_incidents = incidents

        ev_count = max(len(scenario.events), 1)
        med_ms = round(statistics.median(durations), 2)
        sorted_lats = sorted(durations)
        p95_idx = int(len(sorted_lats) * 0.95)
        p95_ms = round(sorted_lats[min(p95_idx, len(sorted_lats) - 1)], 2)
        max_ms = round(max(durations), 2)

        rule_defs = build_stage5_rules(self.config_name)
        seen_keys: Set[Tuple[str, str]] = set()
        duplicates = 0
        fired_rules_set: Set[str] = set()

        for a in final_alerts:
            r_name = a.rule.name if a.rule else f"Rule-{a.rule_id}"
            r_id = f"RULE-{a.rule_id:03d}" if a.rule_id else r_name
            for r_item in rule_defs:
                if r_item["name"] == r_name:
                    r_id = r_item["rule_id"]
                    break
            fired_rules_set.add(r_id)
            key = (r_id, a.source_ip or "")
            if key in seen_keys:
                duplicates += 1
            seen_keys.add(key)

        fired_rules = sorted(list(fired_rules_set))
        has_alert = len(final_alerts) > 0

        if scenario.category == "attack":
            classification = "TP" if has_alert else "FN"
        else:
            classification = "FP" if has_alert else "TN"

        missed = [r for r in scenario.expected_rule_ids if r not in fired_rules]

        is_blind_spot = False
        if scenario.category == "attack" and classification == "FN":
            is_blind_spot = True
        elif scenario.category == "attack" and "RULE-008" in scenario.expected_rule_ids:
            has_vol = "RULE-008" in fired_rules or "RULE-008B" in fired_rules
            if not has_vol:
                is_blind_spot = True
        elif scenario.category == "attack" and "RULE-008B" in scenario.expected_rule_ids:
            if "RULE-008B" not in fired_rules and "RULE-008" not in fired_rules:
                is_blind_spot = True

        return Stage5ScenarioResult(
            scenario_id=scenario.scenario_id,
            category=scenario.category,
            event_count=len(scenario.events),
            duration_seconds=scenario.duration_seconds,
            fired_rule_ids=fired_rules,
            alert_count=len(final_alerts),
            incident_count=len(final_incidents),
            classification=classification,
            duplicate_alerts=duplicates,
            missed_rule_ids=missed,
            blind_spot_flag=is_blind_spot,
            median_latency_ms=med_ms,
            p95_latency_ms=p95_ms,
            max_latency_ms=max_ms,
            per_event_median_ms=round(med_ms / ev_count, 3),
        )


def evaluate_stage5_configuration(
    config_name: str,
    description: str,
    scenarios: List[LabeledScenario],
    use_batched_threshold: bool = False,
    measured_runs: int = 5,
) -> Stage5Scorecard:
    runner = Stage5AuditRunner(
        config_name=config_name, use_batched_threshold=use_batched_threshold
    )
    results: List[Stage5ScenarioResult] = []

    for sc in scenarios:
        res = runner.evaluate_scenario(sc, measured_runs=measured_runs)
        results.append(res)

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
    blind_spots = sum(1 for r in results if r.blind_spot_flag)

    all_meds = [r.median_latency_ms for r in results]
    small_meds = [r.median_latency_ms for r in results if r.event_count <= 10]
    burst_meds = [r.median_latency_ms for r in results if r.event_count >= 100]

    overall_median = round(statistics.median(all_meds), 2) if all_meds else 0.0
    small_median = round(statistics.median(small_meds), 2) if small_meds else 0.0
    burst_median = round(statistics.median(burst_meds), 2) if burst_meds else 0.0

    all_p95s = [r.p95_latency_ms for r in results]
    overall_p95 = round(max(all_p95s), 2) if all_p95s else 0.0
    all_maxes = [r.max_latency_ms for r in results]
    overall_max = round(max(all_maxes), 2) if all_maxes else 0.0

    return Stage5Scorecard(
        configuration_name=config_name,
        description=description,
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
        total_duplicate_alerts=duplicates,
        blind_spots_count=blind_spots,
        overall_median_latency_ms=overall_median,
        small_batch_median_ms=small_median,
        burst_median_ms=burst_median,
        overall_p95_latency_ms=overall_p95,
        overall_max_latency_ms=overall_max,
        scenario_results=results,
    )


def run_full_stage5_audit_suite() -> Dict[str, Any]:
    """Runs the complete Stage 5 robustness and reproducibility audit."""
    all_scenarios = get_all_stage5_scenarios()

    env_metadata = {
        "platform": platform.platform(),
        "python_version": sys.version,
        "processor": platform.processor(),
        "machine": platform.machine(),
        "sqlite_driver": "sqlite3 / StaticPool",
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "baseline_commit": "d4f884b",
        "frozen_checkpoint": "6a153ae17c676e92b7fc7208b374c2646e99b4f6",
        "total_scenarios_evaluated": len(all_scenarios),
        "latency_methodology": "1 warm-up run (discarded) + 5 measured runs per scenario",
    }

    # 1. Baseline Sequential
    base_seq = evaluate_stage5_configuration(
        config_name="baseline",
        description="Production Builtin Rules (Sequential Queries)",
        scenarios=all_scenarios,
        use_batched_threshold=False,
        measured_runs=5,
    )

    # 2. Dual-Threshold Split Sequential
    dual_seq = evaluate_stage5_configuration(
        config_name="candidate_dual_threshold",
        description="Dual-Threshold Split Architecture (RULE-008 60 + RULE-008B 110 Sequential)",
        scenarios=all_scenarios,
        use_batched_threshold=False,
        measured_runs=5,
    )

    # 3. Dual-Threshold Split Batched
    dual_bat = evaluate_stage5_configuration(
        config_name="candidate_dual_threshold",
        description="Dual-Threshold Split Architecture (RULE-008 60 + RULE-008B 110 Batched)",
        scenarios=all_scenarios,
        use_batched_threshold=True,
        measured_runs=5,
    )

    # 4. Hardened Single-Threshold Batched
    hard_bat = evaluate_stage5_configuration(
        config_name="candidate_hardened_single",
        description="Hardened Single-Threshold RULE-008 (Batched Queries)",
        scenarios=all_scenarios,
        use_batched_threshold=True,
        measured_runs=5,
    )

    # 5. Independent 404 Batched
    ind_404_bat = evaluate_stage5_configuration(
        config_name="candidate_independent_404",
        description="Independent 404 Evaluation (RULE-005/006 Exclude Socket.IO Batched)",
        scenarios=all_scenarios,
        use_batched_threshold=True,
        measured_runs=5,
    )

    return {
        "metadata": env_metadata,
        "total_scenarios": len(all_scenarios),
        "configurations": {
            "baseline_sequential": asdict(base_seq),
            "candidate_dual_threshold_sequential": asdict(dual_seq),
            "candidate_dual_threshold_batched": asdict(dual_bat),
            "candidate_hardened_single_batched": asdict(hard_bat),
            "candidate_independent_404_batched": asdict(ind_404_bat),
        },
    }
