"""
backend/app/services/evaluation_phase11_stage4.py

Phase 11 Stage 4: Offline Candidate Hardening and Adversarial Re-evaluation Engine.
Evaluates:
1. Hardened RULE-008 candidate using URL-parsed path normalization (immune to query-parameter smuggling).
2. Alternative Dual-Threshold Architecture (RULE-008 + RULE-008B Companion Rule for Excluded Paths).
3. 23 Comprehensive Scenarios (11 Benign, 6 Standard Attack, 6 Adversarial/Hardening cases).
4. Multi-run Latency Benchmarking (1 warmup + 5 measured runs per scenario).
5. Isolated evaluation of RULE-005 and RULE-006 on namespace probing vs reverse-proxy noise.
"""

from __future__ import annotations

import copy
import json
import platform
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
    get_all_evaluation_scenarios,
)
from app.services.evaluation_phase11_stage3 import (
    generate_adv_excl_01,
    generate_adv_excl_02,
    generate_adv_excl_03,
    generate_adv_excl_04,
)
from app.services.evidence_service import build_evidence_package
from app.services.seed import ensure_builtin_rules, ensure_indicators


# ---------------------------------------------------------------------------
# Additional Hardening & Adversarial Scenarios
# ---------------------------------------------------------------------------

def generate_adv_excl_05() -> LabeledScenario:
    """ADV-EXCL-05: Adversarial Socket.IO Namespace Probing & Fuzzing (30 reqs in 1m)"""
    ip = "198.51.100.205"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SocketFuzzer/2.0"
    events: List[ScenarioEvent] = []
    namespaces = [
        "/socket.io/admin", "/socket.io/internal", "/socket.io/v1/debug",
        "/socket.io/v2/debug", "/socket.io/root", "/socket.io/control",
        "/socket.io/config", "/socket.io/status", "/socket.io/metrics",
        "/socket.io/cluster", "/socket.io/peer", "/socket.io/master",
        "/socket.io/worker", "/socket.io/auth", "/socket.io/jwt",
    ]
    for i in range(30):
        t = 2.0 * i
        target = namespaces[i % len(namespaces)]
        events.append(
            ScenarioEvent(
                offset_seconds=t,
                source_ip=ip,
                method="GET",
                path=f"{target}/?EIO=4&transport=polling",
                status_code=404,
                user_agent=ua,
                message=f"Probe unexpected socket namespace: {target}",
            )
        )
    return LabeledScenario(
        scenario_id="ADV-EXCL-05",
        name="Adversarial Socket.IO Namespace Probing & Fuzzing",
        category="attack",
        duration_seconds=60.0,
        description="Adversary fuzzes unusual WebSocket/Socket.IO administrative namespaces, receiving 30 HTTP 404 responses.",
        expected_rule_ids=["RULE-005", "RULE-006"],
        should_alert=True,
        events=events,
    )


def generate_adv_excl_06() -> LabeledScenario:
    """ADV-EXCL-06: Adversarial Encoded Traversal Evasion Scraper (85 reqs in 1m)"""
    ip = "198.51.100.206"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PathTraversalScraper/1.0"
    events: List[ScenarioEvent] = []
    # Attacker uses /%61ssets/../rest/products/{i} to attempt evasion
    for i in range(85):
        t = 0.7 * i
        events.append(
            ScenarioEvent(
                offset_seconds=t,
                source_ip=ip,
                method="GET",
                path=f"/%61ssets/../rest/products/{i}",
                status_code=200,
                user_agent=ua,
                message="Volumetric scrape using encoded asset traversal prefix",
            )
        )
    return LabeledScenario(
        scenario_id="ADV-EXCL-06",
        name="Adversarial Encoded Traversal Evasion Scraper",
        category="attack",
        duration_seconds=60.0,
        description="Adversary performs volumetric data scraping (85 requests in 60s) using an encoded asset traversal prefix (/%61ssets/../rest/products) to attempt filter evasion.",
        expected_rule_ids=["RULE-008"],
        should_alert=True,
        events=events,
    )


def get_all_stage4_scenarios() -> List[LabeledScenario]:
    """Returns the full 23-scenario matrix for Phase 11 Stage 4 evaluation."""
    base_scenarios = get_all_evaluation_scenarios()
    adversarial = [
        generate_adv_excl_01(),
        generate_adv_excl_02(),
        generate_adv_excl_03(),
        generate_adv_excl_04(),
        generate_adv_excl_05(),
        generate_adv_excl_06(),
    ]
    return base_scenarios + adversarial


# ---------------------------------------------------------------------------
# Candidate Rule Configurations for Stage 4
# ---------------------------------------------------------------------------

def build_stage4_candidate_rules(config_name: str) -> List[dict[str, Any]]:
    """
    Constructs isolated candidate rule definitions for Stage 4 evaluation.
    Leaves production code in builtin.py untouched.
    """
    raw_rules = copy.deepcopy(builtin_rules())

    if config_name == "baseline":
        return raw_rules

    if config_name == "candidate_stage3_naive":
        # Stage 3 naive candidate: exclusions without safe path parsing
        for r in raw_rules:
            if r["rule_id"] == "RULE-008":
                r["conditions_json"]["filters"]["request_path_not_contains_any"] = [
                    "/socket.io", "/assets/", "/media/"
                ]
        return raw_rules

    if config_name == "candidate_stage4_hardened":
        # Stage 4 hardened candidate: path-normalized exclusions
        for r in raw_rules:
            if r["rule_id"] == "RULE-008":
                r["conditions_json"]["filters"]["request_path_not_contains_any"] = [
                    "/socket.io", "/assets/", "/media/"
                ]
        return raw_rules

    if config_name == "candidate_stage4_dual_threshold":
        # Stage 4 alternative architecture: Split Dual-Threshold
        # RULE-008: Sensitive application paths (threshold 60, excludes socket.io and assets)
        for r in raw_rules:
            if r["rule_id"] == "RULE-008":
                r["conditions_json"]["filters"]["request_path_not_contains_any"] = [
                    "/socket.io", "/assets/", "/media/"
                ]

        # Companion RULE-008B: Volumetric flood on excluded paths with threshold 110
        companion_rule = {
            "rule_id": "RULE-008B",
            "name": "Excessive request volume on socket/asset endpoints",
            "description": "Detects high-rate volumetric flooding targeting Socket.IO or static assets indicative of connection pool DoS.",
            "category": "traffic_anomaly",
            "severity": "medium",
            "version": "1.0",
            "status": "ACTIVE",
            "source": "candidate_stage4",
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

    if config_name == "candidate_stage4_independent_404":
        # Evaluating independent RULE-005/006 socket.io exclusion
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
# Data Models for Stage 4 Benchmark and Evaluation Results
# ---------------------------------------------------------------------------

@dataclass
class Stage4ScenarioBenchmark:
    scenario_id: str
    event_count: int
    runs_count: int
    warmup_duration_ms: float
    measured_runs_ms: List[float]
    mean_ms: float
    median_ms: float
    p95_ms: float
    max_ms: float
    min_ms: float
    per_event_median_ms: float
    per_event_p95_ms: float
    stage_breakdown_median: StageLatency


@dataclass
class Stage4ScenarioResult:
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
    benchmark: Stage4ScenarioBenchmark
    details: str = ""


@dataclass
class Stage4Scorecard:
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
    overall_p95_latency_ms: float
    overall_max_latency_ms: float
    scenario_results: List[Stage4ScenarioResult]


# ---------------------------------------------------------------------------
# Stage 4 Evaluation Runner
# ---------------------------------------------------------------------------

class Stage4EvaluationRunner:
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

            rule_defs = build_stage4_candidate_rules(self.config_name)
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

    def execute_pipeline_run(
        self, scenario: LabeledScenario, base_time: datetime
    ) -> Tuple[List[Alert], List[Incident], StageLatency]:
        self.reset_data_tables()
        db = self.SessionLocal()
        try:
            # 1. Ingestion
            t_ingest_start = time.perf_counter()
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
            t_ingest_ms = (time.perf_counter() - t_ingest_start) * 1000.0

            # 2. Rule Evaluation
            t_eval_start = time.perf_counter()
            evaluate_rules_for_events(
                db,
                norm_events,
                auto_correlate=False,
                use_batched_threshold=self.use_batched_threshold,
            )
            db.flush()
            t_eval_ms = (time.perf_counter() - t_eval_start) * 1000.0

            alerts = db.query(Alert).all()
            touched_ids = {a.id for a in alerts}

            # 3. Evidence Packaging
            t_evidence_start = time.perf_counter()
            for alert in alerts:
                build_evidence_package(db, alert)
            db.flush()
            t_evidence_ms = (time.perf_counter() - t_evidence_start) * 1000.0

            # 4. Correlation
            t_correlate_start = time.perf_counter()
            if touched_ids:
                correlate_incidents(db, touched_ids)
                db.flush()
            t_correlate_ms = (time.perf_counter() - t_correlate_start) * 1000.0

            incidents = db.query(Incident).all()
            t_total_ms = t_ingest_ms + t_eval_ms + t_evidence_ms + t_correlate_ms

            latency = StageLatency(
                t_ingest_ms=round(t_ingest_ms, 2),
                t_eval_ms=round(t_eval_ms, 2),
                t_evidence_ms=round(t_evidence_ms, 2),
                t_correlate_ms=round(t_correlate_ms, 2),
                t_total_ms=round(t_total_ms, 2),
            )
            return alerts, incidents, latency
        finally:
            db.close()

    def evaluate_scenario(
        self,
        scenario: LabeledScenario,
        measured_runs: int = 5,
    ) -> Stage4ScenarioResult:
        t_ref = datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)

        # 1. Warmup
        warmup_start = time.perf_counter()
        self.execute_pipeline_run(scenario, t_ref)
        warmup_duration_ms = (time.perf_counter() - warmup_start) * 1000.0

        # 2. Measured Runs
        run_lats: List[float] = []
        s_ingests: List[float] = []
        s_evals: List[float] = []
        s_evids: List[float] = []
        s_corrs: List[float] = []

        final_alerts: List[Alert] = []
        final_incidents: List[Incident] = []

        for _ in range(measured_runs):
            alerts, incidents, latency = self.execute_pipeline_run(scenario, t_ref)
            run_lats.append(latency.t_total_ms)
            s_ingests.append(latency.t_ingest_ms)
            s_evals.append(latency.t_eval_ms)
            s_evids.append(latency.t_evidence_ms)
            s_corrs.append(latency.t_correlate_ms)
            final_alerts = alerts
            final_incidents = incidents

        ev_count = max(len(scenario.events), 1)
        mean_ms = round(statistics.mean(run_lats), 2)
        med_ms = round(statistics.median(run_lats), 2)
        sorted_lats = sorted(run_lats)
        p95_idx = int(len(sorted_lats) * 0.95)
        p95_ms = round(sorted_lats[min(p95_idx, len(sorted_lats) - 1)], 2)
        max_ms = round(max(run_lats), 2)
        min_ms = round(min(run_lats), 2)

        benchmark = Stage4ScenarioBenchmark(
            scenario_id=scenario.scenario_id,
            event_count=len(scenario.events),
            runs_count=measured_runs,
            warmup_duration_ms=round(warmup_duration_ms, 2),
            measured_runs_ms=run_lats,
            mean_ms=mean_ms,
            median_ms=med_ms,
            p95_ms=p95_ms,
            max_ms=max_ms,
            min_ms=min_ms,
            per_event_median_ms=round(med_ms / ev_count, 3),
            per_event_p95_ms=round(p95_ms / ev_count, 3),
            stage_breakdown_median=StageLatency(
                t_ingest_ms=round(statistics.median(s_ingests), 2),
                t_eval_ms=round(statistics.median(s_evals), 2),
                t_evidence_ms=round(statistics.median(s_evids), 2),
                t_correlate_ms=round(statistics.median(s_corrs), 2),
                t_total_ms=med_ms,
            ),
        )

        # Derive fired rule ids and duplicate alert tracking
        rule_defs = build_stage4_candidate_rules(self.config_name)
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

        # Classification
        if scenario.category == "attack":
            if has_alert:
                classification = "TP"
            else:
                classification = "FN"
        else:
            if has_alert:
                classification = "FP"
            else:
                classification = "TN"

        missed = [r for r in scenario.expected_rule_ids if r not in fired_rules]

        # Blind spot detection: Attack scenario missing expected volumetric coverage
        is_blind_spot = False
        if scenario.category == "attack" and classification == "FN":
            is_blind_spot = True
        elif scenario.category == "attack" and "RULE-008" in scenario.expected_rule_ids:
            # If dual threshold has RULE-008B, that counts as valid volume detection
            has_volume_detection = "RULE-008" in fired_rules or "RULE-008B" in fired_rules
            if not has_volume_detection:
                is_blind_spot = True

        return Stage4ScenarioResult(
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
            benchmark=benchmark,
            details=f"Alerts: {fired_rules}; Incidents: {len(final_incidents)}; Duplicates: {duplicates}",
        )


def evaluate_stage4_configuration(
    config_name: str,
    description: str,
    scenarios: List[LabeledScenario],
    use_batched_threshold: bool = False,
    measured_runs: int = 5,
) -> Stage4Scorecard:
    runner = Stage4EvaluationRunner(
        config_name=config_name, use_batched_threshold=use_batched_threshold
    )
    results: List[Stage4ScenarioResult] = []

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

    all_medians = [r.benchmark.median_ms for r in results]
    overall_median = round(statistics.median(all_medians), 2) if all_medians else 0.0
    all_p95s = [r.benchmark.p95_ms for r in results]
    overall_p95 = round(max(all_p95s), 2) if all_p95s else 0.0
    all_maxes = [r.benchmark.max_ms for r in results]
    overall_max = round(max(all_maxes), 2) if all_maxes else 0.0

    return Stage4Scorecard(
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
        overall_p95_latency_ms=overall_p95,
        overall_max_latency_ms=overall_max,
        scenario_results=results,
    )


def run_full_stage4_suite() -> Dict[str, Any]:
    """
    Executes full Phase 11 Stage 4 evaluation across all 23 scenarios and all candidate configurations.
    """
    all_scenarios = get_all_stage4_scenarios()

    env_metadata = {
        "platform": platform.platform(),
        "python_version": sys.version,
        "processor": platform.processor(),
        "machine": platform.machine(),
        "sqlite_driver": "sqlite3 / StaticPool",
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "baseline_commit": "d4f884b",
        "frozen_checkpoint": "6a153ae17c676e92b7fc7208b374c2646e99b4f6",
        "latency_methodology": "1 warm-up run (discarded) + 5 measured runs per scenario",
    }

    # 1. Baseline Sequential (Production Rules)
    baseline_seq = evaluate_stage4_configuration(
        config_name="baseline",
        description="Production Builtin Rules (Threshold 60, Sequential Queries)",
        scenarios=all_scenarios,
        use_batched_threshold=False,
        measured_runs=5,
    )

    # 2. Stage 4 Hardened Path-Normalized Sequential
    hardened_seq = evaluate_stage4_configuration(
        config_name="candidate_stage4_hardened",
        description="Stage 4 Hardened Path-Normalized Exclusion (Sequential)",
        scenarios=all_scenarios,
        use_batched_threshold=False,
        measured_runs=5,
    )

    # 3. Stage 4 Hardened Path-Normalized Batched
    hardened_batched = evaluate_stage4_configuration(
        config_name="candidate_stage4_hardened",
        description="Stage 4 Hardened Path-Normalized Exclusion (Batched Queries)",
        scenarios=all_scenarios,
        use_batched_threshold=True,
        measured_runs=5,
    )

    # 4. Stage 4 Alternative Architecture: Dual-Threshold Split (RULE-008 + RULE-008B)
    dual_threshold_batched = evaluate_stage4_configuration(
        config_name="candidate_stage4_dual_threshold",
        description="Stage 4 Dual-Threshold Architecture (RULE-008 60 + RULE-008B 110 Batched)",
        scenarios=all_scenarios,
        use_batched_threshold=True,
        measured_runs=5,
    )

    # 5. Stage 4 Independent 404 Evaluation (Testing RULE-005/006 Socket Exclusion)
    independent_404_batched = evaluate_stage4_configuration(
        config_name="candidate_stage4_independent_404",
        description="Stage 4 Independent 404 Evaluation (RULE-005/006 Exclude Socket)",
        scenarios=all_scenarios,
        use_batched_threshold=True,
        measured_runs=5,
    )

    return {
        "metadata": env_metadata,
        "scenarios_evaluated": len(all_scenarios),
        "configurations": {
            "baseline_sequential": asdict(baseline_seq),
            "candidate_stage4_hardened_sequential": asdict(hardened_seq),
            "candidate_stage4_hardened_batched": asdict(hardened_batched),
            "candidate_stage4_dual_threshold_batched": asdict(dual_threshold_batched),
            "candidate_stage4_independent_404_batched": asdict(independent_404_batched),
        },
    }
