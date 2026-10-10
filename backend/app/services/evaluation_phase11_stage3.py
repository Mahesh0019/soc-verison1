"""
backend/app/services/evaluation_phase11_stage3.py

Phase 11 Stage 3: Offline Candidate Evaluation Engine.
Performs hermetic, isolated evaluation of candidate detection rule configurations:
1. Evaluates candidate RULE-008 with request_path_not_contains_any without modifying production.
2. Evaluates candidate query batching optimization (evaluate_threshold_rule_batched).
3. Evaluates adversarial cases targeting excluded paths to assess blind spots.
4. Independently assesses RULE-005 and RULE-006 for socket 404 noise.
5. Performs multi-run latency benchmarking (1 warmup + 5 measured runs per scenario).
6. Computes scenario-level confusion matrices and duplicate alert tracking.
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
from app.services.evidence_service import build_evidence_package
from app.services.seed import ensure_builtin_rules, ensure_indicators


# ---------------------------------------------------------------------------
# Adversarial Excluded-Path Scenarios
# ---------------------------------------------------------------------------

def generate_adv_excl_01() -> LabeledScenario:
    """ADV-EXCL-01: Adversarial Volumetric DoS targeting Socket.IO Polling (120 reqs in 2m)"""
    ip = "198.51.100.201"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SocketIO-Flooder/1.0"
    events: List[ScenarioEvent] = []
    # 120 polling requests in 120 seconds (1 req/sec)
    for i in range(120):
        t = 1.0 * i
        events.append(
            ScenarioEvent(
                offset_seconds=t,
                source_ip=ip,
                method="GET",
                path=f"/health/socket.io/?EIO=4&transport=polling&t={int(t * 1000)}",
                status_code=200,
                user_agent=ua,
                message="Socket.IO DoS Flood probe",
            )
        )
    return LabeledScenario(
        scenario_id="ADV-EXCL-01",
        name="Adversarial Volumetric DoS on Socket.IO Polling",
        category="attack",
        duration_seconds=120.0,
        description="Adversary attempts denial of service by flooding the Socket.IO polling endpoint with 120 requests in 2 minutes.",
        expected_rule_ids=["RULE-008"],  # Baseline catches this; Candidate with socket exclusion will miss it
        should_alert=True,
        events=events,
    )


def generate_adv_excl_02() -> LabeledScenario:
    """ADV-EXCL-02: Adversarial Static Asset Exhaustion Flood (150 reqs in 1m)"""
    ip = "198.51.100.202"
    ua = "Mozilla/5.0 (X11; Linux x86_64) AssetSaturator/2.1"
    events: List[ScenarioEvent] = []
    # 150 static asset requests in 60 seconds (2.5 req/sec)
    for i in range(150):
        t = 0.4 * i
        events.append(
            ScenarioEvent(
                offset_seconds=t,
                source_ip=ip,
                method="GET",
                path="/assets/public/images/products/item_1.png",
                status_code=200,
                user_agent=ua,
                message="Static media asset exhaustion flood",
            )
        )
    return LabeledScenario(
        scenario_id="ADV-EXCL-02",
        name="Adversarial Static Asset Exhaustion Flood",
        category="attack",
        duration_seconds=60.0,
        description="Adversary floods static media assets with 150 requests in 60s to exhaust web server bandwidth and worker threads.",
        expected_rule_ids=["RULE-008"],  # Baseline catches; Candidate misses
        should_alert=True,
        events=events,
    )


def generate_adv_excl_03() -> LabeledScenario:
    """ADV-EXCL-03: Adversarial Parameter Smuggling Evasion on Scraper (90 reqs in 2m)"""
    ip = "198.51.100.203"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) EvasiveScraper/1.0"
    events: List[ScenarioEvent] = []
    # 90 product search requests in 120 seconds with smuggled /socket.io in query param
    for i in range(90):
        t = 1.33 * i
        events.append(
            ScenarioEvent(
                offset_seconds=t,
                source_ip=ip,
                method="GET",
                path=f"/rest/products/search?q=item_{i}&bypass=/socket.io",
                status_code=200,
                user_agent=ua,
                message="Volumetric scrape with smuggled exclusion token in query string",
            )
        )
    return LabeledScenario(
        scenario_id="ADV-EXCL-03",
        name="Adversarial Parameter Smuggling Evasion on Scraper",
        category="attack",
        duration_seconds=120.0,
        description="Adversary performs volumetric data scraping (90 requests) while smuggling '/socket.io' token in query parameter (?bypass=/socket.io) to evade substring-based detection.",
        expected_rule_ids=["RULE-008"],  # Baseline catches; naive Candidate substring match misses
        should_alert=True,
        events=events,
    )


def generate_adv_excl_04() -> LabeledScenario:
    """ADV-EXCL-04: Adversarial Sensitive File Probe in Asset Path (16 reqs in 30s)"""
    ip = "198.51.100.204"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AssetFuzzer/1.0"
    events: List[ScenarioEvent] = []
    targets = [
        "/assets/.git/config",
        "/assets/.env",
        "/assets/web.config",
        "/assets/backup.zip",
        "/assets/config.json",
        "/assets/.svn/entries",
        "/assets/.DS_Store",
        "/assets/database.sql",
        "/assets/admin.php",
        "/assets/.bash_history",
        "/assets/secret.key",
        "/assets/id_rsa",
        "/assets/.git/HEAD",
        "/assets/.env.production",
        "/assets/server.key",
        "/assets/credentials.xml",
    ]
    for i, target in enumerate(targets):
        t = 1.8 * i
        events.append(
            ScenarioEvent(
                offset_seconds=t,
                source_ip=ip,
                method="GET",
                path=target,
                status_code=404,
                user_agent=ua,
                message=f"Probe sensitive hidden file in assets: {target}",
            )
        )
    return LabeledScenario(
        scenario_id="ADV-EXCL-04",
        name="Adversarial Sensitive File Probe in Asset Path",
        category="attack",
        duration_seconds=30.0,
        description="Adversary probes sensitive files hosted under an asset directory (/assets/.git/config, /assets/.env), resulting in 16 404s.",
        expected_rule_ids=["RULE-005", "RULE-006", "RULE-007"],
        should_alert=True,
        events=events,
    )


def get_all_stage3_scenarios() -> List[LabeledScenario]:
    """Returns the full 21-scenario matrix for Phase 11 Stage 3 evaluation."""
    base_scenarios = get_all_evaluation_scenarios()
    adversarial = [
        generate_adv_excl_01(),
        generate_adv_excl_02(),
        generate_adv_excl_03(),
        generate_adv_excl_04(),
    ]
    return base_scenarios + adversarial


# ---------------------------------------------------------------------------
# Isolated Candidate Rule Configurations
# ---------------------------------------------------------------------------

def build_candidate_rules_definitions(config_name: str) -> List[dict[str, Any]]:
    """
    Constructs isolated in-memory rule definitions for evaluation.
    Leaves production code in builtin.py untouched.
    """
    raw_rules = copy.deepcopy(builtin_rules())
    if config_name == "baseline":
        return raw_rules

    if config_name in ("candidate_rule_008", "candidate_all"):
        for r in raw_rules:
            if r["rule_id"] == "RULE-008":
                # Candidate RULE-008: threshold 60, window 5, path exclusion
                r["conditions_json"]["filters"]["request_path_not_contains_any"] = [
                    "/socket.io",
                    "/assets/",
                    "/media/",
                ]

    if config_name == "candidate_all":
        for r in raw_rules:
            if r["rule_id"] == "RULE-005":
                # Candidate RULE-005: exclude socket.io 404s
                r["conditions_json"]["filters"]["request_path_not_contains_any"] = ["/socket.io"]
            elif r["rule_id"] == "RULE-006":
                # Candidate RULE-006: exclude socket.io 404s
                r["conditions_json"]["filters"]["request_path_not_contains_any"] = ["/socket.io"]

    return raw_rules


# ---------------------------------------------------------------------------
# Data Models for Benchmark and Evaluation Results
# ---------------------------------------------------------------------------

@dataclass
class ScenarioLatencyBenchmark:
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
    per_event_max_ms: float
    stage_breakdown_median: StageLatency


@dataclass
class ScenarioEvaluationResult:
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
    benchmark: ScenarioLatencyBenchmark
    details: str = ""


@dataclass
class ConfigurationScorecard:
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
    scenario_results: List[ScenarioEvaluationResult]


# ---------------------------------------------------------------------------
# Stage 3 Evaluation Runner
# ---------------------------------------------------------------------------

class Stage3EvaluationRunner:
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

            rule_defs = build_candidate_rules_definitions(self.config_name)
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
        """Runs one complete execution through Ingest -> Eval -> Evidence -> Correlate."""
        self.reset_data_tables()
        db = self.SessionLocal()
        try:
            # 1. Ingest
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
    ) -> ScenarioEvaluationResult:
        """
        Executes 1 warm-up run and at least 5 measured runs per scenario.
        Computes robust latency statistics and classification metrics.
        """
        t_ref = datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)

        # 1. Warm-up Run (discarded from measured latencies)
        warmup_start = time.perf_counter()
        self.execute_pipeline_run(scenario, t_ref)
        warmup_duration_ms = (time.perf_counter() - warmup_start) * 1000.0

        # 2. Measured Runs (at least 5)
        run_latencies_ms: List[float] = []
        stage_ingests: List[float] = []
        stage_evals: List[float] = []
        stage_evidences: List[float] = []
        stage_correlates: List[float] = []

        final_alerts: List[Alert] = []
        final_incidents: List[Incident] = []

        for _ in range(measured_runs):
            alerts, incidents, latency = self.execute_pipeline_run(scenario, t_ref)
            run_latencies_ms.append(latency.t_total_ms)
            stage_ingests.append(latency.t_ingest_ms)
            stage_evals.append(latency.t_eval_ms)
            stage_evidences.append(latency.t_evidence_ms)
            stage_correlates.append(latency.t_correlate_ms)
            final_alerts = alerts
            final_incidents = incidents

        # Latency statistics
        ev_count = max(len(scenario.events), 1)
        mean_ms = round(statistics.mean(run_latencies_ms), 2)
        med_ms = round(statistics.median(run_latencies_ms), 2)
        sorted_lats = sorted(run_latencies_ms)
        p95_idx = int(len(sorted_lats) * 0.95)
        p95_ms = round(sorted_lats[min(p95_idx, len(sorted_lats) - 1)], 2)
        max_ms = round(max(run_latencies_ms), 2)
        min_ms = round(min(run_latencies_ms), 2)

        benchmark = ScenarioLatencyBenchmark(
            scenario_id=scenario.scenario_id,
            event_count=len(scenario.events),
            runs_count=measured_runs,
            warmup_duration_ms=round(warmup_duration_ms, 2),
            measured_runs_ms=run_latencies_ms,
            mean_ms=mean_ms,
            median_ms=med_ms,
            p95_ms=p95_ms,
            max_ms=max_ms,
            min_ms=min_ms,
            per_event_median_ms=round(med_ms / ev_count, 3),
            per_event_p95_ms=round(p95_ms / ev_count, 3),
            per_event_max_ms=round(max_ms / ev_count, 3),
            stage_breakdown_median=StageLatency(
                t_ingest_ms=round(statistics.median(stage_ingests), 2),
                t_eval_ms=round(statistics.median(stage_evals), 2),
                t_evidence_ms=round(statistics.median(stage_evidences), 2),
                t_correlate_ms=round(statistics.median(stage_correlates), 2),
                t_total_ms=med_ms,
            ),
        )

        # Duplicate alert tracking
        seen_keys: Set[Tuple[str, str]] = set()
        duplicates = 0
        fired_rules_set: Set[str] = set()
        for a in final_alerts:
            # Derive rule identifier
            r_name = a.rule.name if a.rule else f"Rule-{a.rule_id}"
            # Find rule_id from conditions
            r_id = f"RULE-{a.rule_id:03d}" if a.rule_id else r_name
            for r_item in builtin_rules():
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

        # Blind spot detection: Attack scenario where expected detection rule did not fire
        is_blind_spot = False
        if scenario.category == "attack" and classification == "FN":
            is_blind_spot = True
        elif scenario.category == "attack" and "RULE-008" in scenario.expected_rule_ids and "RULE-008" not in fired_rules:
            is_blind_spot = True

        return ScenarioEvaluationResult(
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


def evaluate_configuration(
    config_name: str,
    description: str,
    scenarios: List[LabeledScenario],
    use_batched_threshold: bool = False,
    measured_runs: int = 5,
) -> ConfigurationScorecard:
    """Evaluates an entire scenario suite under a given rule configuration and query strategy."""
    runner = Stage3EvaluationRunner(
        config_name=config_name, use_batched_threshold=use_batched_threshold
    )
    results: List[ScenarioEvaluationResult] = []

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

    return ConfigurationScorecard(
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


def run_full_stage3_suite() -> Dict[str, Any]:
    """
    Executes full Phase 11 Stage 3 evaluation across all configurations and generates
    the complete data payload for reporting and artifact persistence.
    """
    all_scenarios = get_all_stage3_scenarios()
    standard_scenarios = [s for s in all_scenarios if not s.scenario_id.startswith("ADV-EXCL-")]

    # 1. Environment metadata
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

    # 2. Evaluations on Standard 17 Scenarios
    std_baseline_seq = evaluate_configuration(
        config_name="baseline",
        description="Production Builtin Rules (Threshold 60, Sequential Queries)",
        scenarios=standard_scenarios,
        use_batched_threshold=False,
        measured_runs=5,
    )

    std_candidate_seq = evaluate_configuration(
        config_name="candidate_rule_008",
        description="Candidate RULE-008 Path Exclusion (Sequential Queries)",
        scenarios=standard_scenarios,
        use_batched_threshold=False,
        measured_runs=5,
    )

    std_candidate_batched = evaluate_configuration(
        config_name="candidate_rule_008",
        description="Candidate RULE-008 Path Exclusion (Batched Queries)",
        scenarios=standard_scenarios,
        use_batched_threshold=True,
        measured_runs=5,
    )

    std_candidate_all_seq = evaluate_configuration(
        config_name="candidate_all",
        description="Candidate RULE-008 + RULE-005 + RULE-006 Exclusions (Sequential)",
        scenarios=standard_scenarios,
        use_batched_threshold=False,
        measured_runs=5,
    )

    # 3. Evaluations on Full 21 Scenarios (Including Adversarial Excluded-Path Cases)
    full_baseline_seq = evaluate_configuration(
        config_name="baseline",
        description="Production Builtin Rules across 21 scenarios (Baseline)",
        scenarios=all_scenarios,
        use_batched_threshold=False,
        measured_runs=5,
    )

    full_candidate_seq = evaluate_configuration(
        config_name="candidate_rule_008",
        description="Candidate RULE-008 Path Exclusion across 21 scenarios (Candidate)",
        scenarios=all_scenarios,
        use_batched_threshold=False,
        measured_runs=5,
    )

    full_candidate_batched = evaluate_configuration(
        config_name="candidate_rule_008",
        description="Candidate RULE-008 Path Exclusion across 21 scenarios (Batched)",
        scenarios=all_scenarios,
        use_batched_threshold=True,
        measured_runs=5,
    )

    return {
        "metadata": env_metadata,
        "standard_17_scenarios": {
            "baseline_sequential": asdict(std_baseline_seq),
            "candidate_rule008_sequential": asdict(std_candidate_seq),
            "candidate_rule008_batched": asdict(std_candidate_batched),
            "candidate_all_sequential": asdict(std_candidate_all_seq),
        },
        "full_21_scenarios_including_adversarial": {
            "baseline_sequential": asdict(full_baseline_seq),
            "candidate_rule008_sequential": asdict(full_candidate_seq),
            "candidate_rule008_batched": asdict(full_candidate_batched),
        },
    }
