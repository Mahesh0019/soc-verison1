"""
backend/app/services/detection_quality_service.py

Detection Quality Engine: transparent, multi-factor scoring of alert and incident quality.
Decomposes detection validity into explainable components:
- Evidence Completeness (0.25)
- Correlation Strength (0.20)
- Rule Confidence (0.20)
- Behavioral Confidence (0.15)
- Context Confidence (0.20)
"""

from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import Alert, DetectionQuality, DetectionRule, Incident, IncidentAlert, ThreatIndicator
from app.rules.correlation import calculate_correlation_metrics
from app.services.evidence_service import build_evidence_package, calculate_evidence_completeness


RULE_CONFIDENCE_TABLE = {
    "repeated access from blacklisted indicator": 0.98,
    "sql injection attempt detected": 0.95,
    "path traversal attempt detected": 0.92,
    "cross-site scripting probe detected": 0.90,
    "successful login after failed attempts": 0.90,
    "suspicious admin login": 0.88,
    "repeated sensitive path access": 0.85,
    "suspicious destination port connection": 0.85,
    "potential reconnaissance pattern": 0.82,
    "possible directory brute force": 0.80,
    "multiple failed login attempts from same ip": 0.80,
    "repeated rejected connections": 0.80,
    "suspicious http activity from zeek": 0.80,
    "dns resolution anomaly": 0.75,
    "login attempt from unusual country": 0.75,
    "suspicious user agent": 0.75,
    "firewall denied traffic spike": 0.70,
    "abnormal network connection burst": 0.70,
    "high number of 404 responses": 0.65,
    "large request volume burst": 0.60,
}


def get_rule_confidence(alert: Alert) -> float:
    """Returns rule confidence based on deterministic specificity."""
    if not alert.title:
        return 0.70
    title_lower = alert.title.lower()
    for name, conf in RULE_CONFIDENCE_TABLE.items():
        if name in title_lower:
            return conf
    return 0.75


def calculate_context_confidence(alert: Alert, db: Session) -> float:
    """
    Computes context confidence based on entity attribution and external validation.
    """
    score = 0.0
    # Valid source IP (non-loopback / non-zero)
    if alert.source_ip and alert.source_ip not in ("0.0.0.0", "127.0.0.1", ""):
        score += 0.40
    # Identified user
    if alert.affected_user and alert.affected_user.lower() not in ("anonymous", "unknown", "-"):
        score += 0.30
    else:
        score += 0.10

    # Threat Intelligence match
    if alert.source_ip:
        matched_ti = db.query(ThreatIndicator).filter(
            ThreatIndicator.type == "ip",
            ThreatIndicator.value == alert.source_ip,
        ).first()
        if matched_ti:
            score += 0.20
        else:
            score += 0.10
    else:
        score += 0.10

    # Multiple observed events increases context certainty
    if alert.event_count > 1:
        score += 0.10

    return min(1.0, round(score, 2))


def calculate_behavioral_confidence(alert: Alert, db: Optional[Session] = None) -> float:
    """
    Evaluates behavioral anomaly confidence blending heuristic baseline and ML Isolation Forest.
    """
    base_score = 0.60
    if alert.severity.lower() == "critical":
        base_score += 0.25
    elif alert.severity.lower() == "high":
        base_score += 0.15

    if alert.event_count >= 5:
        base_score += 0.10

    base_score = min(1.0, round(base_score, 2))

    if db is not None:
        try:
            from app.services.ml_anomaly_service import score_alert_behavior

            ml_result = score_alert_behavior(db, alert)
            ml_anomaly = ml_result.get("anomaly_score", 0.5)
            # Blend 50% heuristic baseline + 50% calibrated ML anomaly score
            calibrated_ml = 0.40 + (0.60 * ml_anomaly)
            blended = (0.50 * base_score) + (0.50 * calibrated_ml)
            return min(1.0, round(blended, 2))
        except Exception:
            return base_score

    return base_score



def evaluate_alert_quality(db: Session, alert: Alert) -> DetectionQuality:
    """
    Calculates explainable DetectionQuality for an Alert.
    """
    existing = db.query(DetectionQuality).filter(DetectionQuality.alert_id == alert.id).first()
    if existing:
        return existing

    # 1. Evidence Completeness
    evidence_items = build_evidence_package(db, alert)
    ev_comp = calculate_evidence_completeness(evidence_items)

    # 2. Correlation Strength
    # Check if linked to an incident
    inc_link = db.query(IncidentAlert).filter(IncidentAlert.alert_id == alert.id).first()
    if inc_link:
        incident_alerts = (
            db.query(Alert)
            .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
            .filter(IncidentAlert.incident_id == inc_link.incident_id)
            .all()
        )
        metrics = calculate_correlation_metrics(incident_alerts)
        corr_strength = metrics["correlation_strength"]
    else:
        corr_strength = 0.50 if alert.event_count > 1 else 0.30

    # 3. Rule Confidence
    rule_conf = get_rule_confidence(alert)

    # 4. Behavioral Confidence
    behav_conf = calculate_behavioral_confidence(alert, db=db)

    # 5. Context Confidence
    context_conf = calculate_context_confidence(alert, db)

    # Weighted Overall Quality Formula:
    # 0.25 * Evidence + 0.20 * Correlation + 0.20 * Rule + 0.15 * Behavioral + 0.20 * Context
    overall = (
        (0.25 * ev_comp)
        + (0.20 * corr_strength)
        + (0.20 * rule_conf)
        + (0.15 * behav_conf)
        + (0.20 * context_conf)
    )
    overall_quality = round(min(1.0, max(0.0, overall)), 2)

    factors = {
        "evidence_completeness": ev_comp,
        "correlation_strength": corr_strength,
        "rule_confidence": rule_conf,
        "behavioral_confidence": behav_conf,
        "context_confidence": context_conf,
        "weights": {
            "evidence_completeness": 0.25,
            "correlation_strength": 0.20,
            "rule_confidence": 0.20,
            "behavioral_confidence": 0.15,
            "context_confidence": 0.20,
        },
        "event_count": alert.event_count,
        "is_incident_linked": inc_link is not None,
    }


    tier = "High" if overall_quality >= 0.80 else "Medium" if overall_quality >= 0.55 else "Low"
    explanation = (
        f"{tier}-confidence detection (Quality: {overall_quality:.2f}). "
        f"Evidence completeness is {ev_comp:.2f}, rule confidence is {rule_conf:.2f}, "
        f"correlation strength is {corr_strength:.2f}, and context certainty is {context_conf:.2f}."
    )

    dq = DetectionQuality(
        alert_id=alert.id,
        incident_id=inc_link.incident_id if inc_link else None,
        overall_quality=overall_quality,
        evidence_completeness=ev_comp,
        correlation_strength=corr_strength,
        rule_confidence=rule_conf,
        behavioral_confidence=behav_conf,
        context_confidence=context_conf,
        factors_json=factors,
        explanation=explanation,
    )
    db.add(dq)
    db.flush()
    return dq


def evaluate_incident_quality(db: Session, incident: Incident) -> DetectionQuality:
    """
    Calculates explainable DetectionQuality for an Incident.
    """
    existing = db.query(DetectionQuality).filter(DetectionQuality.incident_id == incident.id, DetectionQuality.alert_id.is_(None)).first()
    if existing:
        return existing

    links = db.query(IncidentAlert).filter(IncidentAlert.incident_id == incident.id).all()
    alert_ids = [l.alert_id for l in links]
    alerts = db.query(Alert).filter(Alert.id.in_(alert_ids)).all() if alert_ids else []

    # Calculate average factor scores across component alerts
    alert_dqs = [evaluate_alert_quality(db, a) for a in alerts] if alerts else []

    if alert_dqs:
        ev_comp = round(sum(d.evidence_completeness for d in alert_dqs) / len(alert_dqs), 2)
        corr_strength = round(sum(d.correlation_strength for d in alert_dqs) / len(alert_dqs), 2)
        rule_conf = round(sum(d.rule_confidence for d in alert_dqs) / len(alert_dqs), 2)
        behav_conf = round(sum(d.behavioral_confidence for d in alert_dqs) / len(alert_dqs), 2)
        context_conf = round(sum(d.context_confidence for d in alert_dqs) / len(alert_dqs), 2)
        overall_quality = round(sum(d.overall_quality for d in alert_dqs) / len(alert_dqs), 2)
    else:
        ev_comp = 0.50
        corr_strength = 0.50
        rule_conf = 0.75
        behav_conf = 0.60
        context_conf = 0.60
        overall_quality = 0.60

    factors = {
        "evidence_completeness": ev_comp,
        "correlation_strength": corr_strength,
        "rule_confidence": rule_conf,
        "behavioral_confidence": behav_conf,
        "context_confidence": context_conf,
        "component_alert_count": len(alerts),
    }

    dq = DetectionQuality(
        alert_id=None,
        incident_id=incident.id,
        overall_quality=overall_quality,
        evidence_completeness=ev_comp,
        correlation_strength=corr_strength,
        rule_confidence=rule_conf,
        behavioral_confidence=behav_conf,
        context_confidence=context_conf,
        factors_json=factors,
        explanation=f"Incident quality score {overall_quality:.2f} based on {len(alerts)} component alerts.",
    )
    db.add(dq)
    db.flush()
    return dq


def get_detection_quality_summary(db: Session) -> dict[str, Any]:
    """
    Returns aggregated detection quality metrics for dashboard and research evaluation.
    """
    records = db.query(DetectionQuality).filter(DetectionQuality.alert_id.is_not(None)).all()
    if not records:
        # Populate for existing alerts if none exist
        all_alerts = db.query(Alert).all()
        records = [evaluate_alert_quality(db, a) for a in all_alerts]
        db.commit()

    total = len(records)
    if total == 0:
        return {
            "average_quality": 0.0,
            "average_evidence_completeness": 0.0,
            "average_correlation_strength": 0.0,
            "average_rule_confidence": 0.0,
            "average_behavioral_confidence": 0.0,
            "average_context_confidence": 0.0,
            "tier_distribution": {"high": 0, "medium": 0, "low": 0},
            "weak_detection_count": 0,
            "strong_detection_count": 0,
            "rule_quality_rankings": [],
        }

    avg_qual = round(sum(r.overall_quality for r in records) / total, 2)
    avg_ev = round(sum(r.evidence_completeness for r in records) / total, 2)
    avg_corr = round(sum(r.correlation_strength for r in records) / total, 2)
    avg_rule = round(sum(r.rule_confidence for r in records) / total, 2)
    avg_behav = round(sum(r.behavioral_confidence for r in records) / total, 2)
    avg_ctx = round(sum(r.context_confidence for r in records) / total, 2)

    high_count = sum(1 for r in records if r.overall_quality >= 0.80)
    med_count = sum(1 for r in records if 0.55 <= r.overall_quality < 0.80)
    low_count = sum(1 for r in records if r.overall_quality < 0.55)

    weak_count = sum(1 for r in records if r.overall_quality < 0.60)
    strong_count = sum(1 for r in records if r.overall_quality >= 0.80)

    # Quality breakdown by rule
    rule_scores: dict[str, list[float]] = {}
    for r in records:
        if r.alert:
            rule_name = r.alert.title
            rule_scores.setdefault(rule_name, []).append(r.overall_quality)

    rule_rankings = [
        {
            "rule_name": name,
            "alert_count": len(scores),
            "average_quality": round(sum(scores) / len(scores), 2),
        }
        for name, scores in sorted(rule_scores.items(), key=lambda item: sum(item[1]) / len(item[1]), reverse=True)
    ]

    return {
        "average_quality": avg_qual,
        "average_evidence_completeness": avg_ev,
        "average_correlation_strength": avg_corr,
        "average_rule_confidence": avg_rule,
        "average_behavioral_confidence": avg_behav,
        "average_context_confidence": avg_ctx,
        "tier_distribution": {"high": high_count, "medium": med_count, "low": low_count},
        "weak_detection_count": weak_count,
        "strong_detection_count": strong_count,
        "rule_quality_rankings": rule_rankings[:10],
    }


# =====================================================================
# Phase 2: Explainable Rule Health Score & Persistent Quality Metrics
# =====================================================================

def calculate_rule_health_score(
    tp: Optional[int],
    fp: Optional[int],
    fn: Optional[int],
    tn: Optional[int],
    latency_ms: Optional[float] = None,
    confidence: Optional[float] = 0.80,
    regression_status: str = "PASSED",
) -> tuple[Optional[float], str, dict[str, Any]]:
    """
    Computes an explainable Rule Health Score in [0.0, 100.0] based on 5 measurable dimensions:
      1. Accuracy / F1 Score (weight: 0.35)
      2. False-Positive Resistance [1 - FPR] (weight: 0.25)
      3. Regression Status [PASSED=1.0, UNTESTED=0.5, FAILED=0.0] (weight: 0.20)
      4. Latency Score [budget 50ms] (weight: 0.10)
      5. Intrinsic Evidence/Confidence [0.0 - 1.0] (weight: 0.10)

    If insufficient test or evaluation data exists (TP+FP+FN+TN == 0),
    returns (None, "INSUFFICIENT_DATA", details) to prevent artificial scores.
    """
    total_evals = (tp or 0) + (fp or 0) + (fn or 0) + (tn or 0)
    if total_evals == 0:
        return None, "INSUFFICIENT_DATA", {
            "status": "NOT ENOUGH DATA",
            "reason": "No evaluation assertions or validation runs available for this rule",
        }

    # 1. Accuracy / F1 factor (weight: 0.35)
    f_acc = 0.0
    if ((tp or 0) + (fp or 0)) > 0 and ((tp or 0) + (fn or 0)) > 0:
        p = (tp or 0) / ((tp or 0) + (fp or 0))
        r = (tp or 0) / ((tp or 0) + (fn or 0))
        f_acc = (2 * p * r / (p + r)) if (p + r) > 0 else 0.0
    elif (fn or 0) == 0 and (fp or 0) == 0:
        f_acc = 1.0

    # 2. False-positive burden factor (weight: 0.25)
    if ((fp or 0) + (tn or 0)) > 0:
        fpr = (fp or 0) / ((fp or 0) + (tn or 0))
        f_fp = max(0.0, 1.0 - fpr)
    else:
        f_fp = 1.0 if (fp or 0) == 0 else 0.0

    # 3. Regression factor (weight: 0.20)
    if regression_status == "PASSED":
        f_reg = 1.0
    elif regression_status == "FAILED":
        f_reg = 0.0
    else:
        f_reg = 0.5  # UNTESTED

    # 4. Detection latency factor (weight: 0.10, SLA budget: 50.0ms)
    lat = latency_ms if latency_ms is not None else 5.0
    f_lat = max(0.0, min(1.0, 1.0 - (lat / 50.0)))

    # 5. Rule intrinsic confidence factor (weight: 0.10)
    conf = confidence if confidence is not None else 0.80
    f_evid = max(0.0, min(1.0, conf))

    # Explainable weighted sum
    score_raw = (0.35 * f_acc) + (0.25 * f_fp) + (0.20 * f_reg) + (0.10 * f_lat) + (0.10 * f_evid)
    score = round(max(0.0, min(100.0, score_raw * 100.0)), 1)

    if score >= 85.0:
        tier = "EXCELLENT"
    elif score >= 70.0:
        tier = "HEALTHY"
    elif score >= 50.0:
        tier = "DEGRADED"
    else:
        tier = "UNHEALTHY"

    details = {
        "formula": "Score = (0.35 * F_acc + 0.25 * F_fp + 0.20 * F_reg + 0.10 * F_lat + 0.10 * F_conf) * 100.0",
        "subscores": {
            "accuracy_f1": round(f_acc, 3),
            "fp_resistance": round(f_fp, 3),
            "regression_score": round(f_reg, 3),
            "latency_score": round(f_lat, 3),
            "confidence_score": round(f_evid, 3),
        },
        "weights": {
            "accuracy": 0.35,
            "false_positive_resistance": 0.25,
            "regression": 0.20,
            "latency": 0.10,
            "confidence": 0.10,
        },
    }
    return score, tier, details


def evaluate_rule_health(
    db: Session,
    rule: DetectionRule,
    dataset_target: str = "validation_suite",
    persist: bool = True,
) -> Any:
    """
    Evaluates detection quality for a specific DetectionRule, calculating precision, recall,
    F1, FPR, latency, and the explainable Health Score, persisting to rule_health_records.
    """
    from app.models import RuleHealthRecord, ValidationTest
    from app.services.validation_service import run_rule_validation_suite

    # Check existing tests or run validation suite
    tests = db.query(ValidationTest).filter(ValidationTest.rule_id == rule.id).all()
    if not tests:
        suite = run_rule_validation_suite(db, rule.id)
        tests = suite.get("results", [])

    tp = 0
    fp = 0
    fn = 0
    tn = 0
    latencies: list[float] = []

    for t in tests:
        if t.execution_time_ms is not None:
            latencies.append(t.execution_time_ms)
        if t.expected_result and t.observed_result:
            tp += 1
        elif not t.expected_result and t.observed_result:
            fp += 1
        elif t.expected_result and not t.observed_result:
            fn += 1
        else:
            tn += 1

    total_evals = tp + fp + fn + tn
    precision: Optional[float] = round(tp / (tp + fp), 3) if (tp + fp) > 0 else None
    recall: Optional[float] = round(tp / (tp + fn), 3) if (tp + fn) > 0 else None
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1_score: Optional[float] = round(2 * precision * recall / (precision + recall), 3)
    else:
        f1_score = None

    fpr: Optional[float] = round(fp / (fp + tn), 3) if (fp + tn) > 0 else None
    avg_latency: Optional[float] = round(sum(latencies) / len(latencies), 2) if latencies else None

    # Alert volume from operational telemetry
    alert_vol = db.query(Alert).filter(Alert.rule_id == rule.id).count()

    # Regression status
    failed_tests = [t for t in tests if not t.passed]
    if not tests:
        regression_status = "UNTESTED"
    elif failed_tests:
        regression_status = "FAILED"
    else:
        regression_status = "PASSED"

    coverage = 1.0 if (tp > 0 and tn > 0) else 0.5 if total_evals > 0 else None
    rule_conf = rule.confidence if rule.confidence is not None else 0.80

    health_score, health_tier, factors = calculate_rule_health_score(
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        latency_ms=avg_latency,
        confidence=rule_conf,
        regression_status=regression_status,
    )

    factors["total_tests"] = len(tests)
    factors["failed_test_count"] = len(failed_tests)
    factors["operational_alert_volume"] = alert_vol

    record = RuleHealthRecord(
        rule_id=rule.id,
        rule_name=rule.name,
        version=rule.version or "1.0",
        dataset_target=dataset_target,
        true_positives=tp if total_evals > 0 else None,
        false_positives=fp if total_evals > 0 else None,
        false_negatives=fn if total_evals > 0 else None,
        true_negatives=tn if total_evals > 0 else None,
        precision=precision,
        recall=recall,
        f1_score=f1_score,
        false_positive_rate=fpr,
        alert_volume=alert_vol,
        detection_latency_ms=avg_latency,
        coverage_score=coverage,
        confidence=rule_conf,
        regression_status=regression_status,
        health_score=health_score,
        health_tier=health_tier,
        details_json=factors,
    )

    if persist:
        db.add(record)
        db.commit()
        db.refresh(record)

    return record


def evaluate_all_rules_health(db: Session, dataset_target: str = "validation_suite") -> list[Any]:
    """Evaluates and persists health records for all active DetectionRules."""
    rules = db.query(DetectionRule).all()
    results = []
    for r in rules:
        rec = evaluate_rule_health(db, r, dataset_target=dataset_target, persist=True)
        results.append(rec)
    return results


def get_latest_rule_health(db: Session, rule_id: int) -> Optional[Any]:
    """Retrieves the most recent persistent health record for a given rule."""
    from app.models import RuleHealthRecord
    return (
        db.query(RuleHealthRecord)
        .filter(RuleHealthRecord.rule_id == rule_id)
        .order_by(RuleHealthRecord.evaluated_at.desc())
        .first()
    )


def get_all_latest_rule_health(db: Session) -> list[Any]:
    """Retrieves the latest health record for each rule in the database."""
    from app.models import RuleHealthRecord
    rules = db.query(DetectionRule).all()
    records = []
    for r in rules:
        latest = get_latest_rule_health(db, r.id)
        if not latest:
            # Generate evaluation record if none exists yet
            latest = evaluate_rule_health(db, r, persist=True)
        records.append(latest)
    return records

