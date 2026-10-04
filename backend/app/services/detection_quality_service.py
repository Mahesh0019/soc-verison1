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
    "possible directory brute force": 0.80,
    "multiple failed login attempts from same ip": 0.80,
    "login attempt from unusual country": 0.75,
    "suspicious user agent": 0.75,
    "firewall denied traffic spike": 0.70,
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
