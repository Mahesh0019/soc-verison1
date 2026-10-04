"""
backend/app/services/risk_service.py

Risk & Triage Engine
Computes explainable, multi-factor risk scores and risk tiers:
Risk Score = (Impact * Likelihood / 10) * Asset Multiplier * 10
Normalized to [0.0, 100.0]

Tiers:
- LOW: < 25.0
- MEDIUM: 25.0 - 49.9
- HIGH: 50.0 - 74.9
- CRITICAL: >= 75.0
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models import Alert, Incident, IncidentAlert, RiskAssessment
from app.services.detection_quality_service import evaluate_alert_quality


IMPACT_SCORES = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
}

ASSET_MULTIPLIERS = {
    "CRITICAL": 1.30,
    "HIGH": 1.15,
    "MEDIUM": 1.00,
    "LOW": 0.85,
}


def evaluate_risk_level(score: float) -> str:
    if score >= 75.0:
        return "CRITICAL"
    if score >= 50.0:
        return "HIGH"
    if score >= 25.0:
        return "MEDIUM"
    return "LOW"


def evaluate_alert_risk(
    db: Session,
    alert: Alert,
    asset_criticality: str = "MEDIUM",
) -> RiskAssessment:
    """
    Computes explainable risk assessment for an Alert.
    """
    existing = db.query(RiskAssessment).filter(RiskAssessment.alert_id == alert.id).first()
    if existing:
        return existing

    dq = evaluate_alert_quality(db, alert)

    impact = IMPACT_SCORES.get(alert.severity.lower(), 5.0)
    # Likelihood is heavily guided by detection quality and event persistence
    base_likelihood = max(3.0, dq.overall_quality * 9.0)
    if alert.event_count >= 5:
        base_likelihood = min(10.0, base_likelihood + 1.0)

    asset_mult = ASSET_MULTIPLIERS.get(asset_criticality.upper(), 1.0)
    raw_score = (impact * base_likelihood / 10.0) * asset_mult * 10.0
    risk_score = round(min(100.0, max(0.0, raw_score)), 1)
    risk_level = evaluate_risk_level(risk_score)

    justification = (
        f"Assessed {risk_level} risk (score: {risk_score}/100). "
        f"Impact rated {impact:.1f}/10 for {alert.severity} severity; "
        f"likelihood estimated at {base_likelihood:.1f}/10 based on detection quality {dq.overall_quality:.2f}; "
        f"asset criticality modifier: {asset_criticality} (x{asset_mult:.2f})."
    )

    factors = {
        "impact_score": impact,
        "likelihood_score": base_likelihood,
        "asset_criticality": asset_criticality,
        "asset_multiplier": asset_mult,
        "detection_quality": dq.overall_quality,
        "raw_score": raw_score,
    }

    assessment = RiskAssessment(
        alert_id=alert.id,
        incident_id=dq.incident_id,
        risk_score=risk_score,
        risk_level=risk_level,
        impact_score=impact,
        likelihood_score=base_likelihood,
        asset_criticality=asset_criticality,
        justification=justification,
        factors_json=factors,
    )
    db.add(assessment)
    db.flush()
    return assessment


def evaluate_incident_risk(
    db: Session,
    incident: Incident,
    asset_criticality: str = "HIGH",
) -> RiskAssessment:
    """
    Computes explainable risk assessment for a multi-alert Incident.
    """
    existing = db.query(RiskAssessment).filter(RiskAssessment.incident_id == incident.id, RiskAssessment.alert_id.is_(None)).first()
    if existing:
        return existing

    links = db.query(IncidentAlert).filter(IncidentAlert.incident_id == incident.id).all()
    alert_ids = [l.alert_id for l in links]
    alerts = db.query(Alert).filter(Alert.id.in_(alert_ids)).all() if alert_ids else []

    impact = IMPACT_SCORES.get(incident.severity.lower(), 6.0)
    # Incidents with multiple alerts have higher likelihood
    base_likelihood = min(10.0, 5.0 + (len(alerts) * 1.2))
    asset_mult = ASSET_MULTIPLIERS.get(asset_criticality.upper(), 1.15)

    raw_score = (impact * base_likelihood / 10.0) * asset_mult * 10.0
    risk_score = round(min(100.0, max(0.0, raw_score)), 1)
    risk_level = evaluate_risk_level(risk_score)

    justification = (
        f"Incident {incident.incident_number} assigned {risk_level} risk ({risk_score}/100). "
        f"Correlates {len(alerts)} alerts across {incident.event_count} events with {incident.severity} severity."
    )

    assessment = RiskAssessment(
        alert_id=None,
        incident_id=incident.id,
        risk_score=risk_score,
        risk_level=risk_level,
        impact_score=impact,
        likelihood_score=base_likelihood,
        asset_criticality=asset_criticality,
        justification=justification,
        factors_json={
            "impact_score": impact,
            "likelihood_score": base_likelihood,
            "asset_criticality": asset_criticality,
            "alert_count": len(alerts),
            "event_count": incident.event_count,
        },
    )
    db.add(assessment)
    db.flush()
    return assessment


def get_risk_summary(db: Session) -> dict[str, Any]:
    """
    Aggregates risk score distributions across active alerts and incidents.
    """
    assessments = db.query(RiskAssessment).all()
    if not assessments:
        alerts = db.query(Alert).all()
        assessments = [evaluate_alert_risk(db, a) for a in alerts]
        db.commit()

    total = len(assessments)
    if total == 0:
        return {
            "average_risk_score": 0.0,
            "risk_tier_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "highest_risk_items": [],
        }

    avg_score = round(sum(r.risk_score for r in assessments) / total, 1)
    tier_counts = {
        "CRITICAL": sum(1 for r in assessments if r.risk_level == "CRITICAL"),
        "HIGH": sum(1 for r in assessments if r.risk_level == "HIGH"),
        "MEDIUM": sum(1 for r in assessments if r.risk_level == "MEDIUM"),
        "LOW": sum(1 for r in assessments if r.risk_level == "LOW"),
    }

    highest = sorted(assessments, key=lambda r: r.risk_score, reverse=True)[:5]
    highest_items = [
        {
            "id": r.id,
            "alert_id": r.alert_id,
            "incident_id": r.incident_id,
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "justification": r.justification,
        }
        for r in highest
    ]

    return {
        "average_risk_score": avg_score,
        "risk_tier_counts": tier_counts,
        "highest_risk_items": highest_items,
    }
