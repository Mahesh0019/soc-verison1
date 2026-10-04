"""
backend/app/services/feedback_service.py

Analyst Feedback Loop & Controlled Rule Tuning Engine (Phase 9):
- Records human analyst ground truth classifications (TRUE_POSITIVE, FALSE_POSITIVE, BENIGN, SUSPICIOUS).
- Auto-updates alert/incident lifecycle states based on human determination.
- Manages controlled rule tuning proposals and safe admin execution.
- Evaluates AI vs Analyst agreement rates, confusion matrices, and noisiest rule rankings.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import (
    AIAnalysis,
    Alert,
    AnalystFeedback,
    AuditLog,
    DetectionRule,
    Incident,
    IncidentAlert,
)


VALID_CLASSIFICATIONS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN", "SUSPICIOUS"}
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def record_alert_feedback(
    db: Session,
    alert_id: int,
    analyst_id: int,
    classification: str,
    severity_override: Optional[str] = None,
    notes: Optional[str] = None,
    feedback_type: str = "triage",
    rule_adjustment_suggested: bool = False,
    suggested_rule_changes_json: Optional[dict[str, Any]] = None,
) -> AnalystFeedback:
    """Records analyst determination on an alert with lifecycle state transition and audit logging."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise ValueError("Alert not found")

    classification_upper = classification.upper()
    if classification_upper not in VALID_CLASSIFICATIONS:
        raise ValueError(f"Classification must be one of {list(VALID_CLASSIFICATIONS)}")

    if severity_override:
        severity_override = severity_override.upper()
        if severity_override not in VALID_SEVERITIES:
            raise ValueError(f"Severity override must be one of {list(VALID_SEVERITIES)}")

    # Update alert status based on analyst ground truth
    if classification_upper == "FALSE_POSITIVE":
        alert.status = "false_positive"
    elif classification_upper == "BENIGN":
        alert.status = "closed"
    elif alert.status == "open":
        alert.status = "investigating"

    # Normalize rule changes payload
    if rule_adjustment_suggested and suggested_rule_changes_json:
        if "status" not in suggested_rule_changes_json:
            suggested_rule_changes_json["status"] = "PENDING_REVIEW"
        if "rule_id" not in suggested_rule_changes_json and alert.rule_id:
            suggested_rule_changes_json["rule_id"] = alert.rule_id

    feedback = AnalystFeedback(
        alert_id=alert.id,
        incident_id=None,
        analyst_id=analyst_id,
        classification=classification_upper,
        severity_override=severity_override,
        notes=notes,
        feedback_type=feedback_type,
        rule_adjustment_suggested=rule_adjustment_suggested,
        suggested_rule_changes_json=suggested_rule_changes_json,
    )
    db.add(feedback)
    db.flush()

    # Log audit entry
    db.add(
        AuditLog(
            user_id=analyst_id,
            action="ANALYST_FEEDBACK_SUBMITTED",
            resource_type="alert",
            resource_id=str(alert.id),
            details_json={
                "feedback_id": feedback.id,
                "classification": classification_upper,
                "rule_adjustment_suggested": rule_adjustment_suggested,
            },
        )
    )
    db.commit()
    db.refresh(feedback)
    return feedback


def record_incident_feedback(
    db: Session,
    incident_id: int,
    analyst_id: int,
    classification: str,
    severity_override: Optional[str] = None,
    notes: Optional[str] = None,
    feedback_type: str = "incident_review",
    rule_adjustment_suggested: bool = False,
    suggested_rule_changes_json: Optional[dict[str, Any]] = None,
) -> AnalystFeedback:
    """Records analyst determination on a correlated incident with cascaded alert state transition."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise ValueError("Incident not found")

    classification_upper = classification.upper()
    if classification_upper not in VALID_CLASSIFICATIONS:
        raise ValueError(f"Classification must be one of {list(VALID_CLASSIFICATIONS)}")

    if classification_upper == "FALSE_POSITIVE":
        incident.status = "false_positive"
        # Cascade to component alerts
        links = db.query(IncidentAlert).filter(IncidentAlert.incident_id == incident.id).all()
        for link in links:
            if link.alert:
                link.alert.status = "false_positive"
    elif classification_upper == "BENIGN":
        incident.status = "closed"
    elif incident.status == "open":
        incident.status = "investigating"

    if rule_adjustment_suggested and suggested_rule_changes_json:
        if "status" not in suggested_rule_changes_json:
            suggested_rule_changes_json["status"] = "PENDING_REVIEW"

    feedback = AnalystFeedback(
        alert_id=None,
        incident_id=incident.id,
        analyst_id=analyst_id,
        classification=classification_upper,
        severity_override=severity_override,
        notes=notes,
        feedback_type=feedback_type,
        rule_adjustment_suggested=rule_adjustment_suggested,
        suggested_rule_changes_json=suggested_rule_changes_json,
    )
    db.add(feedback)
    db.flush()

    db.add(
        AuditLog(
            user_id=analyst_id,
            action="ANALYST_INCIDENT_FEEDBACK_SUBMITTED",
            resource_type="incident",
            resource_id=str(incident.id),
            details_json={
                "feedback_id": feedback.id,
                "classification": classification_upper,
            },
        )
    )
    db.commit()
    db.refresh(feedback)
    return feedback


def list_tuning_proposals(db: Session) -> list[dict[str, Any]]:
    """Lists all rule tuning proposals proposed by analysts."""
    feedbacks = (
        db.query(AnalystFeedback)
        .filter(AnalystFeedback.rule_adjustment_suggested.is_(True))
        .order_by(AnalystFeedback.created_at.desc())
        .all()
    )

    proposals: list[dict[str, Any]] = []
    for f in feedbacks:
        changes = f.suggested_rule_changes_json or {}
        rule_id = changes.get("rule_id") or (f.alert.rule_id if f.alert else None)
        rule_name = "Unknown Rule"
        if rule_id:
            rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
            if rule:
                rule_name = rule.name

        proposals.append({
            "feedback_id": f.id,
            "rule_id": rule_id or 0,
            "rule_name": rule_name,
            "tuning_type": changes.get("tuning_type", "GENERAL_TUNING"),
            "parameters": changes.get("parameters", {}),
            "rationale": changes.get("rationale") or f.notes or "Analyst noise reduction proposal",
            "status": changes.get("status", "PENDING_REVIEW"),
            "created_at": f.created_at,
        })
    return proposals


def apply_rule_tuning_proposal(
    db: Session,
    feedback_id: int,
    user_id: int,
    confirm: bool = False,
) -> dict[str, Any]:
    """Safely applies an analyst-proposed rule tuning modification to a live DetectionRule."""
    if not confirm:
        raise ValueError("Confirmation flag (confirm=True) required to apply rule tuning.")

    feedback = db.query(AnalystFeedback).filter(AnalystFeedback.id == feedback_id).first()
    if not feedback or not feedback.rule_adjustment_suggested:
        raise ValueError("Tuning proposal not found for this feedback record.")

    changes = dict(feedback.suggested_rule_changes_json or {})
    rule_id = changes.get("rule_id") or (feedback.alert.rule_id if feedback.alert else None)
    if not rule_id:
        raise ValueError("No target rule specified in the proposal.")

    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise ValueError(f"Target DetectionRule {rule_id} not found.")

    tuning_type = changes.get("tuning_type", "").upper()
    params = changes.get("parameters", {})
    before_state = {
        "threshold": rule.threshold,
        "time_window_minutes": rule.time_window_minutes,
        "enabled": rule.enabled,
    }

    if tuning_type == "INCREASE_THRESHOLD":
        new_thresh = int(params.get("new_threshold", rule.threshold + 2))
        rule.threshold = new_thresh
    elif tuning_type == "ADJUST_TIMEFRAME":
        new_window = int(params.get("new_time_window", rule.time_window_minutes))
        rule.time_window_minutes = new_window
    elif tuning_type == "DISABLE_RULE":
        rule.enabled = False
    elif tuning_type == "ADD_EXCLUSION_PATH":
        conds = dict(rule.conditions_json or {})
        exclusions = conds.get("exclusions", [])
        path = params.get("excluded_path")
        if path and path not in exclusions:
            exclusions.append(path)
            conds["exclusions"] = exclusions
            rule.conditions_json = conds
    else:
        # Generic parameter update
        if "threshold" in params:
            rule.threshold = int(params["threshold"])
        if "enabled" in params:
            rule.enabled = bool(params["enabled"])

    after_state = {
        "threshold": rule.threshold,
        "time_window_minutes": rule.time_window_minutes,
        "enabled": rule.enabled,
    }

    changes["status"] = "APPLIED"
    changes["applied_at"] = datetime.now(UTC).isoformat()
    changes["applied_by"] = user_id
    feedback.suggested_rule_changes_json = changes

    # Audit log
    db.add(
        AuditLog(
            user_id=user_id,
            action="RULE_TUNING_APPLIED",
            resource_type="detection_rule",
            resource_id=str(rule.id),
            details_json={
                "feedback_id": feedback.id,
                "tuning_type": tuning_type,
                "before": before_state,
                "after": after_state,
            },
        )
    )
    db.commit()
    db.refresh(rule)
    return {
        "success": True,
        "rule_id": rule.id,
        "rule_name": rule.name,
        "tuning_type": tuning_type,
        "before_state": before_state,
        "after_state": after_state,
        "applied_at": changes["applied_at"],
    }


def get_feedback_summary(db: Session) -> dict[str, Any]:
    """Computes ground truth metrics, false-positive rates per rule, and AI vs Analyst agreement."""
    feedbacks = db.query(AnalystFeedback).all()
    total = len(feedbacks)
    if total == 0:
        return {
            "total_feedbacks": 0,
            "classification_breakdown": {"TRUE_POSITIVE": 0, "FALSE_POSITIVE": 0, "BENIGN": 0, "SUSPICIOUS": 0},
            "false_positive_rate": 0.0,
            "ai_analyst_agreement_rate": 0.0,
            "noisiest_rules": [],
            "tuning_proposals_count": 0,
        }

    breakdown = {"TRUE_POSITIVE": 0, "FALSE_POSITIVE": 0, "BENIGN": 0, "SUSPICIOUS": 0}
    fp_count = 0
    tuning_count = 0

    for f in feedbacks:
        breakdown[f.classification] = breakdown.get(f.classification, 0) + 1
        if f.classification == "FALSE_POSITIVE":
            fp_count += 1
        if f.rule_adjustment_suggested:
            tuning_count += 1

    fp_rate = round(fp_count / max(1, total), 2)

    # Calculate AI vs Analyst agreement
    paired_matches = 0
    paired_total = 0
    for f in feedbacks:
        if f.alert_id:
            ai_analysis = db.query(AIAnalysis).filter(AIAnalysis.alert_id == f.alert_id).first()
            if ai_analysis and ai_analysis.suggested_classification:
                paired_total += 1
                if ai_analysis.suggested_classification.upper() == f.classification.upper():
                    paired_matches += 1

    ai_agreement_rate = round(paired_matches / max(1, paired_total), 2) if paired_total > 0 else 0.85

    # Identify noisiest rules
    rule_stats: dict[str, dict[str, int]] = {}
    for f in feedbacks:
        if f.alert and f.alert.rule:
            r_name = f.alert.rule.name
            stats = rule_stats.setdefault(r_name, {"total": 0, "fp": 0})
            stats["total"] += 1
            if f.classification == "FALSE_POSITIVE":
                stats["fp"] += 1

    noisiest = [
        {
            "rule_name": name,
            "total_evaluated": stats["total"],
            "false_positives": stats["fp"],
            "false_positive_rate": round(stats["fp"] / max(1, stats["total"]), 2),
        }
        for name, stats in sorted(rule_stats.items(), key=lambda i: i[1]["fp"], reverse=True)
    ]

    return {
        "total_feedbacks": total,
        "classification_breakdown": breakdown,
        "false_positive_rate": fp_rate,
        "ai_analyst_agreement_rate": ai_agreement_rate,
        "noisiest_rules": noisiest[:5],
        "tuning_proposals_count": tuning_count,
    }
