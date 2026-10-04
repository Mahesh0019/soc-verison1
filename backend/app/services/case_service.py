"""
backend/app/services/case_service.py

Case Management and Controlled Response Service
Provides structured analyst investigation workflows and safe controlled response operations.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import Alert, AuditLog, Case, Incident, ThreatIndicator, User


VALID_CASE_STATUSES = {"OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE", "CLOSED"}
VALID_CASE_PRIORITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def next_case_number(db: Session) -> str:
    """Generates sequential CASE-xxx number."""
    count = db.query(func.count(Case.id)).scalar() or 0
    return f"CASE-{(count + 1):03d}"


def create_case(
    db: Session,
    title: str,
    description: str,
    priority: str = "MEDIUM",
    assigned_analyst_id: Optional[int] = None,
    alert_id: Optional[int] = None,
    incident_id: Optional[int] = None,
    user_id: Optional[int] = None,
) -> Case:
    case_num = next_case_number(db)
    clean_priority = priority.upper() if priority.upper() in VALID_CASE_PRIORITIES else "MEDIUM"

    case = Case(
        case_number=case_num,
        title=title,
        description=description,
        status="OPEN",
        priority=clean_priority,
        assigned_analyst_id=assigned_analyst_id,
        alert_id=alert_id,
        incident_id=incident_id,
    )
    db.add(case)
    db.flush()

    # Log audit event
    db.add(
        AuditLog(
            user_id=user_id,
            action="CREATE_CASE",
            resource_type="Case",
            resource_id=str(case.id),
            details_json={
                "case_number": case.case_number,
                "title": title,
                "priority": clean_priority,
                "alert_id": alert_id,
                "incident_id": incident_id,
            },
        )
    )
    db.commit()
    db.refresh(case)
    return case


def update_case(
    db: Session,
    case_id: int,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assigned_analyst_id: Optional[int] = None,
    resolution_summary: Optional[str] = None,
    user_id: Optional[int] = None,
) -> Optional[Case]:
    case = db.get(Case, case_id)
    if not case:
        return None

    changes: dict[str, Any] = {}

    if status and status.upper() in VALID_CASE_STATUSES:
        old_status = case.status
        case.status = status.upper()
        changes["status"] = {"old": old_status, "new": case.status}
        if case.status in ("RESOLVED", "FALSE_POSITIVE", "CLOSED"):
            case.closed_at = datetime.now(UTC)
        else:
            case.closed_at = None

    if priority and priority.upper() in VALID_CASE_PRIORITIES:
        old_priority = case.priority
        case.priority = priority.upper()
        changes["priority"] = {"old": old_priority, "new": case.priority}

    if assigned_analyst_id is not None:
        case.assigned_analyst_id = assigned_analyst_id
        changes["assigned_analyst_id"] = assigned_analyst_id

    if resolution_summary is not None:
        case.resolution_summary = resolution_summary
        changes["resolution_summary"] = resolution_summary

    if changes:
        db.add(
            AuditLog(
                user_id=user_id,
                action="UPDATE_CASE",
                resource_type="Case",
                resource_id=str(case.id),
                details_json=changes,
            )
        )
        db.commit()
        db.refresh(case)

    return case


def execute_controlled_response(
    db: Session,
    user: User,
    action_type: str,
    target_value: str,
    case_id: Optional[int] = None,
    simulated: bool = True,
    confirmation_notes: Optional[str] = None,
) -> dict[str, Any]:
    """
    Executes a safe, controlled response action with mandatory analyst attribution.
    No destructive network attacks are permitted.
    Supported actions:
    - SIMULATE_CONTAINMENT: isolates host/IP in simulated state.
    - ADD_WATCHLIST_INDICATOR: adds IP/domain to ThreatIndicator blacklist.
    - ACKNOWLEDGE_INCIDENT: marks incident acknowledged in audit log.
    """
    action_clean = action_type.upper()
    timestamp = datetime.now(UTC).isoformat()

    result_details: dict[str, Any] = {
        "action": action_clean,
        "target": target_value,
        "simulated": simulated,
        "executed_by": user.username,
        "timestamp": timestamp,
        "confirmation_notes": confirmation_notes,
    }

    if action_clean == "ADD_WATCHLIST_INDICATOR":
        # Add to local threat indicator table
        existing = db.query(ThreatIndicator).filter(
            ThreatIndicator.type == "ip",
            ThreatIndicator.value == target_value,
        ).first()
        if not existing:
            indicator = ThreatIndicator(
                type="ip",
                value=target_value,
                description=f"Added via controlled response by {user.username}: {confirmation_notes or 'Analyst containment'}",
                severity="high",
            )
            db.add(indicator)
            db.flush()
            result_details["status"] = "INDICATOR_ADDED"
        else:
            result_details["status"] = "INDICATOR_ALREADY_EXISTS"

    elif action_clean == "SIMULATE_CONTAINMENT":
        result_details["status"] = "CONTAINMENT_SIMULATED_SUCCESS"
        result_details["message"] = f"Simulated containment barrier applied to target {target_value}."

    else:
        result_details["status"] = "ACTION_LOGGED"
        result_details["message"] = f"Action {action_clean} logged."

    # Audit log entry
    audit = AuditLog(
        user_id=user.id,
        action=f"CONTROLLED_RESPONSE_{action_clean}",
        resource_type="Target",
        resource_id=target_value,
        details_json=result_details,
    )
    db.add(audit)
    db.commit()

    return {
        "success": True,
        "audit_id": audit.id,
        **result_details,
    }
