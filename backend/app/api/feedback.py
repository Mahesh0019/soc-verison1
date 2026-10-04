"""
backend/app/api/feedback.py

REST API Endpoints for Analyst Feedback Loop & Controlled Rule Tuning (Phase 9):
- POST /api/feedback/alert/{alert_id}: Submit analyst ground truth on an alert
- POST /api/feedback/incident/{incident_id}: Submit analyst ground truth on an incident
- GET /api/feedback: List analyst feedback records
- GET /api/feedback/{feedback_id}: Get detailed feedback record
- GET /api/feedback/rules/tuning-proposals: List active rule tuning proposals
- POST /api/feedback/rules/apply-tuning: Approve and safely apply rule tuning modification
- GET /api/feedback/summary: Ground truth metrics, false-positive breakdown, agreement rate
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.utils import paginate
from app.auth.dependencies import get_current_user, require_roles
from app.database.session import get_db
from app.models import AnalystFeedback, User
from app.schemas.common import Page
from app.schemas.feedback import (
    AnalystFeedbackCreate,
    AnalystFeedbackOut,
    FeedbackSummaryOut,
    RuleTuningApplyRequest,
    RuleTuningProposal,
)
from app.services.feedback_service import (
    apply_rule_tuning_proposal,
    get_feedback_summary,
    list_tuning_proposals,
    record_alert_feedback,
    record_incident_feedback,
)


router = APIRouter(prefix="/feedback", tags=["Analyst Feedback & Rule Tuning"])


@router.post("/alert/{alert_id}", response_model=AnalystFeedbackOut, status_code=status.HTTP_201_CREATED)
def submit_alert_feedback(
    alert_id: int,
    payload: AnalystFeedbackCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> AnalystFeedback:
    """Submits ground truth analyst classification and optional rule tuning proposal for an alert."""
    try:
        feedback = record_alert_feedback(
            db,
            alert_id=alert_id,
            analyst_id=current_user.id,
            classification=payload.classification,
            severity_override=payload.severity_override,
            notes=payload.notes,
            feedback_type=payload.feedback_type or "triage",
            rule_adjustment_suggested=bool(payload.rule_adjustment_suggested),
            suggested_rule_changes_json=payload.suggested_rule_changes_json,
        )
        return feedback
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/incident/{incident_id}", response_model=AnalystFeedbackOut, status_code=status.HTTP_201_CREATED)
def submit_incident_feedback(
    incident_id: int,
    payload: AnalystFeedbackCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> AnalystFeedback:
    """Submits ground truth analyst classification and cascades state for an incident."""
    try:
        feedback = record_incident_feedback(
            db,
            incident_id=incident_id,
            analyst_id=current_user.id,
            classification=payload.classification,
            severity_override=payload.severity_override,
            notes=payload.notes,
            feedback_type=payload.feedback_type or "incident_review",
            rule_adjustment_suggested=bool(payload.rule_adjustment_suggested),
            suggested_rule_changes_json=payload.suggested_rule_changes_json,
        )
        return feedback
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("", response_model=Page[AnalystFeedbackOut])
def list_feedback(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    classification: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieves paginated analyst feedback records."""
    query = db.query(AnalystFeedback)
    if classification:
        query = query.filter(AnalystFeedback.classification == classification.upper())
    query = query.order_by(AnalystFeedback.created_at.desc())
    items, total = paginate(query, page, page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/rules/tuning-proposals", response_model=list[RuleTuningProposal])
def get_rule_tuning_proposals(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[RuleTuningProposal]:
    """Lists pending and applied rule tuning proposals proposed by security analysts."""
    proposals = list_tuning_proposals(db)
    return [RuleTuningProposal(**p) for p in proposals]


@router.post("/rules/apply-tuning")
def apply_tuning(
    payload: RuleTuningApplyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
) -> dict[str, Any]:
    """Applies a proposed rule tuning change to a live DetectionRule (Admin only)."""
    try:
        result = apply_rule_tuning_proposal(
            db,
            feedback_id=payload.feedback_id,
            user_id=current_user.id,
            confirm=payload.confirm,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/summary", response_model=FeedbackSummaryOut)
def get_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> FeedbackSummaryOut:
    """Returns ground truth statistics, false-positive rates per rule, and AI agreement metrics."""
    data = get_feedback_summary(db)
    return FeedbackSummaryOut(**data)


@router.get("/{feedback_id}", response_model=AnalystFeedbackOut)
def get_feedback_detail(
    feedback_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AnalystFeedback:
    """Fetches details for a specific feedback record."""
    fb = db.query(AnalystFeedback).filter(AnalystFeedback.id == feedback_id).first()
    if not fb:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feedback not found")
    return fb
