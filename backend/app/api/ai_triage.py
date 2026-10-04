"""
backend/app/api/ai_triage.py

REST API Endpoints for Evidence-Grounded SLM/LLM Assistance & Claims Audit (Phase 8):
- POST /api/ai/triage/alert/{alert_id}: Perform or retrieve evidence-grounded AI triage for an alert
- POST /api/ai/triage/incident/{incident_id}: Perform or retrieve evidence-grounded AI triage for an incident
- GET /api/ai/analyses: List all AI analyses
- GET /api/ai/analyses/{analysis_id}: Get specific analysis detail with claims audit breakdown
- POST /api/ai/analyses/{analysis_id}/feedback: Record analyst agreement feedback
- GET /api/ai/summary: Aggregated AI triage & claims audit metrics
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.utils import paginate
from app.auth.dependencies import get_current_user, require_roles
from app.database.session import get_db
from app.models import AIAnalysis, Alert, Incident, User
from app.schemas.ai_triage import (
    AIAgreementRequest,
    AIAnalysisOut,
    AITriageSummary,
)
from app.schemas.common import Page
from app.services.ai_triage_service import (
    get_ai_triage_summary,
    record_analyst_agreement,
    triage_alert,
    triage_incident,
)


router = APIRouter(prefix="/ai", tags=["AI Triage & Claims Audit"])


@router.post("/triage/alert/{alert_id}", response_model=AIAnalysisOut)
def run_alert_triage(
    alert_id: int,
    force_refresh: bool = Query(False, description="Re-run AI triage even if existing analysis exists"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AIAnalysis:
    """Generates an evidence-grounded AI triage assessment with claims audit for an alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    analysis = triage_alert(db, alert, force_refresh=force_refresh)
    db.commit()
    db.refresh(analysis)
    return analysis


@router.post("/triage/incident/{incident_id}", response_model=AIAnalysisOut)
def run_incident_triage(
    incident_id: int,
    force_refresh: bool = Query(False, description="Re-run AI triage even if existing analysis exists"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AIAnalysis:
    """Generates an evidence-grounded AI triage assessment with claims audit for an incident."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    analysis = triage_incident(db, incident, force_refresh=force_refresh)
    db.commit()
    db.refresh(analysis)
    return analysis


@router.get("/analyses", response_model=Page[AIAnalysisOut])
def list_analyses(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Lists generated AI triage analyses with claim metrics and analyst agreement status."""
    query = db.query(AIAnalysis).order_by(AIAnalysis.created_at.desc())
    items, total = paginate(query, page, page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/analyses/{analysis_id}", response_model=AIAnalysisOut)
def get_analysis_detail(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AIAnalysis:
    """Fetches details and verified claims breakdown for an AI triage analysis."""
    analysis = db.query(AIAnalysis).filter(AIAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI Analysis not found")
    return analysis


@router.post("/analyses/{analysis_id}/feedback", response_model=AIAnalysisOut)
def record_feedback(
    analysis_id: int,
    payload: AIAgreementRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> AIAnalysis:
    """Records human analyst agreement (AGREE, DISAGREE, PARTIAL) on AI triage findings."""
    try:
        updated = record_analyst_agreement(
            db,
            analysis_id=analysis_id,
            agreement=payload.agreement,
            user_id=current_user.id,
            notes=payload.notes,
        )
        return updated
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/summary", response_model=AITriageSummary)
def get_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AITriageSummary:
    """Retrieves aggregated AI triage performance, grounding rates, and claims audit metrics."""
    data = get_ai_triage_summary(db)
    return AITriageSummary(**data)
