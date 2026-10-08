"""
backend/app/api/ai_analyst.py

REST API Endpoints for Phase 8: Evidence-Grounded AI Analyst Assistance & Hallucination Evaluation.
- POST /api/ai/assistant/incident/{incident_id}: Generate/retrieve structured AI analyst assistance
- POST /api/ai/assistant/incident/{incident_id}/question: Ask an evidence-grounded investigation question
- GET /api/ai/assistant/incident/{incident_id}/context: Inspect raw bounded context with provenance & redactions
- GET /api/experiments/ai-analyst/evaluation: Retrieve Phase 8 System A vs System B evaluation metrics
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user, require_roles
from app.database.session import get_db
from app.models import Incident, User
from app.schemas.ai_analyst import (
    AIAnalystContextOut,
    AIAnalystStructuredOutput,
    AnalystQuestionRequest,
    AnalystQuestionResponse,
)
from app.services.ai_analyst_service import (
    answer_analyst_question,
    build_ai_analyst_context,
    generate_ai_analyst_assistance,
)

router = APIRouter(prefix="/ai/assistant", tags=["Evidence-Grounded AI Analyst Assistant"])


@router.post("/incident/{incident_id}", response_model=AIAnalystStructuredOutput)
def get_incident_assistant(
    incident_id: int,
    force_refresh: bool = Query(False, description="Re-generate assistance assessment"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AIAnalystStructuredOutput:
    """
    Generates structured, evidence-grounded AI analyst assistance for an incident.
    Guarantees:
      - Read-only: Does NOT alter authoritative incident status, risk, or evidence.
      - Every factual claim references verified incident evidence records.
      - Explicit abstention when evidence is insufficient or contradictory.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    analysis = generate_ai_analyst_assistance(db, incident, force_refresh=force_refresh)
    return analysis


@router.post("/incident/{incident_id}/question", response_model=AnalystQuestionResponse)
def ask_question_about_incident(
    incident_id: int,
    payload: AnalystQuestionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AnalystQuestionResponse:
    """
    Answers an analyst inquiry strictly bounded to the verified incident evidence.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    return answer_analyst_question(db, incident, payload.question)


@router.get("/incident/{incident_id}/context", response_model=AIAnalystContextOut)
def get_incident_ai_context(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AIAnalystContextOut:
    """
    Inspects the evidence-grounded context package built for the incident,
    including provenance tags, isolated untrusted payloads, and redacted fields count.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    context = build_ai_analyst_context(db, incident)
    return AIAnalystContextOut(
        incident_id=context["incident_id"],
        incident_number=context["incident_number"],
        severity=context["severity"],
        risk_score=context["risk_score"],
        correlation_score=context["correlation_score"],
        source_types=context["source_types"],
        alert_count=context["alert_count"],
        event_count=context["event_count"],
        evidence_items_count=len(context["evidence_records"]),
        evidence_provenance_records=context["provenance_records"],
        untrusted_telemetry_payloads=context["untrusted_payloads"],
        redacted_fields_count=context["redacted_fields_count"],
    )


@router.get("/evaluation", tags=["Phase 8 Experiments"])
def get_ai_analyst_evaluation(
    current_user: User = Depends(get_current_user),
):
    """
    Returns empirical Phase 8 evaluation metrics: System A vs. System B,
    unsupported claim rates, citation coverage, abstention precision/recall, and injection resistance.
    """
    results_path = (
        Path(__file__).resolve().parent.parent.parent.parent
        / "research"
        / "results"
        / "ai_analyst_v1.json"
    )
    if not results_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Phase 8 evaluation results not found. Run evaluate_ai_analyst_v1.py first.",
        )
    return json.loads(results_path.read_text(encoding="utf-8"))
