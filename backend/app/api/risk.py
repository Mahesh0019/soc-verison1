"""
backend/app/api/risk.py

Risk & Triage API Endpoints
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.database.session import get_db
from app.models import Alert, Incident, RiskAssessment, User
from app.schemas.risk import RiskAssessmentOut, RiskSummaryOut
from app.services.risk_service import evaluate_alert_risk, evaluate_incident_risk, get_risk_summary

router = APIRouter(prefix="/risk", tags=["risk"])


@router.get("/summary", response_model=RiskSummaryOut)
def get_risk_overview(
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    return get_risk_summary(db)


@router.get("/alert/{alert_id}", response_model=RiskAssessmentOut)
def get_alert_risk(
    alert_id: int,
    asset_criticality: str = "MEDIUM",
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> RiskAssessment:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    assessment = evaluate_alert_risk(db, alert, asset_criticality=asset_criticality)
    db.commit()
    return assessment


@router.get("/incident/{incident_id}", response_model=RiskAssessmentOut)
def get_incident_risk(
    incident_id: int,
    asset_criticality: str = "HIGH",
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> RiskAssessment:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    assessment = evaluate_incident_risk(db, incident, asset_criticality=asset_criticality)
    db.commit()
    return assessment
