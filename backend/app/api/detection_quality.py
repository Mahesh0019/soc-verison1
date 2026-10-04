"""
backend/app/api/detection_quality.py

Detection Quality API Endpoints
Provides explainable detection-quality factors, scores, and distribution summaries.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.utils import paginate
from app.auth.dependencies import get_current_user
from app.database.session import get_db
from app.models import Alert, DetectionQuality, Incident, User
from app.schemas import Page
from app.schemas.detection_quality import DetectionQualityOut, DetectionQualitySummaryOut
from app.services.detection_quality_service import (
    evaluate_alert_quality,
    evaluate_incident_quality,
    get_detection_quality_summary,
)

router = APIRouter(prefix="/detection-quality", tags=["detection-quality"])


@router.get("", response_model=Page[DetectionQualityOut])
def list_detection_quality(
    min_quality: Optional[float] = None,
    max_quality: Optional[float] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    query = db.query(DetectionQuality)
    if min_quality is not None:
        query = query.filter(DetectionQuality.overall_quality >= min_quality)
    if max_quality is not None:
        query = query.filter(DetectionQuality.overall_quality <= max_quality)

    query = query.order_by(DetectionQuality.overall_quality.desc())
    items, total = paginate(query, page, page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/summary", response_model=DetectionQualitySummaryOut)
def get_quality_summary(
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    return get_detection_quality_summary(db)


@router.get("/alert/{alert_id}", response_model=DetectionQualityOut)
def get_alert_quality(
    alert_id: int,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DetectionQuality:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    dq = evaluate_alert_quality(db, alert)
    db.commit()
    return dq


@router.get("/incident/{incident_id}", response_model=DetectionQualityOut)
def get_incident_quality(
    incident_id: int,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DetectionQuality:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    dq = evaluate_incident_quality(db, incident)
    db.commit()
    return dq
