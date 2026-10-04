"""
backend/app/api/evidence.py

Evidence Query and Management Endpoints
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.utils import paginate
from app.auth.dependencies import get_current_user
from app.database.session import get_db
from app.models import Alert, Evidence, Incident, User
from app.schemas import Page
from app.schemas.evidence import EvidenceOut, EvidencePackageOut
from app.services.evidence_service import (
    build_evidence_package,
    build_incident_evidence_package,
    calculate_evidence_completeness,
)

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.get("", response_model=Page[EvidenceOut])
def list_evidence(
    alert_id: Optional[int] = None,
    incident_id: Optional[int] = None,
    evidence_type: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    query = db.query(Evidence)
    if alert_id is not None:
        query = query.filter(Evidence.alert_id == alert_id)
    if incident_id is not None:
        query = query.filter(Evidence.incident_id == incident_id)
    if evidence_type:
        query = query.filter(Evidence.evidence_type == evidence_type)

    query = query.order_by(Evidence.created_at.desc())
    items, total = paginate(query, page, page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/{evidence_id}", response_model=EvidenceOut)
def get_evidence_item(
    evidence_id: int,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Evidence:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence item not found")
    return item


@router.get("/alert/{alert_id}", response_model=EvidencePackageOut)
def get_alert_evidence_package(
    alert_id: int,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    items = build_evidence_package(db, alert)
    db.commit()
    completeness = calculate_evidence_completeness(items)

    return {
        "alert_id": alert.id,
        "incident_id": None,
        "completeness_score": completeness,
        "total_evidence_items": len(items),
        "items": items,
    }


@router.get("/incident/{incident_id}", response_model=EvidencePackageOut)
def get_incident_evidence_package(
    incident_id: int,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    items = build_incident_evidence_package(db, incident)
    db.commit()
    completeness = calculate_evidence_completeness(items)

    return {
        "alert_id": None,
        "incident_id": incident.id,
        "completeness_score": completeness,
        "total_evidence_items": len(items),
        "items": items,
    }
