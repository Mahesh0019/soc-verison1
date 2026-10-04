"""
backend/app/api/incidents.py

Incident Management API Endpoints
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, joinedload

from app.api.utils import apply_keyword_search, apply_sort, paginate
from app.auth.dependencies import get_current_user, require_roles
from app.database.session import get_db
from app.models import Alert, AuditLog, Incident, IncidentAlert, User
from app.schemas import Page
from app.schemas.alert import AlertOut
from app.schemas.incident import IncidentDetail, IncidentOut, IncidentStatusUpdate

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=Page[IncidentOut])
def list_incidents(
    q: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source_ip: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    sort_by: Optional[str] = "last_seen",
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    query = db.query(Incident)
    query = apply_keyword_search(query, Incident, q, ["incident_number", "title", "description", "source_ip", "affected_user"])
    if severity:
        query = query.filter(Incident.severity == severity)
    if status:
        query = query.filter(Incident.status == status)
    if source_ip:
        query = query.filter(Incident.source_ip == source_ip)

    query = apply_sort(query, Incident, sort_by, sort_order, {"last_seen", "first_seen", "severity", "status", "created_at"}, "last_seen")
    items, total = paginate(query, page, page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(
    incident_id: int,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    incident = (
        db.query(Incident)
        .options(joinedload(Incident.alerts).joinedload(IncidentAlert.alert))
        .filter(Incident.id == incident_id)
        .first()
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    alerts = [link.alert for link in incident.alerts if link.alert]
    data = IncidentOut.model_validate(incident).model_dump()
    data["alerts"] = [AlertOut.model_validate(a) for a in alerts]
    return data


@router.patch("/{incident_id}/status", response_model=IncidentOut)
def update_incident_status(
    incident_id: int,
    payload: IncidentStatusUpdate,
    user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
) -> Incident:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    old_status = incident.status
    incident.status = payload.status

    db.add(
        AuditLog(
            user_id=user.id,
            action="UPDATE_INCIDENT_STATUS",
            resource_type="Incident",
            resource_id=str(incident.id),
            details_json={"old_status": old_status, "new_status": payload.status},
        )
    )
    db.commit()
    db.refresh(incident)
    return incident
