"""
backend/app/api/incidents.py

Incident Management API Endpoints
"""

import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, joinedload

from app.api.utils import apply_keyword_search, apply_sort, paginate
from app.auth.dependencies import get_current_user, require_roles
from app.database.session import get_db
from app.models import Alert, AlertEvent, AuditLog, Evidence, Incident, IncidentAlert, NormalizedEvent, User
from app.schemas import Page
from app.schemas.alert import AlertOut
from app.schemas.incident import (
    CrossSourceCorrelationRequest,
    CrossSourceCorrelationResult,
    IncidentDetail,
    IncidentGraphData,
    IncidentOut,
    IncidentStatusUpdate,
    IncidentTimelineItem,
    UnifiedIncidentOut,
)
from app.services.correlation_service import (
    DEFAULT_WINDOW_SECONDS,
    build_incident_graph,
    build_incident_timeline,
    run_cross_source_correlation,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.post("/correlate", response_model=CrossSourceCorrelationResult)
def trigger_correlation(
    payload: CrossSourceCorrelationRequest,
    _: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
) -> CrossSourceCorrelationResult:
    start_t = time.perf_counter()
    incidents = run_cross_source_correlation(
        db=db,
        alert_ids=payload.alert_ids,
        window_seconds=payload.window_seconds or DEFAULT_WINDOW_SECONDS,
    )
    db.commit()
    elapsed_ms = (time.perf_counter() - start_t) * 1000.0

    return CrossSourceCorrelationResult(
        correlated_incidents_count=len(incidents),
        incidents=[IncidentOut.model_validate(inc) for inc in incidents],
        execution_time_ms=round(elapsed_ms, 2),
        applied_window_seconds=payload.window_seconds or DEFAULT_WINDOW_SECONDS,
        matched_rules=["CORR-001", "CORR-002", "CORR-003", "CORR-004"],
    )


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


@router.get("/{incident_id}/unified", response_model=UnifiedIncidentOut)
def get_unified_incident(
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
    alert_ids = [a.id for a in alerts]

    events = (
        db.query(NormalizedEvent)
        .join(AlertEvent, AlertEvent.event_id == NormalizedEvent.id)
        .filter(AlertEvent.alert_id.in_(alert_ids))
        .all()
    ) if alert_ids else []

    evidence_items = (
        db.query(Evidence)
        .filter(Evidence.incident_id == incident.id)
        .all()
    )

    timeline = incident.timeline_json or build_incident_timeline(events, alerts)
    graph = incident.graph_json or build_incident_graph(incident.id, incident.incident_number, events, alerts)

    sources = incident.source_types_json or list({e.source_type.upper() for e in events if e.source_type})
    if not sources:
        sources = ["WEB"]

    return {
        "incident_id": incident.id,
        "incident_number": incident.incident_number,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "risk_score": incident.risk_score or 50.0,
        "created_at": incident.created_at,
        "updated_at": incident.updated_at,
        "status": incident.status,
        "primary_entity": incident.primary_entity or incident.source_ip,
        "related_entities": incident.related_entities_json or [],
        "source_types": sources,
        "alerts": [AlertOut.model_validate(a) for a in alerts],
        "events": [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "source_type": e.source_type,
                "event_type": e.event_type,
                "severity": e.severity,
                "source_ip": e.source_ip,
                "destination_ip": e.destination_ip,
                "hostname": e.hostname,
                "process": e.process,
                "dns_query": e.dns_query,
                "message": e.message,
            }
            for e in events
        ],
        "evidence": [
            {
                "id": ev.id,
                "evidence_type": ev.evidence_type,
                "title": ev.title,
                "description": ev.description,
                "data_json": ev.data_json,
                "sha256_hash": ev.sha256_hash,
                "confidence": ev.confidence,
            }
            for ev in evidence_items
        ],
        "correlation_score": incident.correlation_score,
        "confidence": incident.confidence or "MEDIUM",
        "attack_chain_status": incident.attack_chain_status or "CORRELATED ACTIVITY",
        "timeline": timeline,
        "graph": graph,
    }


@router.get("/{incident_id}/graph", response_model=IncidentGraphData)
def get_incident_graph(
    incident_id: int,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> IncidentGraphData:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if incident.graph_json and incident.graph_json.get("nodes"):
        return IncidentGraphData(**incident.graph_json)

    # Reconstruct on the fly if needed
    alerts = (
        db.query(Alert)
        .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
        .filter(IncidentAlert.incident_id == incident.id)
        .all()
    )
    alert_ids = [a.id for a in alerts]
    events = (
        db.query(NormalizedEvent)
        .join(AlertEvent, AlertEvent.event_id == NormalizedEvent.id)
        .filter(AlertEvent.alert_id.in_(alert_ids))
        .all()
    ) if alert_ids else []

    graph_data = build_incident_graph(incident.id, incident.incident_number, events, alerts)
    return IncidentGraphData(**graph_data)


@router.get("/{incident_id}/timeline", response_model=list[IncidentTimelineItem])
def get_incident_timeline(
    incident_id: int,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[IncidentTimelineItem]:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if incident.timeline_json:
        return [IncidentTimelineItem(**item) for item in incident.timeline_json]

    alerts = (
        db.query(Alert)
        .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
        .filter(IncidentAlert.incident_id == incident.id)
        .all()
    )
    alert_ids = [a.id for a in alerts]
    events = (
        db.query(NormalizedEvent)
        .join(AlertEvent, AlertEvent.event_id == NormalizedEvent.id)
        .filter(AlertEvent.alert_id.in_(alert_ids))
        .all()
    ) if alert_ids else []

    timeline = build_incident_timeline(events, alerts)
    return [IncidentTimelineItem(**item) for item in timeline]


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
