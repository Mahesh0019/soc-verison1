from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, joinedload

from app.api.utils import apply_date_range, apply_keyword_search, apply_sort, paginate
from app.auth.dependencies import get_current_user, require_roles
from app.database.session import get_db
from app.models import Alert, AlertEvent, AlertNote, User
from app.schemas import AlertDetail, AlertNoteCreate, AlertNoteOut, AlertOut, AlertStatusUpdate, Page


router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=Page[AlertOut])
def list_alerts(
    q: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    severity: str | None = None,
    status: str | None = None,
    source_ip: str | None = None,
    username: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    sort_by: str | None = "last_seen",
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    query = db.query(Alert)
    query = apply_keyword_search(query, Alert, q, ["title", "description", "source_ip", "affected_user", "severity", "status"])
    query = apply_date_range(query, Alert.created_at, date_from, date_to)
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if source_ip:
        query = query.filter(Alert.source_ip == source_ip)
    if username:
        query = query.filter(Alert.affected_user == username)
    query = apply_sort(query, Alert, sort_by, sort_order, {"last_seen", "first_seen", "severity", "status", "created_at"}, "last_seen")
    items, total = paginate(query, page, page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    alert = (
        db.query(Alert)
        .options(joinedload(Alert.events).joinedload(AlertEvent.event), joinedload(Alert.notes).joinedload(AlertNote.user))
        .filter(Alert.id == alert_id)
        .first()
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return serialize_alert_detail(alert)


@router.patch("/{alert_id}/status", response_model=AlertOut)
def update_status(
    alert_id: int,
    payload: AlertStatusUpdate,
    _: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
) -> Alert:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = payload.status
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/{alert_id}/notes", response_model=AlertNoteOut, status_code=201)
def add_note(
    alert_id: int,
    payload: AlertNoteCreate,
    user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
) -> AlertNote:
    if not db.get(Alert, alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    note = AlertNote(alert_id=alert_id, user_id=user.id, note=payload.note)
    db.add(note)
    db.commit()
    db.refresh(note)
    return note


def serialize_alert_detail(alert: Alert) -> dict:
    base = AlertOut.model_validate(alert).model_dump()
    base["related_events"] = [link.event for link in sorted(alert.events, key=lambda item: item.event.timestamp, reverse=True)]
    base["notes"] = sorted(alert.notes, key=lambda item: item.created_at)
    return base

