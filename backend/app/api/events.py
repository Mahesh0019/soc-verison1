from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.utils import apply_date_range, apply_keyword_search, apply_sort, paginate
from app.auth.dependencies import get_current_user
from app.database.session import get_db
from app.models import NormalizedEvent, User
from app.schemas import EventOut, Page


router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=Page[EventOut])
def list_events(
    q: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    severity: str | None = None,
    event_type: str | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    source_port: int | None = None,
    destination_port: int | None = None,
    protocol: str | None = None,
    dns_query: str | None = None,
    raw_reference: str | None = None,
    username: str | None = None,
    hostname: str | None = None,
    source_type: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    sort_by: str | None = "timestamp",
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    query = db.query(NormalizedEvent)
    query = apply_keyword_search(
        query,
        NormalizedEvent,
        q,
        [
            "message",
            "source_ip",
            "destination_ip",
            "username",
            "hostname",
            "event_type",
            "source_type",
            "dns_query",
            "raw_reference",
            "event_id",
            "request_path",
            "raw_log",
        ],
    )
    query = apply_date_range(query, NormalizedEvent.timestamp, date_from, date_to)
    if severity:
        query = query.filter(NormalizedEvent.severity == severity)
    if event_type:
        query = query.filter(NormalizedEvent.event_type == event_type)
    if source_type:
        query = query.filter(NormalizedEvent.source_type == source_type.upper())
    if source_ip:
        query = query.filter(NormalizedEvent.source_ip == source_ip)
    if destination_ip:
        query = query.filter(NormalizedEvent.destination_ip == destination_ip)
    if source_port is not None:
        query = query.filter(NormalizedEvent.source_port == source_port)
    if destination_port is not None:
        query = query.filter(NormalizedEvent.destination_port == destination_port)
    if protocol:
        query = query.filter(NormalizedEvent.protocol == protocol.lower())
    if dns_query:
        query = query.filter(NormalizedEvent.dns_query.ilike(f"%{dns_query}%"))
    if raw_reference:
        query = query.filter(NormalizedEvent.raw_reference == raw_reference)
    if username:
        query = query.filter(NormalizedEvent.username == username)
    if hostname:
        query = query.filter(NormalizedEvent.hostname == hostname)
    query = apply_sort(
        query,
        NormalizedEvent,
        sort_by,
        sort_order,
        {"timestamp", "severity", "event_type", "source_type", "source_ip", "destination_ip", "destination_port", "username", "created_at"},
        "timestamp",
    )
    items, total = paginate(query, page, page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/{event_id}", response_model=EventOut)
def get_event(event_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)) -> NormalizedEvent:
    event = db.get(NormalizedEvent, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event

