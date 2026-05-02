from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.database.session import get_db
from app.models import Alert, NormalizedEvent, User
from app.schemas import DashboardSummary
from app.schemas.alert import AlertOut


router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def summary(_: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    since = datetime.now(UTC) - timedelta(hours=24)
    total_events = db.query(func.count(NormalizedEvent.id)).scalar() or 0
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    open_critical = db.query(func.count(Alert.id)).filter(Alert.status.in_(["open", "investigating"]), Alert.severity == "critical").scalar() or 0

    recent_events = db.query(NormalizedEvent).filter(NormalizedEvent.timestamp >= since).all()

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "open_critical_alerts": open_critical,
        "events_over_time": bucket_events(recent_events),
        "alerts_by_severity": grouped(db, Alert, "severity"),
        "top_source_ips": grouped(db, NormalizedEvent, "source_ip", limit=8),
        "top_usernames": grouped(db, NormalizedEvent, "username", limit=8),
        "top_event_types": grouped(db, NormalizedEvent, "event_type", limit=8),
        "event_category_distribution": grouped(db, NormalizedEvent, "event_category"),
        "alert_status_distribution": grouped(db, Alert, "status"),
        "login_trends": bucket_logins(recent_events),
        "recent_alerts": [AlertOut.model_validate(alert) for alert in db.query(Alert).order_by(Alert.last_seen.desc()).limit(8).all()],
    }


def grouped(db: Session, model, column_name: str, limit: int = 10) -> list[dict]:
    column = getattr(model, column_name)
    query = db.query(column, func.count(model.id)).filter(column.is_not(None)).group_by(column).order_by(func.count(model.id).desc())
    return [{"label": str(label), "value": count} for label, count in query.limit(limit).all()]


def bucket_events(events: list[NormalizedEvent]) -> list[dict]:
    buckets: dict[str, int] = {}
    for event in events:
        label = aware(event.timestamp).strftime("%H:00")
        buckets[label] = buckets.get(label, 0) + 1
    return [{"label": label, "value": buckets[label]} for label in sorted(buckets)]


def bucket_logins(events: list[NormalizedEvent]) -> list[dict]:
    buckets: dict[str, dict[str, int]] = {}
    for event in events:
        if event.event_category != "authentication":
            continue
        label = aware(event.timestamp).strftime("%H:00")
        buckets.setdefault(label, {"failed": 0, "successful": 0})
        if event.event_type == "failed_login":
            buckets[label]["failed"] += 1
        if event.event_type == "successful_login":
            buckets[label]["successful"] += 1
    return [{"label": label, **buckets[label]} for label in sorted(buckets)]


def aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)
