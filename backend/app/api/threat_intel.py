from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.utils import apply_keyword_search, apply_sort, paginate
from app.auth.dependencies import get_current_user, require_roles
from app.database.session import get_db
from app.models import ThreatIndicator, User
from app.schemas import Message, Page, ThreatIndicatorCreate, ThreatIndicatorOut


router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


@router.get("", response_model=Page[ThreatIndicatorOut])
def list_indicators(
    q: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    type: str | None = None,
    severity: str | None = None,
    sort_by: str | None = "updated_at",
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    query = db.query(ThreatIndicator)
    query = apply_keyword_search(query, ThreatIndicator, q, ["type", "value", "description", "severity"])
    if type:
        query = query.filter(ThreatIndicator.type == type)
    if severity:
        query = query.filter(ThreatIndicator.severity == severity)
    query = apply_sort(query, ThreatIndicator, sort_by, sort_order, {"type", "value", "severity", "updated_at"}, "updated_at")
    items, total = paginate(query, page, page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.post("", response_model=ThreatIndicatorOut, status_code=status.HTTP_201_CREATED)
def create_indicator(
    payload: ThreatIndicatorCreate,
    _: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
) -> ThreatIndicator:
    existing = db.query(ThreatIndicator).filter(ThreatIndicator.type == payload.type, ThreatIndicator.value == payload.value).first()
    if existing:
        raise HTTPException(status_code=409, detail="Indicator already exists")
    indicator = ThreatIndicator(**payload.model_dump())
    db.add(indicator)
    db.commit()
    db.refresh(indicator)
    return indicator


@router.patch("/{indicator_id}", response_model=ThreatIndicatorOut)
def update_indicator(
    indicator_id: int,
    payload: ThreatIndicatorCreate,
    _: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
) -> ThreatIndicator:
    indicator = db.get(ThreatIndicator, indicator_id)
    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")
    for key, value in payload.model_dump().items():
        setattr(indicator, key, value)
    db.commit()
    db.refresh(indicator)
    return indicator


@router.delete("/{indicator_id}", response_model=Message)
def delete_indicator(
    indicator_id: int,
    _: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
) -> dict:
    indicator = db.get(ThreatIndicator, indicator_id)
    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")
    db.delete(indicator)
    db.commit()
    return {"message": "Indicator deleted"}

