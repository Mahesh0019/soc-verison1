from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.utils import apply_keyword_search, apply_sort, paginate
from app.auth.dependencies import get_current_user, require_roles
from app.database.session import get_db
from app.models import DetectionRule, User
from app.schemas import Page, RuleCreate, RuleOut, RuleToggle


router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("", response_model=Page[RuleOut])
def list_rules(
    q: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: str | None = None,
    enabled: bool | None = None,
    sort_by: str | None = "name",
    sort_order: str = Query("asc", pattern="^(asc|desc)$"),
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    query = db.query(DetectionRule)
    query = apply_keyword_search(query, DetectionRule, q, ["name", "description", "severity"])
    if severity:
        query = query.filter(DetectionRule.severity == severity)
    if enabled is not None:
        query = query.filter(DetectionRule.enabled.is_(enabled))
    query = apply_sort(query, DetectionRule, sort_by, sort_order, {"name", "severity", "enabled", "updated_at"}, "name")
    items, total = paginate(query, page, page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.post("", response_model=RuleOut, status_code=status.HTTP_201_CREATED)
def create_rule(payload: RuleCreate, _: User = Depends(require_roles("admin")), db: Session = Depends(get_db)) -> DetectionRule:
    if db.query(DetectionRule).filter(DetectionRule.name == payload.name).first():
        raise HTTPException(status_code=409, detail="Rule name already exists")
    rule = DetectionRule(**payload.model_dump())
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@router.patch("/{rule_id}/toggle", response_model=RuleOut)
def toggle_rule(
    rule_id: int,
    payload: RuleToggle,
    _: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
) -> DetectionRule:
    rule = db.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.enabled = payload.enabled
    db.commit()
    db.refresh(rule)
    return rule

