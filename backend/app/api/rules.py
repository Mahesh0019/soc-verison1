from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.utils import apply_keyword_search, apply_sort, paginate
from app.auth.dependencies import get_current_user, require_roles
from app.database.session import get_db
from app.models import DetectionRule, RuleHealthRecord, User
from app.schemas import (
    Page,
    RuleCreate,
    RuleHealthOut,
    RuleHealthSummaryOut,
    RuleOut,
    RuleToggle,
    RuleUpdate,
)
from app.services.detection_quality_service import (
    evaluate_all_rules_health,
    evaluate_rule_health,
    get_all_latest_rule_health,
    get_latest_rule_health,
)


router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("", response_model=Page[RuleOut])
def list_rules(
    q: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: str | None = None,
    enabled: bool | None = None,
    status_filter: str | None = Query(None, alias="status"),
    category: str | None = None,
    sort_by: str | None = "name",
    sort_order: str = Query("asc", pattern="^(asc|desc)$"),
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    query = db.query(DetectionRule)
    query = apply_keyword_search(query, DetectionRule, q, ["name", "description", "severity", "category", "rule_id"])
    if severity:
        query = query.filter(DetectionRule.severity == severity)
    if enabled is not None:
        query = query.filter(DetectionRule.enabled.is_(enabled))
    if status_filter:
        query = query.filter(DetectionRule.status == status_filter)
    if category:
        query = query.filter(DetectionRule.category == category)

    query = apply_sort(query, DetectionRule, sort_by, sort_order, {"name", "severity", "enabled", "updated_at", "status", "category"}, "name")
    items, total = paginate(query, page, page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/health/summary")
def get_rules_health_summary(
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Returns persistent rule health scores and distribution across all rules."""
    records = get_all_latest_rule_health(db)
    valid_scores = [r.health_score for r in records if r.health_score is not None]
    avg_score = round(sum(valid_scores) / len(valid_scores), 1) if valid_scores else None

    tier_dist = {"EXCELLENT": 0, "HEALTHY": 0, "DEGRADED": 0, "UNHEALTHY": 0, "INSUFFICIENT_DATA": 0}
    for r in records:
        tier = r.health_tier or "INSUFFICIENT_DATA"
        tier_dist[tier] = tier_dist.get(tier, 0) + 1

    serialized_records = []
    for r in records:
        serialized_records.append({
            "id": r.id,
            "rule_id": r.rule_id,
            "rule_name": r.rule_name,
            "version": r.version,
            "dataset_target": r.dataset_target,
            "evaluated_at": r.evaluated_at.isoformat() if r.evaluated_at else None,
            "true_positives": r.true_positives,
            "false_positives": r.false_positives,
            "false_negatives": r.false_negatives,
            "true_negatives": r.true_negatives,
            "precision": r.precision,
            "recall": r.recall,
            "f1_score": r.f1_score,
            "false_positive_rate": r.false_positive_rate,
            "alert_volume": r.alert_volume,
            "detection_latency_ms": r.detection_latency_ms,
            "coverage_score": r.coverage_score,
            "confidence": r.confidence,
            "regression_status": r.regression_status,
            "health_score": r.health_score,
            "health_tier": r.health_tier,
            "details_json": r.details_json,
        })

    return {
        "total_rules": len(records),
        "evaluated_rules": len(valid_scores),
        "average_health_score": avg_score,
        "tier_distribution": tier_dist,
        "rule_records": serialized_records,
    }


@router.post("/health/evaluate-all")
def evaluate_all_rules_endpoint(
    dataset_target: str = "validation_suite",
    _: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Executes regression tests and recalculates health scores across all detection rules."""
    records = evaluate_all_rules_health(db, dataset_target=dataset_target)
    return {"message": f"Successfully evaluated {len(records)} rules", "evaluated_count": len(records)}


@router.post("", response_model=RuleOut, status_code=status.HTTP_201_CREATED)
def create_rule(payload: RuleCreate, _: User = Depends(require_roles("admin")), db: Session = Depends(get_db)) -> DetectionRule:
    if db.query(DetectionRule).filter(DetectionRule.name == payload.name).first():
        raise HTTPException(status_code=409, detail="Rule name already exists")
    if payload.rule_id and db.query(DetectionRule).filter(DetectionRule.rule_id == payload.rule_id).first():
        raise HTTPException(status_code=409, detail=f"Rule identifier {payload.rule_id} already exists")

    rule = DetectionRule(**payload.model_dump())
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@router.get("/{rule_id}", response_model=RuleOut)
def get_rule_detail(
    rule_id: int,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DetectionRule:
    rule = db.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.patch("/{rule_id}", response_model=RuleOut)
def update_rule(
    rule_id: int,
    payload: RuleUpdate,
    _: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
) -> DetectionRule:
    rule = db.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    update_dict = payload.model_dump(exclude_unset=True)
    for field, val in update_dict.items():
        setattr(rule, field, val)

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


@router.get("/{rule_id}/health")
def get_rule_health(
    rule_id: int,
    history_limit: int = Query(10, ge=1, le=50),
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rule = db.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    latest = get_latest_rule_health(db, rule_id)
    history = (
        db.query(RuleHealthRecord)
        .filter(RuleHealthRecord.rule_id == rule_id)
        .order_by(RuleHealthRecord.evaluated_at.desc())
        .limit(history_limit)
        .all()
    )

    def serialize_rec(r: RuleHealthRecord) -> dict[str, Any]:
        return {
            "id": r.id,
            "rule_id": r.rule_id,
            "rule_name": r.rule_name,
            "version": r.version,
            "dataset_target": r.dataset_target,
            "evaluated_at": r.evaluated_at.isoformat() if r.evaluated_at else None,
            "true_positives": r.true_positives,
            "false_positives": r.false_positives,
            "false_negatives": r.false_negatives,
            "true_negatives": r.true_negatives,
            "precision": r.precision,
            "recall": r.recall,
            "f1_score": r.f1_score,
            "false_positive_rate": r.false_positive_rate,
            "alert_volume": r.alert_volume,
            "detection_latency_ms": r.detection_latency_ms,
            "coverage_score": r.coverage_score,
            "confidence": r.confidence,
            "regression_status": r.regression_status,
            "health_score": r.health_score,
            "health_tier": r.health_tier,
            "details_json": r.details_json,
        }

    return {
        "rule_id": rule.id,
        "rule_name": rule.name,
        "rule_version": rule.version,
        "rule_status": rule.status,
        "latest": serialize_rec(latest) if latest else None,
        "history": [serialize_rec(h) for h in history],
    }


@router.post("/{rule_id}/evaluate")
def evaluate_rule_endpoint(
    rule_id: int,
    dataset_target: str = "validation_suite",
    _: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rule = db.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    record = evaluate_rule_health(db, rule, dataset_target=dataset_target, persist=True)
    return {
        "message": f"Rule {rule.name} evaluated successfully",
        "health_score": record.health_score,
        "health_tier": record.health_tier,
        "evaluated_at": record.evaluated_at.isoformat() if record.evaluated_at else None,
    }
