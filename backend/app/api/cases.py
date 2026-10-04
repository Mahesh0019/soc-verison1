"""
backend/app/api/cases.py

Case Management and Controlled Response API Endpoints
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session, joinedload

from app.api.utils import apply_keyword_search, apply_sort, paginate
from app.auth.dependencies import get_current_user, require_roles
from app.database.session import get_db
from app.models import Case, User
from app.schemas import Page
from app.schemas.case import (
    CaseCreate,
    CaseOut,
    CaseUpdate,
    ControlledResponseRequest,
    ControlledResponseResult,
)
from app.services.case_service import create_case, execute_controlled_response, update_case

router = APIRouter(prefix="/cases", tags=["cases"])


@router.get("", response_model=Page[CaseOut])
def list_cases(
    q: Optional[str] = None,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assigned_analyst_id: Optional[int] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    sort_by: Optional[str] = "updated_at",
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    query = db.query(Case).options(joinedload(Case.assigned_analyst))
    query = apply_keyword_search(query, Case, q, ["case_number", "title", "description", "status", "priority"])
    if status:
        query = query.filter(Case.status == status.upper())
    if priority:
        query = query.filter(Case.priority == priority.upper())
    if assigned_analyst_id is not None:
        query = query.filter(Case.assigned_analyst_id == assigned_analyst_id)

    query = apply_sort(query, Case, sort_by, sort_order, {"case_number", "status", "priority", "created_at", "updated_at"}, "updated_at")
    items, total = paginate(query, page, page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.post("", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
def create_new_case(
    payload: CaseCreate,
    user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
) -> Case:
    return create_case(
        db,
        title=payload.title,
        description=payload.description,
        priority=payload.priority,
        assigned_analyst_id=payload.assigned_analyst_id or user.id,
        alert_id=payload.alert_id,
        incident_id=payload.incident_id,
        user_id=user.id,
    )


@router.get("/{case_id}", response_model=CaseOut)
def get_case_detail(
    case_id: int,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Case:
    case = db.query(Case).options(joinedload(Case.assigned_analyst)).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.patch("/{case_id}", response_model=CaseOut)
def modify_case(
    case_id: int,
    payload: CaseUpdate,
    user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
) -> Case:
    case = update_case(
        db,
        case_id=case_id,
        status=payload.status,
        priority=payload.priority,
        assigned_analyst_id=payload.assigned_analyst_id,
        resolution_summary=payload.resolution_summary,
        user_id=user.id,
    )
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.post("/controlled-response", response_model=ControlledResponseResult)
def trigger_controlled_response(
    payload: ControlledResponseRequest,
    user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
) -> dict:
    if not payload.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Controlled response requires explicit analyst confirmation (confirm: true).",
        )

    return execute_controlled_response(
        db,
        user=user,
        action_type=payload.action_type,
        target_value=payload.target_value,
        case_id=payload.case_id,
        simulated=True,
        confirmation_notes=payload.confirmation_notes,
    )
