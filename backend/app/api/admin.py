from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.utils import apply_keyword_search, paginate
from app.auth.dependencies import require_roles
from app.auth.security import hash_password
from app.database.session import get_db
from app.models import Alert, AuditLog, DetectionRule, NormalizedEvent, RawLog, ThreatIndicator, User
from app.schemas import AdminPasswordResetRequest, Page, UserCreate, UserOut, UserUpdate


router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/stats")
def stats(_: User = Depends(require_roles("admin")), db: Session = Depends(get_db)) -> dict:
    return {
        "users": db.query(func.count(User.id)).scalar() or 0,
        "events": db.query(func.count(NormalizedEvent.id)).scalar() or 0,
        "raw_logs": db.query(func.count(RawLog.id)).scalar() or 0,
        "alerts": db.query(func.count(Alert.id)).scalar() or 0,
        "rules": db.query(func.count(DetectionRule.id)).scalar() or 0,
        "threat_indicators": db.query(func.count(ThreatIndicator.id)).scalar() or 0,
    }


@router.get("/users", response_model=Page[UserOut])
def list_users(
    q: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    _: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
) -> dict:
    query = db.query(User).order_by(User.created_at.desc())
    query = apply_keyword_search(query, User, q, ["username", "email", "role"])
    items, total = paginate(query, page, page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate, _: User = Depends(require_roles("admin")), db: Session = Depends(get_db)) -> User:
    if db.query(User).filter((User.username == payload.username) | (User.email == payload.email)).first():
        raise HTTPException(status_code=409, detail="Username or email already exists")
    user = User(username=payload.username, email=payload.email, role=payload.role, password_hash=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(user_id: int, payload: UserUpdate, _: User = Depends(require_roles("admin")), db: Session = Depends(get_db)) -> User:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(user, key, value)
    db.commit()
    db.refresh(user)
    return user


@router.post("/users/{user_id}/reset-password")
def admin_reset_password(
    user_id: int,
    payload: AdminPasswordResetRequest,
    current_admin: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Allows an administrator to reset/rotate another user's password securely."""
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    target.password_hash = hash_password(payload.new_password)
    try:
        audit = AuditLog(
            action="ADMIN_PASSWORD_RESET",
            resource_type="USER",
            resource_id=str(target.id),
            user_id=current_admin.id,
            details_json={"target_username": target.username, "reset_by": current_admin.username},
        )
        db.add(audit)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reset password",
        )
    return {"message": f"Password for user {target.username} reset successfully"}


@router.get("/audit-logs")
def list_audit_logs(
    action: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    _: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
) -> dict:
    """Allows administrators to inspect and query the system audit trail."""
    query = db.query(AuditLog).order_by(AuditLog.timestamp.desc())
    if action:
        query = query.filter(AuditLog.action == action)
    items, total = paginate(query, page, page_size)
    return {
        "items": [
            {
                "id": log.id,
                "user_id": log.user_id,
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "details_json": log.details_json,
                "ip_address": log.ip_address,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            }
            for log in items
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


