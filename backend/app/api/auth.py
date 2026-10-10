import time
from collections import defaultdict
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.auth.security import create_access_token, hash_password, verify_password
from app.database.session import get_db
from app.models import AuditLog, User
from app.schemas import LoginRequest, PasswordChangeRequest, Token, UserCreate, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])

# In-memory sliding-window failed login attempt tracker: key -> list of timestamps
_FAILED_ATTEMPTS: dict[str, list[float]] = defaultdict(list)
_MAX_FAILED_ATTEMPTS = 15
_LOCKOUT_WINDOW_SECONDS = 300.0


def _check_rate_limit(key: str) -> None:
    now = time.time()
    # Prune old timestamps
    attempts = [t for t in _FAILED_ATTEMPTS[key] if now - t < _LOCKOUT_WINDOW_SECONDS]
    _FAILED_ATTEMPTS[key] = attempts
    if len(attempts) >= _MAX_FAILED_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Account temporarily locked for 5 minutes.",
        )


def _record_failed_attempt(key: str) -> None:
    _FAILED_ATTEMPTS[key].append(time.time())


def _clear_failed_attempts(key: str) -> None:
    _FAILED_ATTEMPTS.pop(key, None)


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)) -> User:
    existing = db.query(User).filter((User.username == payload.username) | (User.email == payload.email)).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username or email already exists")
    role = payload.role if db.query(User).count() == 0 else "viewer"
    user = User(username=payload.username, email=payload.email, role=role, password_hash=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)

    audit = AuditLog(
        action="USER_REGISTERED",
        resource_type="USER",
        resource_id=str(user.id),
        details_json={"username": user.username, "role": user.role},
    )
    db.add(audit)
    db.commit()

    return user


@router.post("/login", response_model=Token)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"{client_ip}:{payload.username}"

    # Check brute-force rate limit
    _check_rate_limit(rate_key)

    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        _record_failed_attempt(rate_key)

        try:
            audit = AuditLog(
                action="AUTH_LOGIN_FAILED",
                resource_type="USER",
                resource_id=payload.username,
                details_json={"client_ip": client_ip, "username": payload.username},
            )
            db.add(audit)
            db.commit()
        except Exception:
            db.rollback()

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    # Clear lockout on valid credentials
    _clear_failed_attempts(rate_key)

    try:
        audit = AuditLog(
            action="AUTH_LOGIN_SUCCESS",
            resource_type="USER",
            resource_id=str(user.id),
            user_id=user.id,
            details_json={"client_ip": client_ip, "username": user.username, "role": user.role},
        )
        db.add(audit)
        db.commit()
    except Exception:
        db.rollback()

    token = create_access_token(user.username, {"role": user.role})
    return {"access_token": token, "token_type": "bearer", "user": user}


@router.post("/change-password")
def change_password(
    payload: PasswordChangeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Allows an authenticated user to change their password securely."""
    if not verify_password(payload.current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password verification failed",
        )
    current_user.password_hash = hash_password(payload.new_password)
    try:
        audit = AuditLog(
            action="AUTH_PASSWORD_CHANGED",
            resource_type="USER",
            resource_id=str(current_user.id),
            user_id=current_user.id,
            details_json={"username": current_user.username},
        )
        db.add(audit)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist password change",
        )
    return {"message": "Password updated successfully"}


