from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth.dependencies import require_roles
from app.database.session import get_db
from app.models import User
from app.services import clear_demo_data, seed_demo_data


router = APIRouter(prefix="/demo", tags=["demo"])


@router.post("/seed")
def seed(_: User = Depends(require_roles("admin")), db: Session = Depends(get_db)) -> dict:
    result = seed_demo_data(db)
    return {"message": "Demo data seeded", **result}


@router.delete("/clear")
def clear(_: User = Depends(require_roles("admin")), db: Session = Depends(get_db)) -> dict:
    result = clear_demo_data(db)
    return {"message": "Demo data cleared", "deleted": result}

