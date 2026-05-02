from fastapi import APIRouter, Depends, File, UploadFile, status
from sqlalchemy.orm import Session

from app.auth.dependencies import require_roles
from app.database.session import get_db
from app.models import User
from app.schemas import IngestRequest, IngestResponse
from app.services import ingest_api_payload, ingest_upload, validate_upload


router = APIRouter(prefix="/logs", tags=["logs"])


@router.post("/upload", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
async def upload_logs(
    file: UploadFile = File(...),
    user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
) -> dict:
    content = await validate_upload(file)
    return ingest_upload(db, user_id=user.id, file_name=file.filename or "upload.log", content=content)


@router.post("/ingest", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
def ingest_logs(
    payload: IngestRequest,
    user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
) -> dict:
    return ingest_api_payload(db, source_type=payload.source_type, events=payload.events, raw_lines=payload.raw_lines, user_id=user.id)

