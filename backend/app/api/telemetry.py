from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user, require_roles
from app.database.session import get_db
from app.models import SOURCE_TYPE_STATUS, TelemetrySourceType, User
from app.schemas.event import ZeekReplayRequest, ZeekReplayResponse
from app.services.zeek_service import ingest_zeek_telemetry


router = APIRouter(prefix="/telemetry", tags=["telemetry"])


@router.get("/sources")
def list_telemetry_sources(_: User = Depends(get_current_user)) -> dict[str, Any]:
    """Returns official multi-source classification and implementation status."""
    return {
        "sources": [s.value for s in TelemetrySourceType],
        "status_map": SOURCE_TYPE_STATUS,
        "active_sources": [k for k, v in SOURCE_TYPE_STATUS.items() if v == "IMPLEMENTED"],
        "planned_sources": [k for k, v in SOURCE_TYPE_STATUS.items() if "PLANNED" in v],
    }


@router.post("/zeek/replay", response_model=ZeekReplayResponse, status_code=status.HTTP_201_CREATED)
def replay_zeek_telemetry(
    payload: ZeekReplayRequest,
    user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Replays Zeek network telemetry (conn, http, or dns) with performance benchmarking."""
    if not payload.raw_content or not payload.raw_content.strip():
        raise HTTPException(status_code=400, detail="No Zeek raw content provided for replay")

    return ingest_zeek_telemetry(
        db,
        content=payload.raw_content,
        log_type=payload.log_type,
        mode=payload.mode or "REPLAY",
        file_name=f"zeek_replay_{payload.log_type or 'auto'}.log",
        user_id=user.id,
    )


@router.post("/zeek/upload", response_model=ZeekReplayResponse, status_code=status.HTTP_201_CREATED)
async def upload_zeek_log(
    file: UploadFile = File(...),
    log_type: str | None = Query(None, description="conn, http, dns, or auto"),
    mode: str = Query("REPLAY", pattern="^(LIVE|REPLAY|SIMULATED)$"),
    user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Uploads a Zeek TSV or JSON log file for ingestion and normalization."""
    content_bytes = await file.read()
    content_str = content_bytes.decode("utf-8", errors="replace")

    return ingest_zeek_telemetry(
        db,
        content=content_str,
        log_type=log_type,
        mode=mode,
        file_name=file.filename or "zeek.log",
        user_id=user.id,
    )
