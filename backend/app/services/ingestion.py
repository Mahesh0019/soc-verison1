import json
import os
from typing import Any

from fastapi import HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import NormalizedEvent, RawLog
from app.parsers import normalize_object, parse_content, sanitize_text
from app.rules import evaluate_rules_for_events


settings = get_settings()


def detect_source_type(file_name: str | None, fallback: str = "text") -> str:
    extension = os.path.splitext(file_name or "")[1].lower()
    if extension == ".json":
        return "json"
    if extension == ".csv":
        return "csv"
    if extension in {".txt", ".log"}:
        return "text"
    return fallback


async def validate_upload(file: UploadFile) -> bytes:
    extension = os.path.splitext(file.filename or "")[1].lower()
    if extension not in settings.allowed_upload_extensions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type. Allowed: {', '.join(sorted(settings.allowed_upload_extensions))}",
        )
    content = await file.read()
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File exceeds the configured size limit")
    return content


def ingest_upload(db: Session, *, user_id: int | None, file_name: str, content: bytes) -> dict[str, Any]:
    source_type = detect_source_type(file_name)
    text = content.decode("utf-8", errors="replace")
    return ingest_text(db, source_type=source_type, content=text, file_name=file_name, user_id=user_id)


def ingest_api_payload(db: Session, *, source_type: str, events: list[dict[str, Any]], raw_lines: list[str], user_id: int | None) -> dict[str, Any]:
    normalized: list[dict[str, Any]] = []
    errors: list[str] = []
    raw_parts: list[str] = []
    for item in events:
        raw = json.dumps(item, default=str)
        raw_parts.append(raw)
        normalized.append(normalize_object(item, raw))
    if raw_lines:
        raw_text = "\n".join(raw_lines)
        raw_parts.append(raw_text)
        parsed, parse_errors = parse_content(source_type or "text", raw_text)
        normalized.extend(parsed)
        errors.extend(parse_errors)
    if not normalized:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No events or raw lines were provided")
    return persist_events(db, source_type=source_type or "api", content="\n".join(raw_parts), file_name=None, user_id=user_id, normalized=normalized, errors=errors)


def ingest_text(db: Session, *, source_type: str, content: str, file_name: str | None, user_id: int | None) -> dict[str, Any]:
    safe_content = sanitize_text(content)
    normalized, errors = parse_content(source_type, safe_content)
    return persist_events(db, source_type=source_type, content=safe_content, file_name=file_name, user_id=user_id, normalized=normalized, errors=errors)


def persist_events(
    db: Session,
    *,
    source_type: str,
    content: str,
    file_name: str | None,
    user_id: int | None,
    normalized: list[dict[str, Any]],
    errors: list[str],
) -> dict[str, Any]:
    raw_log = RawLog(
        source_type=source_type[:80],
        original_content=content[: settings.max_upload_bytes],
        file_name=file_name,
        uploaded_by=user_id,
    )
    db.add(raw_log)
    db.flush()

    events: list[NormalizedEvent] = []
    for item in normalized:
        event = NormalizedEvent(raw_log_id=raw_log.id, **item)
        db.add(event)
        events.append(event)
    db.flush()
    alert_count = evaluate_rules_for_events(db, events)
    db.commit()
    preview = events[:10]
    return {
        "raw_log_id": raw_log.id,
        "parsed_count": len(events),
        "alert_count": alert_count,
        "errors": errors[:100],
        "preview": preview,
    }

