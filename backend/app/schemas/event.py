from datetime import datetime

from pydantic import BaseModel, ConfigDict


class EventBase(BaseModel):
    timestamp: datetime
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    event_type: str
    event_category: str
    severity: str
    message: str
    raw_log: str | None = None
    user_agent: str | None = None
    request_path: str | None = None
    http_method: str | None = None
    status_code: int | None = None
    geo_country: str | None = None


class EventCreate(EventBase):
    raw_log_id: int | None = None


class EventOut(EventBase):
    id: int
    raw_log_id: int | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IngestRequest(BaseModel):
    source_type: str = "api"
    events: list[dict] = []
    raw_lines: list[str] = []


class IngestResponse(BaseModel):
    raw_log_id: int
    parsed_count: int
    alert_count: int
    errors: list[str]
    preview: list[EventOut]

