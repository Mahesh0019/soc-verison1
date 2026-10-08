from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class EventBase(BaseModel):
    event_id: Optional[str] = None
    timestamp: datetime

    # Multi-Source Classification
    source_type: str = "WEB"
    source_name: Optional[str] = None

    # Network Telemetry
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    connection_state: Optional[str] = None
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None
    response_time_ms: Optional[float] = None

    # DNS Telemetry
    dns_query: Optional[str] = None
    dns_response: Optional[str] = None

    # Identity, Host & EDR / Process Fields
    username: Optional[str] = None
    hostname: Optional[str] = None
    process: Optional[str] = None
    parent_process: Optional[str] = None

    # Core Event Fields
    event_type: str
    event_category: str
    severity: str
    message: str

    # Web Telemetry
    user_agent: Optional[str] = None
    request_path: Optional[str] = None
    http_method: Optional[str] = None
    status_code: Optional[int] = None
    geo_country: Optional[str] = None

    # Provenance
    raw_reference: Optional[str] = None
    raw_log: Optional[str] = None


class EventCreate(EventBase):
    raw_log_id: Optional[int] = None


class EventOut(EventBase):
    id: int
    raw_log_id: Optional[int] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IngestRequest(BaseModel):
    source_type: str = "api"
    source_name: Optional[str] = None
    events: list[dict[str, Any]] = []
    raw_lines: list[str] = []


class IngestResponse(BaseModel):
    raw_log_id: int
    parsed_count: int
    alert_count: int
    errors: list[str]
    preview: list[EventOut]


class ZeekReplayRequest(BaseModel):
    log_type: Optional[str] = Field(default=None, description="conn, http, dns, or auto")
    mode: str = Field(default="REPLAY", description="LIVE, REPLAY, or SIMULATED")
    raw_content: Optional[str] = Field(default=None, description="Raw Zeek TSV or JSON log content")


class ZeekReplayResponse(BaseModel):
    raw_log_id: int
    log_type: str
    mode: str
    events_processed: int
    events_accepted: int
    events_rejected: int
    events_duplicated: int
    throughput_eps: float
    average_latency_ms: float
    maximum_latency_ms: float
    alert_count: int
    errors: list[str]
    preview: list[EventOut]
