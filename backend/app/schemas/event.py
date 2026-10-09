from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.source_types import TelemetrySourceType, normalize_source_type


class EventBase(BaseModel):
    event_id: Optional[str] = None
    timestamp: datetime

    # Multi-Source Classification (WEB, AUTH, FIREWALL, ZEEK, SYSMON, THREAT_INTEL, OTHER)
    source_type: Optional[str] = Field(default=TelemetrySourceType.OTHER.value)
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

    # Identity, Host & Endpoint / Sysmon Fields
    username: Optional[str] = None
    hostname: Optional[str] = None
    process: Optional[str] = None
    parent_process: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_id: Optional[int] = None
    command_line: Optional[str] = None
    image_path: Optional[str] = None
    file_hash: Optional[str] = None

    # Core Event Fields
    event_type: Optional[str] = "generic"
    event_category: Optional[str] = "general"
    severity: Optional[str] = "low"
    message: Optional[str] = ""

    # Web Telemetry
    user_agent: Optional[str] = None
    request_path: Optional[str] = None
    http_method: Optional[str] = None
    status_code: Optional[int] = None
    geo_country: Optional[str] = None

    # Provenance
    raw_reference: Optional[str] = None
    raw_log: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def derive_and_normalize_source(cls, data: Any) -> Any:
        """Derive missing source_type from trustworthy metadata or classify as OTHER."""
        if isinstance(data, dict):
            src = data.get("source_type")
            if not src:
                if data.get("request_path") or data.get("http_method") or data.get("status_code"):
                    data["source_type"] = TelemetrySourceType.WEB.value
                elif data.get("event_category") == "authentication" or data.get("event_type") in ("failed_login", "successful_login"):
                    data["source_type"] = TelemetrySourceType.AUTH.value
                elif data.get("event_category") == "firewall":
                    data["source_type"] = TelemetrySourceType.FIREWALL.value
                elif data.get("dns_query") or data.get("connection_state") or data.get("protocol"):
                    data["source_type"] = TelemetrySourceType.ZEEK.value
                elif data.get("process") or data.get("image_path") or data.get("command_line"):
                    data["source_type"] = TelemetrySourceType.SYSMON.value
                else:
                    data["source_type"] = TelemetrySourceType.OTHER.value
            else:
                data["source_type"] = normalize_source_type(str(src))
            return data

        if hasattr(data, "source_type"):
            src = getattr(data, "source_type", None)
            if not src:
                if getattr(data, "request_path", None) or getattr(data, "http_method", None) or getattr(data, "status_code", None):
                    setattr(data, "source_type", TelemetrySourceType.WEB.value)
                elif getattr(data, "event_category", None) == "authentication" or getattr(data, "event_type", None) in ("failed_login", "successful_login"):
                    setattr(data, "source_type", TelemetrySourceType.AUTH.value)
                elif getattr(data, "event_category", None) == "firewall":
                    setattr(data, "source_type", TelemetrySourceType.FIREWALL.value)
                elif getattr(data, "dns_query", None) or getattr(data, "connection_state", None) or getattr(data, "protocol", None):
                    setattr(data, "source_type", TelemetrySourceType.ZEEK.value)
                elif getattr(data, "process", None) or getattr(data, "image_path", None) or getattr(data, "command_line", None):
                    setattr(data, "source_type", TelemetrySourceType.SYSMON.value)
                else:
                    setattr(data, "source_type", TelemetrySourceType.OTHER.value)
            else:
                setattr(data, "source_type", normalize_source_type(str(src)))
        return data

    @field_validator("source_type", mode="before")
    @classmethod
    def ensure_source_type(cls, v: Any) -> Optional[str]:
        if v is not None and str(v).strip():
            return normalize_source_type(str(v).strip())
        return TelemetrySourceType.OTHER.value

    @field_validator("event_type", mode="before")
    @classmethod
    def ensure_event_type(cls, v: Any) -> str:
        return str(v) if v else "generic"

    @field_validator("event_category", mode="before")
    @classmethod
    def ensure_event_category(cls, v: Any) -> str:
        return str(v) if v else "general"

    @field_validator("severity", mode="before")
    @classmethod
    def ensure_severity(cls, v: Any) -> str:
        return str(v) if v else "low"

    @field_validator("message", mode="before")
    @classmethod
    def ensure_message(cls, v: Any) -> str:
        return str(v) if v is not None else ""


class EventCreate(EventBase):
    raw_log_id: Optional[int] = None


class EventOut(EventBase):
    id: int
    raw_log_id: Optional[int] = None
    created_at: Optional[datetime] = None

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
    parse_time_ms: Optional[float] = None
    db_persistence_time_ms: Optional[float] = None
    detection_latency_ms: Optional[float] = None
    parser_throughput_eps: Optional[float] = None
    ingestion_throughput_eps: Optional[float] = None
    detection_throughput_eps: Optional[float] = None
    total_soc_throughput_eps: Optional[float] = None
    alert_count: int
    errors: list[str]
    preview: list[EventOut]


class SysmonReplayRequest(BaseModel):
    mode: str = Field(default="REPLAY", description="LIVE, REPLAY, or SIMULATED")
    raw_content: Optional[str] = Field(default=None, description="Raw Sysmon XML or JSON lines log content")


class SysmonReplayResponse(BaseModel):
    raw_log_id: int
    source_type: str
    mode: str
    events_processed: int
    events_accepted: int
    events_rejected: int
    events_duplicated: int
    throughput_eps: float
    average_latency_ms: float
    maximum_latency_ms: float
    parse_time_ms: Optional[float] = None
    db_persistence_time_ms: Optional[float] = None
    detection_latency_ms: Optional[float] = None
    parser_throughput_eps: Optional[float] = None
    ingestion_throughput_eps: Optional[float] = None
    detection_throughput_eps: Optional[float] = None
    total_soc_throughput_eps: Optional[float] = None
    alert_count: int
    errors: list[str]
    preview: list[EventOut]
