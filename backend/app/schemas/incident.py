from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict

from app.schemas.alert import AlertOut


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_number: str
    title: str
    description: str
    severity: str
    status: str
    source_ip: Optional[str] = None
    affected_user: Optional[str] = None
    correlation_key: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    alert_count: int
    event_count: int

    # Phase 6 additions
    primary_entity: Optional[str] = None
    related_entities_json: Optional[list[dict[str, Any]]] = None
    source_types_json: Optional[list[str]] = None
    correlation_score: Optional[float] = None
    confidence: Optional[str] = "MEDIUM"
    risk_score: Optional[float] = 50.0
    attack_chain_status: Optional[str] = "CORRELATED ACTIVITY"
    timeline_json: Optional[list[dict[str, Any]]] = None
    graph_json: Optional[dict[str, Any]] = None

    created_at: datetime
    updated_at: datetime


class IncidentTimelineItem(BaseModel):
    timestamp: datetime
    source_type: Optional[str] = "WEB"
    stage: Optional[str] = "initial_access"
    title: Optional[str] = "Activity"
    description: Optional[str] = ""
    event_id: Optional[str] = None
    alert_id: Optional[int] = None
    raw_reference: Optional[str] = None
    evidence_ref: Optional[str] = None
    entities: dict[str, Any] = {}


class IncidentGraphNode(BaseModel):
    id: str
    label: str
    type: str  # IP, Host, User, Process, Event, Alert, Incident, Domain, URL
    properties: dict[str, Any] = {}


class IncidentGraphEdge(BaseModel):
    source: str
    target: str
    relationship: str  # REQUESTED, CONNECTED_TO, EXECUTED, QUERIED, GENERATED, ASSOCIATED_WITH
    timestamp: Optional[datetime] = None
    evidence_ref: Optional[str] = None


class IncidentGraphData(BaseModel):
    nodes: list[IncidentGraphNode] = []
    edges: list[IncidentGraphEdge] = []


class UnifiedIncidentOut(BaseModel):
    incident_id: int
    incident_number: str
    title: str
    description: str
    severity: str
    risk_score: float
    created_at: datetime
    updated_at: datetime
    status: str
    primary_entity: Optional[str] = None
    related_entities: list[dict[str, Any]] = []
    source_types: list[str] = []
    alerts: list[AlertOut] = []
    events: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    correlation_score: Optional[float] = None
    confidence: str = "MEDIUM"
    attack_chain_status: str = "CORRELATED ACTIVITY"
    timeline: list[IncidentTimelineItem] = []
    graph: IncidentGraphData = IncidentGraphData()


class CrossSourceCorrelationRequest(BaseModel):
    window_seconds: int = 300
    alert_ids: Optional[list[int]] = None
    rule_ids: Optional[list[str]] = None


class CrossSourceCorrelationResult(BaseModel):
    correlated_incidents_count: int
    incidents: list[IncidentOut] = []
    execution_time_ms: float
    applied_window_seconds: int
    matched_rules: list[str] = []


class IncidentDetail(IncidentOut):
    alerts: list[AlertOut] = []


class IncidentStatusUpdate(BaseModel):
    status: str
