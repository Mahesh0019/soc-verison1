"""
backend/app/schemas/threat_hunting.py

Phase 9: Threat Hunting & Closed-Loop Detection Engineering Schemas.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


class ThreatHuntCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    hypothesis: str = Field(..., min_length=10)
    analyst: str = Field("analyst_secops", max_length=128)
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    data_sources: list[str] = Field(default_factory=list)
    query_filter: dict[str, Any] = Field(default_factory=dict)
    expected_behavior: str = Field(..., min_length=5)


class ThreatHuntUpdate(BaseModel):
    status: Optional[str] = None
    observed_behavior: Optional[str] = None
    result: Optional[Literal["CONFIRMED", "NEGATED", "INCONCLUSIVE", "INSUFFICIENT_DATA"]] = None
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)


class ThreatHuntOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    hunt_id: str
    title: str
    hypothesis: str
    analyst: str
    created_at: datetime
    updated_at: datetime
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    data_sources_json: list[str] = Field(default_factory=list)
    query_filter_json: dict[str, Any] = Field(default_factory=dict)
    expected_behavior: str
    observed_behavior: Optional[str] = None
    related_incidents_json: list[int] = Field(default_factory=list)
    related_alerts_json: list[int] = Field(default_factory=list)
    related_events_json: list[int] = Field(default_factory=list)
    evidence_refs_json: list[dict[str, Any]] = Field(default_factory=list)
    mitre_context_json: list[dict[str, Any]] = Field(default_factory=list)
    result: Optional[str] = "INCONCLUSIVE"
    confidence: Optional[float] = 0.5
    classification: Optional[str] = "INSUFFICIENT_DATA"
    detection_gap_id: Optional[int] = None
    candidate_rule_id: Optional[int] = None
    status: Optional[str] = "COMPLETED"


class DetectionGapCreate(BaseModel):
    hunt_id: Optional[int] = None
    description: str
    affected_source: str
    affected_behavior: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "HIGH"
    frequency: int = 1
    existing_rule_ids: list[str] = Field(default_factory=list)
    missing_detection_capability: str
    evidence_refs: list[dict[str, Any]] = Field(default_factory=list)
    mitre_mapping: dict[str, Any] = Field(default_factory=dict)


class DetectionGapOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    gap_id: str
    hunt_id: Optional[int] = None
    description: str
    affected_source: str
    affected_behavior: str
    severity: str
    frequency: int
    existing_rule_ids_json: list[str] = Field(default_factory=list)
    missing_detection_capability: str
    evidence_refs_json: list[dict[str, Any]] = Field(default_factory=list)
    mitre_mapping_json: dict[str, Any] = Field(default_factory=dict)
    candidate_rule_id: Optional[int] = None
    status: Literal[
        "IDENTIFIED",
        "UNDER_REVIEW",
        "CANDIDATE",
        "VALIDATING",
        "ACCEPTED",
        "REJECTED",
        "DUPLICATE",
    ]
    created_at: datetime
    updated_at: datetime


class CandidateRuleCreate(BaseModel):
    gap_id: Optional[int] = None
    name: str = Field(..., min_length=3, max_length=255)
    description: str
    source: str = "threat_hunt"
    category: str = "endpoint"
    severity: str = "high"
    logic: dict[str, Any]
    expected_entities: list[str] = Field(default_factory=list)
    mitre_mapping: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(0.85, ge=0.0, le=1.0)
    false_positive_notes: Optional[str] = None
    required_telemetry: list[str] = Field(default_factory=list)
    test_cases: dict[str, Any] = Field(default_factory=dict)
    version: str = "1.0"
    author: str = "analyst_threat_hunter"


class CandidateRuleTransitionRequest(BaseModel):
    target_status: Literal["DRAFT", "TESTING", "VALIDATING", "ACTIVE", "DEPRECATED"]
    change_reason: str
    author: str = "analyst_lead"


class RuleVersionHistoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    candidate_rule_id: int
    rule_identifier: str
    version: str
    parent_version: Optional[str] = None
    status: str
    change_reason: str
    author: str
    validation_metrics_json: dict[str, Any]
    activation_reason: Optional[str] = None
    deprecation_reason: Optional[str] = None
    created_at: datetime


class RegressionEvaluationRecordOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    candidate_rule_id: int
    evaluated_at: datetime
    target_datasets_json: list[str]
    tp_delta: int
    fp_delta: int
    fn_delta: int
    tn_delta: int
    f1_delta: float
    fpr_delta: float
    latency_delta_ms: float
    status: str
    tradeoff_notes: Optional[str] = None


class CandidateRuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    candidate_rule_id: str
    gap_id: Optional[int] = None
    name: str
    description: str
    source: str
    category: str
    severity: str
    logic_json: dict[str, Any]
    expected_entities_json: list[str]
    mitre_mapping_json: dict[str, Any]
    confidence: float
    false_positive_notes: Optional[str] = None
    required_telemetry_json: list[str]
    test_cases_json: dict[str, Any]
    version: str
    parent_version: Optional[str] = None
    status: Literal["DRAFT", "TESTING", "VALIDATING", "ACTIVE", "DEPRECATED"]
    author: str
    change_reason: Optional[str] = None
    validation_result_json: Optional[dict[str, Any]] = None
    activation_reason: Optional[str] = None
    deprecation_reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    active_rule_id: Optional[int] = None
    version_history: list[RuleVersionHistoryOut] = Field(default_factory=list)
    regression_records: list[RegressionEvaluationRecordOut] = Field(default_factory=list)


class HuntExecutionResponse(BaseModel):
    hunt_id: str
    result: Literal["CONFIRMED", "NEGATED", "INCONCLUSIVE", "INSUFFICIENT_DATA"]
    confidence: float
    classification: Literal[
        "TRUE_POSITIVE_DISCOVERY",
        "FALSE_LEAD",
        "INSUFFICIENT_DATA",
        "ALREADY_COVERED_BY_EXISTING_RULE",
        "DETECTION_GAP",
    ]
    matched_events_count: int
    matched_event_ids: list[int]
    related_incident_ids: list[int]
    related_alert_ids: list[int]
    evidence_refs: list[dict[str, Any]]
    detection_gap: Optional[DetectionGapOut] = None
    candidate_rule: Optional[CandidateRuleOut] = None


class DetectionCoverageItem(BaseModel):
    behavior: str
    telemetry_source: str
    mitre_technique: str
    technique_name: str
    existing_rule: Optional[str] = None
    coverage: Literal["FULL", "PARTIAL", "MISSING", "UNKNOWN"]
    confidence: float
    known_gap: Optional[str] = None


class DetectionCoverageMatrixResponse(BaseModel):
    total_behaviors_evaluated: int
    full_coverage_count: int
    partial_coverage_count: int
    missing_coverage_count: int
    coverage_percentage: float
    items: list[DetectionCoverageItem]
