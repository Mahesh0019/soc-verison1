from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class RuleBase(BaseModel):
    rule_id: Optional[str] = Field(default=None, pattern=r"^[A-Z0-9_\-]{3,32}$")
    name: str = Field(min_length=3, max_length=160)
    description: str = Field(min_length=1, max_length=1000)
    severity: str = Field(pattern="^(low|medium|high|critical)$")
    category: str = Field(default="web_attack", pattern=r"^[a-z0-9_\-]{2,64}$")
    version: str = Field(default="1.0", pattern=r"^\d+\.\d+(\.\d+)?$")
    status: str = Field(default="ACTIVE", pattern="^(DRAFT|TESTING|ACTIVE|DISABLED|DEPRECATED)$")
    source: str = Field(default="custom", max_length=64)
    owner: str = Field(default="secops-team", max_length=64)
    mitre_technique: str = Field(default="NOT_MAPPED", pattern=r"^(T\d{4}(\.\d{3})?|NOT_MAPPED)$")
    confidence: float = Field(default=0.80, ge=0.0, le=1.0)
    false_positive_notes: Optional[str] = None
    expected_data_source: str = Field(default="web_telemetry", max_length=64)
    enabled: bool = True
    conditions_json: dict[str, Any]
    test_cases_json: Optional[dict[str, Any]] = None
    time_window_minutes: int = Field(default=10, ge=1, le=1440)
    threshold: int = Field(default=1, ge=1, le=10000)


class RuleCreate(RuleBase):
    pass


class RuleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=3, max_length=160)
    description: Optional[str] = Field(default=None, min_length=1, max_length=1000)
    severity: Optional[str] = Field(default=None, pattern="^(low|medium|high|critical)$")
    category: Optional[str] = Field(default=None, pattern=r"^[a-z0-9_\-]{2,64}$")
    version: Optional[str] = Field(default=None, pattern=r"^\d+\.\d+(\.\d+)?$")
    status: Optional[str] = Field(default=None, pattern="^(DRAFT|TESTING|ACTIVE|DISABLED|DEPRECATED)$")
    owner: Optional[str] = Field(default=None, max_length=64)
    mitre_technique: Optional[str] = Field(default=None, pattern=r"^(T\d{4}(\.\d{3})?|NOT_MAPPED)$")
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    false_positive_notes: Optional[str] = None
    expected_data_source: Optional[str] = Field(default=None, max_length=64)
    enabled: Optional[bool] = None
    conditions_json: Optional[dict[str, Any]] = None
    test_cases_json: Optional[dict[str, Any]] = None
    time_window_minutes: Optional[int] = Field(default=None, ge=1, le=1440)
    threshold: Optional[int] = Field(default=None, ge=1, le=10000)


class RuleOut(RuleBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RuleToggle(BaseModel):
    enabled: bool


class RuleHealthOut(BaseModel):
    id: int
    rule_id: Optional[int] = None
    rule_identifier: Optional[str] = None
    rule_name: str
    version: str
    dataset_target: str
    evaluated_at: datetime

    true_positives: Optional[int] = None
    false_positives: Optional[int] = None
    false_negatives: Optional[int] = None
    true_negatives: Optional[int] = None

    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    false_positive_rate: Optional[float] = None

    alert_volume: int = 0
    detection_latency_ms: Optional[float] = None
    coverage_score: Optional[float] = None
    confidence: Optional[float] = None
    regression_status: str = "PASSED"

    health_score: Optional[float] = None
    health_tier: str = "INSUFFICIENT_DATA"
    details_json: Optional[dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class RuleHealthSummaryOut(BaseModel):
    total_rules: int
    evaluated_rules: int
    average_health_score: Optional[float] = None
    tier_distribution: dict[str, int]
    rule_records: list[RuleHealthOut]
