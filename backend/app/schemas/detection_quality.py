from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict


class DetectionQualityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: Optional[int] = None
    incident_id: Optional[int] = None
    overall_quality: float
    evidence_completeness: float
    correlation_strength: float
    rule_confidence: float
    behavioral_confidence: float
    context_confidence: float
    factors_json: dict[str, Any]
    explanation: str
    created_at: datetime


class DetectionQualitySummaryOut(BaseModel):
    average_quality: float
    average_evidence_completeness: float
    average_correlation_strength: float
    average_rule_confidence: float
    average_behavioral_confidence: float
    average_context_confidence: float
    tier_distribution: dict[str, int]
    weak_detection_count: int
    strong_detection_count: int
    rule_quality_rankings: list[dict[str, Any]]
