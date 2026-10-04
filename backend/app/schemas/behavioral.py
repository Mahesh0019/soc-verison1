from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class BehavioralFeatureVector(BaseModel):
    request_rate: float = Field(..., description="Requests per minute or window count")
    error_ratio_4xx: float = Field(..., description="Proportion of 4xx client errors [0.0, 1.0]")
    error_ratio_5xx: float = Field(..., description="Proportion of 5xx server errors [0.0, 1.0]")
    path_entropy: float = Field(..., description="Shannon entropy of request paths")
    method_diversity: float = Field(..., description="Count or proportion of distinct HTTP methods")
    status_diversity: float = Field(..., description="Count of distinct HTTP status codes")
    off_hours_ratio: float = Field(..., description="Proportion of requests outside normal business hours")
    unique_paths_ratio: float = Field(..., description="Distinct paths ratio")
    failed_login_ratio: float = Field(..., description="Proportion of failed login attempts")
    sensitive_path_ratio: float = Field(..., description="Proportion of requests targeting sensitive endpoints")


class BehavioralAnomalyResult(BaseModel):
    entity_type: str = Field(..., description="Target entity type: 'ip', 'alert', 'user', or 'window'")
    entity_id: str = Field(..., description="Target entity identifier")
    anomaly_score: float = Field(..., ge=0.0, le=1.0, description="Normalized anomaly score [0.0, 1.0]")
    is_anomaly: bool = Field(..., description="Whether the sample is classified as anomalous")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in anomaly assessment")
    primary_factor: str = Field(..., description="Primary explanatory feature driving the anomaly")
    features: dict[str, float] = Field(..., description="Observed feature values")
    feature_contributions: dict[str, float] = Field(..., description="Deviation/contribution weights per feature")
    explanation: str = Field(..., description="Human-readable explanation of behavioral findings")


class ModelTrainingRequest(BaseModel):
    window_minutes: Optional[int] = Field(1440, description="Historical time window in minutes to sample")
    contamination: Optional[float] = Field(0.08, ge=0.01, le=0.5, description="Expected proportion of outliers")


class ModelTrainingResponse(BaseModel):
    success: bool
    sample_count: int
    feature_dimensions: int
    contamination: float
    trained_at: datetime
    message: str


class ModelStatusResponse(BaseModel):
    is_fitted: bool
    model_name: str
    sample_count: int
    feature_names: list[str]
    last_trained: Optional[datetime] = None
    baseline_averages: dict[str, float] = {}
