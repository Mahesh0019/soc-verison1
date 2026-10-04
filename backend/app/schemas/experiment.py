"""
backend/app/schemas/experiment.py

Pydantic schemas for Phase 11 Research & Evaluation Engine (M0–M6 Benchmark Comparison & Ground Truth Experiments).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class ExperimentMetricOut(BaseModel):
    id: int
    experiment_run_id: int
    metric_name: str
    metric_value: float
    details_json: Optional[dict[str, Any]] = None

    class Config:
        from_attributes = True


class ExperimentRunOut(BaseModel):
    id: int
    experiment_id: int
    run_number: int
    mode: str
    total_events: int
    total_alerts: int
    total_incidents: int
    execution_duration_seconds: float
    status: str
    created_at: datetime
    metrics: list[ExperimentMetricOut] = []

    class Config:
        from_attributes = True


class ExperimentCreate(BaseModel):
    name: str = Field(..., max_length=160, description="Experiment title or hypothesis name")
    description: Optional[str] = Field(default="", description="Experimental methodology and dataset details")
    mode: str = Field(default="BENCHMARK", description="Target evaluation mode: M0, M1, ..., M6, or BENCHMARK")
    dataset_version: str = Field(default="v1.0", description="Dataset identifier/version e.g. v1.0")


class ExperimentOut(BaseModel):
    id: int
    name: str
    description: str
    mode: str
    dataset_version: str
    status: str
    created_at: datetime
    runs: list[ExperimentRunOut] = []

    class Config:
        from_attributes = True


class RunExperimentRequest(BaseModel):
    mode: str = Field(default="ALL", description="Target mode (M0, M1, M2, M3, M4, M5, M6, or ALL)")
    dataset_version: str = Field(default="v1.0", description="Dataset version to evaluate against")
    experiment_name: Optional[str] = Field(default=None, description="Optional custom name for experiment record")
    description: Optional[str] = Field(default=None, description="Optional experiment description")


class BenchmarkComparisonRow(BaseModel):
    mode: str
    name: str
    description: str
    total_events: int
    alerts_generated: int
    incidents_promoted: int
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float
    recall: float
    f1_score: float
    fp_reduction_pct: float
    attack_retention_pct: float
    mtti_minutes: float
    evidence_retrieval_ms: float
    ai_analyst_agreement_pct: Optional[float] = None


class BenchmarkComparisonResponse(BaseModel):
    experiment_id: Optional[int] = None
    experiment_name: str
    dataset_version: str
    timestamp: datetime
    comparison_matrix: list[BenchmarkComparisonRow]
    summary: dict[str, Any]
