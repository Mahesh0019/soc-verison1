"""
backend/app/schemas/feedback.py

Pydantic schemas for Phase 9 Analyst Feedback Loop & Controlled Rule Tuning.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class AnalystFeedbackCreate(BaseModel):
    classification: str = Field(..., description="'TRUE_POSITIVE', 'FALSE_POSITIVE', 'BENIGN', or 'SUSPICIOUS'")
    severity_override: Optional[str] = Field(None, description="Optional analyst-specified severity: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'")
    notes: Optional[str] = Field(None, description="Detailed analyst reasoning or investigation findings")
    feedback_type: Optional[str] = Field("triage", description="'triage', 'tuning', 'incident_review', or 'closure'")
    rule_adjustment_suggested: Optional[bool] = Field(False, description="Whether rule conditions or thresholds should be tuned")
    suggested_rule_changes_json: Optional[dict[str, Any]] = Field(None, description="Proposed tuning payload")


class AnalystFeedbackOut(BaseModel):
    id: int
    alert_id: Optional[int] = None
    incident_id: Optional[int] = None
    analyst_id: Optional[int] = None
    classification: str
    severity_override: Optional[str] = None
    notes: Optional[str] = None
    feedback_type: str
    rule_adjustment_suggested: bool
    suggested_rule_changes_json: Optional[dict[str, Any]] = None
    created_at: datetime

    class Config:
        from_attributes = True


class RuleTuningProposal(BaseModel):
    feedback_id: int
    rule_id: int
    rule_name: str
    tuning_type: str
    parameters: dict[str, Any]
    rationale: str
    status: str
    created_at: datetime


class RuleTuningApplyRequest(BaseModel):
    feedback_id: int = Field(..., description="ID of the feedback containing the tuning proposal")
    confirm: bool = Field(..., description="Must be true to apply the rule change safely")


class FeedbackSummaryOut(BaseModel):
    total_feedbacks: int
    classification_breakdown: dict[str, int]
    false_positive_rate: float
    ai_analyst_agreement_rate: float
    noisiest_rules: list[dict[str, Any]]
    tuning_proposals_count: int
