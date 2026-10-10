"""
backend/app/schemas/ai_triage.py

Pydantic schemas for Phase 8 Evidence-Grounded SLM/LLM Assistance & Claims Audit.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class AIClaim(BaseModel):
    claim_text: str = Field(..., description="Factual claim asserted in the AI triage")
    evidence_id: Optional[int] = Field(None, description="ID of verified backing evidence item")
    evidence_type: Optional[str] = Field(None, description="Type of evidence backing the claim")
    is_supported: bool = Field(..., description="True if proven by concrete verified evidence item")


class AIAnalysisOut(BaseModel):
    id: int
    alert_id: Optional[int] = None
    incident_id: Optional[int] = None
    model_name: str
    prompt_version: str
    summary: str
    suggested_classification: str
    suggested_severity: str
    confidence: float
    supporting_evidence_json: dict[str, Any]
    uncertainty_notes: Optional[str] = None
    ai_claim_count: int
    supported_claim_count: int
    unsupported_claim_count: int
    grounding_rate: float
    analyst_agreement: Optional[str] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class AIAgreementRequest(BaseModel):
    agreement: str = Field(..., description="'AGREE', 'DISAGREE', or 'PARTIAL'")
    notes: Optional[str] = Field(None, description="Analyst rationale or corrections")


class AITriageSummary(BaseModel):
    total_analyses: int
    average_confidence: float
    average_grounding_rate: float
    total_claims: int
    total_supported_claims: int
    total_unsupported_claims: int
    agreement_breakdown: dict[str, int]
