"""
backend/app/schemas/ai_analyst.py

Pydantic schemas for Phase 8: Evidence-Grounded AI Analyst Assistance & Hallucination Evaluation.
Strictly separates:
  - Authoritative Evidence citations
  - Fact vs. Inference vs. Recommendation vs. Uncertainty
  - Structured post-generation validation status
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


class EvidenceCitation(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    evidence_id: Optional[int] = Field(None, description="Database ID of authoritative Evidence record")
    source_type: str = Field(..., description="Telemetry plane: WEB, ZEEK, SYSMON, AUTH, FIREWALL")
    event_id: Optional[int] = Field(None, description="Database ID of NormalizedEvent")
    field: str = Field(..., description="Telemetry attribute referenced (e.g. process, source_ip, request_path)")
    value: str = Field(..., description="Observed value from authoritative database record")
    timestamp: Optional[datetime] = Field(None, description="Authoritative event timestamp")
    provenance: str = Field("database_event", description="Cryptographic provenance origin")


class AIClaim(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    claim_id: str
    claim_type: Literal["FACT", "INFERENCE", "RECOMMENDATION", "UNCERTAINTY"]
    claim_text: str
    citation: Optional[EvidenceCitation] = None
    validation_status: Literal["SUPPORTED", "UNSUPPORTED", "CONTRADICTED", "UNVERIFIABLE"]
    validation_reason: str


class AttackChainStep(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    stage_order: int
    stage_name: str
    description: str
    source_type: str
    evidence_ids: list[int] = Field(default_factory=list)
    timestamp: Optional[datetime] = None


class MITREContextItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tactic: str
    technique_id: str
    technique_name: str
    evidence_ids: list[int] = Field(default_factory=list)
    confidence: float = 1.0


class AIAnalystStructuredOutput(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident_id: int
    model_name: str = "Deterministic AI Analyst Baseline (Evidence-Grounded Engine v2.0)"
    prompt_version: str = "v2.0-evidence-bounded"
    created_at: datetime

    # High-level analytical assessment
    summary: str
    assessment: Literal["TRUE_POSITIVE", "SUSPICIOUS", "FALSE_POSITIVE", "INSUFFICIENT_EVIDENCE"]
    confidence: float = Field(..., ge=0.0, le=1.0)
    abstain: bool = Field(False, description="True when evidence is insufficient, contradictory, or absent")
    abstention_reason: Optional[str] = None

    # Granular separation of analytical planes
    facts: list[str] = Field(default_factory=list, description="Verified factual statements citing evidence")
    inferences: list[str] = Field(default_factory=list, description="Logical security inferences derived from facts")
    recommendations: list[str] = Field(default_factory=list, description="Advisory investigation and response guidance")
    uncertainties: list[str] = Field(default_factory=list, description="Explicit data gaps or ambiguities")

    # Structured collections
    supporting_evidence: list[EvidenceCitation] = Field(default_factory=list)
    contradicting_evidence: list[EvidenceCitation] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    attack_chain: list[AttackChainStep] = Field(default_factory=list)
    mitre_context: list[MITREContextItem] = Field(default_factory=list)
    recommended_investigation_steps: list[str] = Field(default_factory=list)
    recommended_response: list[str] = Field(default_factory=list, description="Advisory containment actions only")

    # Decomposed Claims & Validation Metrics
    claims: list[AIClaim] = Field(default_factory=list)
    total_claims_count: int = 0
    supported_claims_count: int = 0
    unsupported_claims_count: int = 0
    contradicted_claims_count: int = 0
    citation_coverage_pct: float = 0.0
    invalid_citation_count: int = 0


class AnalystQuestionRequest(BaseModel):
    question: str = Field(..., min_length=3, max_length=500)


class AnalystQuestionResponse(BaseModel):
    incident_id: int
    question: str
    answer: str
    evidence_citations: list[EvidenceCitation] = Field(default_factory=list)
    grounded_in_evidence: bool = True
    uncertainty: Optional[str] = None


class AIAnalystContextOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident_id: int
    incident_number: str
    severity: str
    risk_score: float
    correlation_score: float
    source_types: list[str]
    alert_count: int
    event_count: int
    evidence_items_count: int
    evidence_provenance_records: list[dict[str, Any]]
    untrusted_telemetry_payloads: list[dict[str, Any]]
    redacted_fields_count: int
