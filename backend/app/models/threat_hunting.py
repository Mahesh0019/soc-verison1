"""
backend/app/models/threat_hunting.py

Phase 9: Threat Hunting & Closed-Loop Detection Engineering Data Models.
Establishes the closed-loop lifecycle:
  Investigation/Hunt -> Detection Gap -> Candidate Detection -> Validation Gate -> Versioned Rule -> Regression Check
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class ThreatHunt(Base):
    __tablename__ = "threat_hunts"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    hunt_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255), index=True)
    hypothesis: Mapped[str] = mapped_column(Text)
    analyst: Mapped[str] = mapped_column(String(128), default="analyst_secops")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    time_range_start: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    time_range_end: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    data_sources_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    query_filter_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    expected_behavior: Mapped[str] = mapped_column(Text)
    observed_behavior: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    related_incidents_json: Mapped[list[int]] = mapped_column(JSON, default=list)
    related_alerts_json: Mapped[list[int]] = mapped_column(JSON, default=list)
    related_events_json: Mapped[list[int]] = mapped_column(JSON, default=list)
    evidence_refs_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    mitre_context_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)

    # Allowed results: CONFIRMED, NEGATED, INCONCLUSIVE, INSUFFICIENT_DATA
    result: Mapped[str] = mapped_column(String(32), default="INCONCLUSIVE", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.50)

    # Classification: TRUE_POSITIVE_DISCOVERY, FALSE_LEAD, INSUFFICIENT_DATA, ALREADY_COVERED_BY_EXISTING_RULE, DETECTION_GAP
    classification: Mapped[str] = mapped_column(String(64), default="FALSE_LEAD", index=True)

    candidate_rule_id: Mapped[Optional[int]] = mapped_column(ForeignKey("candidate_rules.id", ondelete="SET NULL"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", index=True)

    # Relationships
    detection_gap = relationship("DetectionGap", back_populates="hunt", uselist=False, foreign_keys="[DetectionGap.hunt_id]")
    candidate_rule = relationship("CandidateRule", foreign_keys=[candidate_rule_id])

    @property
    def detection_gap_id(self) -> Optional[int]:
        return self.detection_gap.id if self.detection_gap else None


class DetectionGap(Base):
    __tablename__ = "detection_gaps"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    gap_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    hunt_id: Mapped[Optional[int]] = mapped_column(ForeignKey("threat_hunts.id", ondelete="SET NULL"), nullable=True, index=True)
    description: Mapped[str] = mapped_column(Text)
    affected_source: Mapped[str] = mapped_column(String(64), index=True)
    affected_behavior: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(32), default="HIGH", index=True)
    frequency: Mapped[int] = mapped_column(Integer, default=1)
    existing_rule_ids_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    missing_detection_capability: Mapped[str] = mapped_column(Text)
    evidence_refs_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    mitre_mapping_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    candidate_rule_id: Mapped[Optional[int]] = mapped_column(ForeignKey("candidate_rules.id", ondelete="SET NULL"), nullable=True, index=True)

    # Statuses: IDENTIFIED, UNDER_REVIEW, CANDIDATE, VALIDATING, ACCEPTED, REJECTED, DUPLICATE
    status: Mapped[str] = mapped_column(String(32), default="IDENTIFIED", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    hunt = relationship("ThreatHunt", back_populates="detection_gap", foreign_keys=[hunt_id])
    candidate_rule = relationship("CandidateRule", back_populates="detection_gaps", foreign_keys=[candidate_rule_id])


class CandidateRule(Base):
    __tablename__ = "candidate_rules"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    candidate_rule_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(64), default="threat_hunt")
    category: Mapped[str] = mapped_column(String(64), default="endpoint")
    severity: Mapped[str] = mapped_column(String(32), default="high")
    logic_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    expected_entities_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    mitre_mapping_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=0.85)
    false_positive_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    required_telemetry_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    test_cases_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    version: Mapped[str] = mapped_column(String(32), default="1.0")
    parent_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    # Lifecycle: DRAFT -> TESTING -> VALIDATING -> ACTIVE -> DEPRECATED
    status: Mapped[str] = mapped_column(String(32), default="DRAFT", index=True)
    author: Mapped[str] = mapped_column(String(128), default="analyst_threat_hunter")
    change_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    validation_result_json: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    activation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    deprecation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Linked active DetectionRule (if promoted to active)
    active_rule_id: Mapped[Optional[int]] = mapped_column(ForeignKey("detection_rules.id", ondelete="SET NULL"), nullable=True, index=True)

    # Relationships
    detection_gaps = relationship("DetectionGap", back_populates="candidate_rule", foreign_keys="[DetectionGap.candidate_rule_id]")
    version_history = relationship("RuleVersionHistory", back_populates="candidate_rule", cascade="all, delete-orphan")
    regression_records = relationship("RegressionEvaluationRecord", back_populates="candidate_rule", cascade="all, delete-orphan")

    @property
    def gap_id(self) -> Optional[int]:
        return self.detection_gaps[0].id if self.detection_gaps else None


class RuleVersionHistory(Base):
    __tablename__ = "rule_version_histories"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    candidate_rule_id: Mapped[int] = mapped_column(ForeignKey("candidate_rules.id", ondelete="CASCADE"), index=True)
    rule_identifier: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[str] = mapped_column(String(32))
    parent_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(32))
    change_reason: Mapped[str] = mapped_column(Text)
    author: Mapped[str] = mapped_column(String(128))
    validation_metrics_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    activation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    deprecation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    candidate_rule = relationship("CandidateRule", back_populates="version_history")


class RegressionEvaluationRecord(Base):
    __tablename__ = "regression_evaluation_records"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    candidate_rule_id: Mapped[int] = mapped_column(ForeignKey("candidate_rules.id", ondelete="CASCADE"), index=True)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    target_datasets_json: Mapped[list[str]] = mapped_column(JSON, default=list)

    tp_delta: Mapped[int] = mapped_column(Integer, default=0)
    fp_delta: Mapped[int] = mapped_column(Integer, default=0)
    fn_delta: Mapped[int] = mapped_column(Integer, default=0)
    tn_delta: Mapped[int] = mapped_column(Integer, default=0)

    f1_delta: Mapped[float] = mapped_column(Float, default=0.0)
    fpr_delta: Mapped[float] = mapped_column(Float, default=0.0)
    latency_delta_ms: Mapped[float] = mapped_column(Float, default=0.0)

    status: Mapped[str] = mapped_column(String(32), default="PASSED")
    tradeoff_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    candidate_rule = relationship("CandidateRule", back_populates="regression_records")
