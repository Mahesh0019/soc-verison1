from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    incident_number: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(32), default="medium", index=True)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    affected_user: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    correlation_key: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    event_count: Mapped[int] = mapped_column(Integer, default=0)

    # Phase 6: Cross-Source Correlation & Unified Incident Fields
    primary_entity: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    related_entities_json: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(JSON, nullable=True)
    source_types_json: Mapped[Optional[list[str]]] = mapped_column(JSON, nullable=True)
    correlation_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    confidence: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, default="MEDIUM")
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True, default=50.0)
    attack_chain_status: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, default="CORRELATED ACTIVITY")
    timeline_json: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(JSON, nullable=True)
    graph_json: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    @property
    def source_types(self) -> list[str]:
        return self.source_types_json or []

    @source_types.setter
    def source_types(self, val: list[str]) -> None:
        self.source_types_json = val

    @property
    def timeline(self) -> list[dict[str, Any]]:
        return self.timeline_json or []

    @timeline.setter
    def timeline(self, val: list[dict[str, Any]]) -> None:
        self.timeline_json = val

    @property
    def graph(self) -> dict[str, Any]:
        return self.graph_json or {}

    @graph.setter
    def graph(self, val: dict[str, Any]) -> None:
        self.graph_json = val

    @property
    def related_entities(self) -> list[Any]:
        return self.related_entities_json or []

    @related_entities.setter
    def related_entities(self, val: list[Any]) -> None:
        self.related_entities_json = val


    alerts = relationship("IncidentAlert", back_populates="incident", cascade="all, delete-orphan")
    cases = relationship("Case", back_populates="incident")
    evidence_items = relationship("Evidence", back_populates="incident", cascade="all, delete-orphan")
    detection_quality = relationship("DetectionQuality", back_populates="incident", uselist=False, cascade="all, delete-orphan")
    risk_assessment = relationship("RiskAssessment", back_populates="incident", uselist=False, cascade="all, delete-orphan")
    ai_analyses = relationship("AIAnalysis", back_populates="incident", cascade="all, delete-orphan")
    feedbacks = relationship("AnalystFeedback", back_populates="incident", cascade="all, delete-orphan")


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"
    __table_args__ = (UniqueConstraint("incident_id", "alert_id", name="uq_incident_alert"),)

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)

    incident = relationship("Incident", back_populates="alerts")
    alert = relationship("Alert")
