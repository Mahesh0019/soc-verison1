from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class AIAnalysis(Base):
    __tablename__ = "ai_analyses"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    alert_id: Mapped[Optional[int]] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), nullable=True, index=True)
    incident_id: Mapped[Optional[int]] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True)
    model_name: Mapped[str] = mapped_column(String(80))
    prompt_version: Mapped[str] = mapped_column(String(32), default="v1.0")
    summary: Mapped[str] = mapped_column(Text)
    suggested_classification: Mapped[str] = mapped_column(String(32))
    suggested_severity: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[float] = mapped_column(Float, default=0.8)
    supporting_evidence_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    uncertainty_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_claim_count: Mapped[int] = mapped_column(Integer, default=0)
    supported_claim_count: Mapped[int] = mapped_column(Integer, default=0)
    unsupported_claim_count: Mapped[int] = mapped_column(Integer, default=0)
    analyst_agreement: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    alert = relationship("Alert", back_populates="ai_analyses")
    incident = relationship("Incident", back_populates="ai_analyses")
