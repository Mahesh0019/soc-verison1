from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class DetectionQuality(Base):
    __tablename__ = "detection_quality"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    alert_id: Mapped[Optional[int]] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), nullable=True, index=True)
    incident_id: Mapped[Optional[int]] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True)
    overall_quality: Mapped[float] = mapped_column(Float, index=True)
    evidence_completeness: Mapped[float] = mapped_column(Float, default=0.0)
    correlation_strength: Mapped[float] = mapped_column(Float, default=0.0)
    rule_confidence: Mapped[float] = mapped_column(Float, default=1.0)
    behavioral_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    context_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    factors_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    explanation: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    alert = relationship("Alert", back_populates="detection_quality")
    incident = relationship("Incident", back_populates="detection_quality")
