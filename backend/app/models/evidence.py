from datetime import datetime
from typing import Any, Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    alert_id: Mapped[Optional[int]] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), nullable=True, index=True)
    incident_id: Mapped[Optional[int]] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True)
    evidence_type: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    data_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    sha256_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    alert = relationship("Alert", back_populates="evidence_items")
    incident = relationship("Incident", back_populates="evidence_items")
