from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    rule_id: Mapped[Optional[str]] = mapped_column(String(32), unique=True, index=True, nullable=True)
    name: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    category: Mapped[str] = mapped_column(String(64), default="web_attack", index=True)
    version: Mapped[str] = mapped_column(String(32), default="1.0")
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE", index=True)
    source: Mapped[str] = mapped_column(String(64), default="builtin")
    owner: Mapped[str] = mapped_column(String(64), default="secops-team")
    mitre_technique: Mapped[str] = mapped_column(String(32), default="NOT_MAPPED")
    confidence: Mapped[float] = mapped_column(Float, default=0.80)
    false_positive_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    expected_data_source: Mapped[str] = mapped_column(String(64), default="web_telemetry")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    conditions_json: Mapped[dict] = mapped_column(JSON)
    test_cases_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    time_window_minutes: Mapped[int] = mapped_column(Integer, default=10)
    threshold: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    alerts = relationship("Alert", back_populates="rule")
