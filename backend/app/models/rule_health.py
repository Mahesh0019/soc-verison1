from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class RuleHealthRecord(Base):
    __tablename__ = "rule_health_records"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    rule_id: Mapped[Optional[int]] = mapped_column(ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=True, index=True)
    rule_name: Mapped[str] = mapped_column(String(160), index=True)
    version: Mapped[str] = mapped_column(String(32), default="1.0")
    dataset_target: Mapped[str] = mapped_column(String(64), default="validation_suite")
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    true_positives: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    false_positives: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    false_negatives: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    true_negatives: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    precision: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    recall: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    f1_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    false_positive_rate: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    alert_volume: Mapped[int] = mapped_column(Integer, default=0)
    detection_latency_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    coverage_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    regression_status: Mapped[str] = mapped_column(String(32), default="PASSED")

    health_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    health_tier: Mapped[str] = mapped_column(String(32), default="INSUFFICIENT_DATA")
    details_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    rule = relationship("DetectionRule")
