from datetime import datetime
from typing import Any, Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class ValidationTest(Base):
    __tablename__ = "validation_tests"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("detection_rules.id", ondelete="CASCADE"), index=True)
    rule_version: Mapped[str] = mapped_column(String(32), default="1.0")
    test_name: Mapped[str] = mapped_column(String(160))
    test_scenario_id: Mapped[str] = mapped_column(String(80), index=True)
    expected_result: Mapped[bool] = mapped_column(Boolean)
    observed_result: Mapped[bool] = mapped_column(Boolean)
    passed: Mapped[bool] = mapped_column(Boolean, index=True)
    execution_time_ms: Mapped[float] = mapped_column(Float, default=0.0)
    details_json: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    rule = relationship("DetectionRule")
