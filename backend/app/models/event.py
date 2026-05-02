from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class NormalizedEvent(Base):
    __tablename__ = "normalized_events"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    raw_log_id: Mapped[Optional[int]] = mapped_column(ForeignKey("raw_logs.id", ondelete="SET NULL"), nullable=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    username: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    event_category: Mapped[str] = mapped_column(String(80), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    message: Mapped[str] = mapped_column(Text)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    request_path: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True, index=True)
    http_method: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    geo_country: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, index=True)
    raw_log: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    raw_log_ref = relationship("RawLog", back_populates="events")
    alert_links = relationship("AlertEvent", back_populates="event", cascade="all, delete-orphan")
