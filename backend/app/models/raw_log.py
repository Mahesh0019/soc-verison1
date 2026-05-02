from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class RawLog(Base):
    __tablename__ = "raw_logs"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    source_type: Mapped[str] = mapped_column(String(80), index=True)
    original_content: Mapped[str] = mapped_column(Text)
    file_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    uploaded_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    uploader = relationship("User", back_populates="raw_logs")
    events = relationship("NormalizedEvent", back_populates="raw_log_ref", cascade="all, delete-orphan")
