from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class NormalizedEvent(Base):
    __tablename__ = "normalized_events"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    raw_log_id: Mapped[Optional[int]] = mapped_column(ForeignKey("raw_logs.id", ondelete="SET NULL"), nullable=True, index=True)
    event_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    # Multi-Source Classification (WEB, AUTH, FIREWALL, ZEEK, SYSMON, THREAT_INTEL, OTHER)
    source_type: Mapped[Optional[str]] = mapped_column(String(32), default="WEB", index=True, nullable=True)
    source_name: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    # Network Telemetry
    source_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    source_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    connection_state: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    bytes_in: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    bytes_out: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    response_time_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # DNS Telemetry
    dns_query: Mapped[Optional[str]] = mapped_column(String(512), nullable=True, index=True)
    dns_response: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Identity, Host & Endpoint / Sysmon Fields
    username: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    process: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    parent_process: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    process_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    parent_process_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    command_line: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    image_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    file_hash: Mapped[Optional[str]] = mapped_column(String(256), nullable=True, index=True)

    # Core Event Attributes
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    event_category: Mapped[str] = mapped_column(String(80), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    message: Mapped[str] = mapped_column(Text)

    # Web Telemetry
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    request_path: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True, index=True)
    http_method: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    geo_country: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, index=True)

    # Raw Provenance
    raw_reference: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    raw_log: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    raw_log_ref = relationship("RawLog", back_populates="events")
    alert_links = relationship("AlertEvent", back_populates="event", cascade="all, delete-orphan")
