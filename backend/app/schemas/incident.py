from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict

from app.schemas.alert import AlertOut


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_number: str
    title: str
    description: str
    severity: str
    status: str
    source_ip: Optional[str] = None
    affected_user: Optional[str] = None
    correlation_key: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    alert_count: int
    event_count: int
    created_at: datetime
    updated_at: datetime


class IncidentDetail(IncidentOut):
    alerts: list[AlertOut] = []


class IncidentStatusUpdate(BaseModel):
    status: str
