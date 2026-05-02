from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.event import EventOut
from app.schemas.user import UserOut


AlertStatus = Literal["open", "investigating", "resolved", "false_positive"]


class AlertOut(BaseModel):
    id: int
    rule_id: int | None
    title: str
    description: str
    severity: str
    status: str
    source_ip: str | None
    affected_user: str | None
    first_seen: datetime
    last_seen: datetime
    event_count: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertStatusUpdate(BaseModel):
    status: AlertStatus


class AlertNoteCreate(BaseModel):
    note: str = Field(min_length=2, max_length=4000)


class AlertNoteOut(BaseModel):
    id: int
    user_id: int | None
    note: str
    created_at: datetime
    user: UserOut | None = None

    model_config = ConfigDict(from_attributes=True)


class AlertDetail(AlertOut):
    related_events: list[EventOut]
    notes: list[AlertNoteOut]

