from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict

from app.schemas.user import UserOut


class CaseCreate(BaseModel):
    title: str
    description: str
    priority: str = "MEDIUM"
    assigned_analyst_id: Optional[int] = None
    alert_id: Optional[int] = None
    incident_id: Optional[int] = None


class CaseUpdate(BaseModel):
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_analyst_id: Optional[int] = None
    resolution_summary: Optional[str] = None


class CaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_number: str
    title: str
    description: str
    status: str
    priority: str
    assigned_analyst_id: Optional[int] = None
    incident_id: Optional[int] = None
    alert_id: Optional[int] = None
    resolution_summary: Optional[str] = None
    closed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    assigned_analyst: Optional[UserOut] = None


class ControlledResponseRequest(BaseModel):
    action_type: str  # SIMULATE_CONTAINMENT, ADD_WATCHLIST_INDICATOR, ACKNOWLEDGE_INCIDENT
    target_value: str
    case_id: Optional[int] = None
    confirmation_notes: Optional[str] = None
    confirm: bool = False  # Explicit confirmation required


class ControlledResponseResult(BaseModel):
    success: bool
    audit_id: int
    action: str
    target: str
    status: str
    simulated: bool
    executed_by: str
    timestamp: str
    message: Optional[str] = None
    confirmation_notes: Optional[str] = None
