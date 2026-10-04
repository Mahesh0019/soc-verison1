from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict


class RiskAssessmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: Optional[int] = None
    incident_id: Optional[int] = None
    risk_score: float
    risk_level: str
    impact_score: float
    likelihood_score: float
    asset_criticality: str
    justification: str
    factors_json: dict[str, Any]
    created_at: datetime


class RiskSummaryOut(BaseModel):
    average_risk_score: float
    risk_tier_counts: dict[str, int]
    highest_risk_items: list[dict[str, Any]]
