from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict


class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: Optional[int] = None
    incident_id: Optional[int] = None
    evidence_type: str
    title: str
    description: str
    data_json: dict[str, Any]
    confidence: float
    is_verified: bool
    created_at: datetime


class EvidencePackageOut(BaseModel):
    alert_id: Optional[int] = None
    incident_id: Optional[int] = None
    completeness_score: float
    total_evidence_items: int
    items: list[EvidenceOut]
