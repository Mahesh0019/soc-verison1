from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


IndicatorType = Literal["ip", "domain", "username"]


class ThreatIndicatorBase(BaseModel):
    type: IndicatorType
    value: str = Field(min_length=1, max_length=255)
    description: str | None = None
    severity: str = Field(default="medium", pattern="^(low|medium|high|critical)$")


class ThreatIndicatorCreate(ThreatIndicatorBase):
    pass


class ThreatIndicatorOut(ThreatIndicatorBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

