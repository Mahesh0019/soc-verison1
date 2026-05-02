from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RuleBase(BaseModel):
    name: str = Field(min_length=3, max_length=160)
    description: str
    severity: str = Field(pattern="^(low|medium|high|critical)$")
    enabled: bool = True
    conditions_json: dict[str, Any]
    time_window_minutes: int = Field(default=10, ge=1, le=1440)
    threshold: int = Field(default=1, ge=1, le=10000)


class RuleCreate(RuleBase):
    pass


class RuleOut(RuleBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RuleToggle(BaseModel):
    enabled: bool

