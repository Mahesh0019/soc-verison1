from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field


T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=200)


class Message(BaseModel):
    message: str


class DashboardSeriesPoint(BaseModel):
    label: str
    value: int


class DashboardSummary(BaseModel):
    total_events: int
    total_alerts: int
    open_critical_alerts: int
    events_over_time: list[DashboardSeriesPoint]
    alerts_by_severity: list[DashboardSeriesPoint]
    top_source_ips: list[DashboardSeriesPoint]
    top_usernames: list[DashboardSeriesPoint]
    top_event_types: list[DashboardSeriesPoint]
    event_category_distribution: list[DashboardSeriesPoint]
    alert_status_distribution: list[DashboardSeriesPoint]
    login_trends: list[dict[str, Any]]
    recent_alerts: list[Any]

