"""
backend/app/schemas/validation.py

Pydantic schemas for Phase 10 Detection Validation Engine.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class ValidationTestOut(BaseModel):
    id: int
    rule_id: int
    rule_version: str
    test_name: str
    test_scenario_id: str
    expected_result: bool
    observed_result: bool
    passed: bool
    execution_time_ms: float
    details_json: Optional[dict[str, Any]] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ValidationSuiteRunResponse(BaseModel):
    total_tests: int
    passed_tests: int
    failed_tests: int
    pass_rate: float
    execution_time_ms_total: float
    results: list[ValidationTestOut]


class RuleHealthMetric(BaseModel):
    rule_id: int
    rule_name: str
    total_tests: int
    passed_tests: int
    pass_rate: float
    status: str


class ValidationSummaryOut(BaseModel):
    total_runs: int
    overall_pass_rate: float
    total_passed: int
    total_failed: int
    rules_tested_count: int
    rule_health: list[RuleHealthMetric]


class CustomValidationTestRequest(BaseModel):
    rule_id: int = Field(..., description="Target DetectionRule ID")
    test_name: str = Field(..., description="Descriptive test name")
    test_scenario_id: str = Field(..., description="Scenario identifier e.g. SCENARIO-CUSTOM-01")
    expected_result: bool = Field(..., description="True if alert expected, False if benign")
    events_data: list[dict[str, Any]] = Field(..., description="Raw or normalized event dictionaries for test scenario")
