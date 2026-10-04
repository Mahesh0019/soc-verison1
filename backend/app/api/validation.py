"""
backend/app/api/validation.py

REST API Endpoints for Detection Validation Engine (Phase 10):
- POST /api/validation/run-all: Trigger regression test suite across all active rules
- POST /api/validation/run-rule/{rule_id}: Run validation tests for a specific rule
- GET /api/validation/results: List validation test results
- GET /api/validation/results/{test_id}: Get specific validation test record
- GET /api/validation/summary: Get rule regression health and pass rate metrics
- POST /api/validation/custom-test: Run custom scenario assertion on a rule
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.utils import paginate
from app.auth.dependencies import get_current_user, require_roles
from app.database.session import get_db
from app.models import DetectionRule, User, ValidationTest
from app.schemas.common import Page
from app.schemas.validation import (
    CustomValidationTestRequest,
    ValidationSuiteRunResponse,
    ValidationSummaryOut,
    ValidationTestOut,
)
from app.services.validation_service import (
    get_validation_summary,
    run_all_validation_tests,
    run_rule_validation_suite,
    run_validation_test,
)


router = APIRouter(prefix="/validation", tags=["Detection Validation Engine"])


@router.post("/run-all", response_model=ValidationSuiteRunResponse)
def execute_all_validations(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> ValidationSuiteRunResponse:
    """Executes the full automated regression test suite across all active DetectionRules."""
    data = run_all_validation_tests(db)
    return ValidationSuiteRunResponse(**data)


@router.post("/run-rule/{rule_id}", response_model=ValidationSuiteRunResponse)
def execute_rule_validation(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> ValidationSuiteRunResponse:
    """Executes targeted positive and negative regression tests for a specific rule."""
    try:
        suite = run_rule_validation_suite(db, rule_id)
        return ValidationSuiteRunResponse(
            total_tests=suite["total_tests"],
            passed_tests=suite["passed_tests"],
            failed_tests=suite["failed_tests"],
            pass_rate=suite["pass_rate"],
            execution_time_ms_total=round(sum(r.execution_time_ms for r in suite["results"]), 2),
            results=suite["results"],
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/results", response_model=Page[ValidationTestOut])
def list_validation_results(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    rule_id: Optional[int] = None,
    passed: Optional[bool] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Lists historical detection rule validation test runs."""
    query = db.query(ValidationTest)
    if rule_id is not None:
        query = query.filter(ValidationTest.rule_id == rule_id)
    if passed is not None:
        query = query.filter(ValidationTest.passed.is_(passed))
    query = query.order_by(ValidationTest.created_at.desc())
    items, total = paginate(query, page, page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/summary", response_model=ValidationSummaryOut)
def get_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ValidationSummaryOut:
    """Retrieves overall pass rate, test counts, and rule regression health status."""
    data = get_validation_summary(db)
    return ValidationSummaryOut(**data)


@router.get("/results/{test_id}", response_model=ValidationTestOut)
def get_validation_detail(
    test_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ValidationTest:
    """Retrieves details of a specific validation test run."""
    record = db.query(ValidationTest).filter(ValidationTest.id == test_id).first()
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Validation test not found")
    return record


@router.post("/custom-test", response_model=ValidationTestOut, status_code=status.HTTP_201_CREATED)
def run_custom_test(
    payload: CustomValidationTestRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> ValidationTest:
    """Runs a custom dynamic assertion scenario against a DetectionRule."""
    rule = db.query(DetectionRule).filter(DetectionRule.id == payload.rule_id).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target DetectionRule not found")

    scenario = {
        "scenario_id": payload.test_scenario_id,
        "test_name": payload.test_name,
        "expected_result": payload.expected_result,
        "events": payload.events_data,
    }
    result = run_validation_test(db, rule, scenario)
    return result
