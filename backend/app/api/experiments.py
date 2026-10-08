"""
backend/app/api/experiments.py

REST API Endpoints for Phase 11 Research & Evaluation Engine:
- POST /api/experiments: Create/register an experiment record
- GET /api/experiments: List experiments (paginated)
- GET /api/experiments/{id}: Get detailed experiment record with runs and metrics
- POST /api/experiments/run: Execute an experiment run (single mode M0-M6 or ALL for full benchmark suite)
- GET /api/experiments/benchmark/matrix: Direct endpoint returning the M0-M6 benchmark comparison matrix
- GET /api/experiments/benchmark/latest: Retrieve latest completed benchmark comparison
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.utils import paginate
from app.auth.dependencies import get_current_user, require_roles
from app.database.session import get_db
from app.models import User
from app.models.experiment import Experiment
from app.schemas.common import Page
from app.schemas.experiment import (
    BenchmarkComparisonResponse,
    ExperimentCreate,
    ExperimentOut,
    RunExperimentRequest,
)
from app.services.experiment_service import (
    get_experiment_by_id,
    get_latest_benchmark,
    list_experiments,
    run_full_benchmark,
    run_single_mode_experiment,
)

router = APIRouter(prefix="/experiments", tags=["Research & Evaluation Engine"])


@router.post("", response_model=ExperimentOut, status_code=status.HTTP_201_CREATED)
def create_experiment(
    payload: ExperimentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> Experiment:
    """Register a new research experiment record."""
    exp = Experiment(
        name=payload.name,
        description=payload.description or "",
        mode=payload.mode.upper(),
        dataset_version=payload.dataset_version,
        status="PENDING",
    )
    db.add(exp)
    db.commit()
    db.refresh(exp)
    return exp


@router.get("", response_model=Page[ExperimentOut])
def get_all_experiments(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Page[ExperimentOut]:
    """List recorded research and benchmark experiments."""
    query = db.query(Experiment).order_by(Experiment.id.desc())
    items, total = paginate(query, page=page, page_size=page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/benchmark/matrix", response_model=BenchmarkComparisonResponse)
def get_benchmark_comparison_matrix(
    dataset_version: str = Query(default="v1.0"),
    force_run: bool = Query(default=False),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> BenchmarkComparisonResponse:
    """
    Returns the comprehensive M0–M6 benchmark comparison matrix.
    If no benchmark has been executed yet (or force_run=True), executes one automatically.
    """
    if not force_run:
        latest = get_latest_benchmark(db)
        if latest:
            return latest

    # If no benchmark run exists yet or force_run is True, run the full benchmark
    return run_full_benchmark(db, dataset_version=dataset_version)


@router.get("/benchmark/latest", response_model=BenchmarkComparisonResponse)
def get_latest_benchmark_result(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> BenchmarkComparisonResponse:
    """Retrieve the latest completed M0–M6 benchmark comparison."""
    latest = get_latest_benchmark(db)
    if not latest:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No completed benchmark run found. Run /api/experiments/run or /api/experiments/benchmark/matrix first.",
        )
    return latest


@router.post("/run", response_model=BenchmarkComparisonResponse)
def execute_experiment_run(
    payload: RunExperimentRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> BenchmarkComparisonResponse:
    """
    Execute an experiment run:
    - If mode is 'ALL' or 'BENCHMARK', executes the full M0 through M6 comparative suite.
    - If mode is a specific operational mode (M0, M1, M2, M3, M4, M5, or M6), simulates that mode.
    """
    target_mode = payload.mode.upper().strip()
    if target_mode in ["ALL", "BENCHMARK"]:
        return run_full_benchmark(
            db,
            dataset_version=payload.dataset_version,
            experiment_name=payload.experiment_name,
            description=payload.description,
        )
    elif target_mode in ["M0", "M1", "M2", "M3", "M4", "M5", "M6"]:
        return run_single_mode_experiment(
            db,
            mode=target_mode,
            dataset_version=payload.dataset_version,
            experiment_name=payload.experiment_name,
            description=payload.description,
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid operational mode: '{payload.mode}'. Must be one of M0, M1, M2, M3, M4, M5, M6, or ALL.",
        )


@router.get("/{experiment_id}", response_model=ExperimentOut)
def get_experiment_details(
    experiment_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Experiment:
    """Fetch an experiment by ID with all associated runs and metric series."""
    exp = get_experiment_by_id(db, experiment_id)
    if not exp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Experiment with ID {experiment_id} not found.",
        )
    return exp


@router.get("/adversarial/robustness")
def get_adversarial_robustness_evaluation(
    current_user: User = Depends(get_current_user),
) -> dict:
    """Retrieve Phase 7 Adversarial Robustness evaluation results and curves."""
    from pathlib import Path
    candidates = [
        Path(__file__).resolve().parent.parent.parent.parent / "research" / "results" / "adversarial_robustness_v1.json",
        Path(__file__).resolve().parent.parent.parent / "research" / "results" / "adversarial_robustness_v1.json",
        Path.cwd() / "research" / "results" / "adversarial_robustness_v1.json",
        Path("/app/research/results/adversarial_robustness_v1.json"),
    ]
    results_path = next((p for p in candidates if p.exists()), candidates[0])
    if not results_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Adversarial robustness evaluation results not found.",
        )
    return json.loads(results_path.read_text(encoding="utf-8"))

