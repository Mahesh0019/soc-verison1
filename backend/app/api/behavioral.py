"""
backend/app/api/behavioral.py

REST API Endpoints for Behavioral ML Anomaly Detection (Phase 7):
- GET /api/behavioral/status: ML model status and baseline metrics
- POST /api/behavioral/train: Trigger Isolation Forest training on historical/windowed telemetry
- GET /api/behavioral/score/ip/{ip_address}: Anomaly score & feature explainability for an IP
- GET /api/behavioral/score/alert/{alert_id}: Anomaly score & feature breakdown for an alert
- GET /api/behavioral/anomalies: List recent anomalous entities
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user, require_roles
from app.database.session import get_db
from app.models import Alert, User
from app.schemas.behavioral import (
    BehavioralAnomalyResult,
    ModelStatusResponse,
    ModelTrainingRequest,
    ModelTrainingResponse,
)
from app.services.ml_anomaly_service import (
    FEATURE_NAMES,
    get_behavioral_detector,
    get_recent_behavioral_anomalies,
    score_alert_behavior,
    score_ip_behavior,
    train_behavioral_model_from_db,
)


router = APIRouter(prefix="/behavioral", tags=["Behavioral ML Anomaly"])


@router.get("/status", response_model=ModelStatusResponse)
def get_model_status(
    current_user: User = Depends(get_current_user),
) -> ModelStatusResponse:
    """Returns the operational status, sample statistics, and baseline of the Isolation Forest detector."""
    detector = get_behavioral_detector()
    return ModelStatusResponse(
        is_fitted=detector.is_fitted,
        model_name="IsolationForest (scikit-learn)",
        sample_count=detector.sample_count,
        feature_names=detector.feature_names,
        last_trained=detector.last_trained,
        baseline_averages=detector.baseline_means,
    )


@router.post("/train", response_model=ModelTrainingResponse)
def train_model(
    payload: ModelTrainingRequest = ModelTrainingRequest(),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> ModelTrainingResponse:
    """Trains or retrains the Isolation Forest model on historical telemetry."""
    result = train_behavioral_model_from_db(
        db,
        window_minutes=payload.window_minutes or 1440,
        contamination=payload.contamination or 0.08,
    )
    if not result.get("success", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("reason", "Training failed"),
        )
    return ModelTrainingResponse(
        success=True,
        sample_count=result["sample_count"],
        feature_dimensions=result["feature_dimensions"],
        contamination=result["contamination"],
        trained_at=result["trained_at"],
        message=f"Isolation Forest successfully trained on {result['sample_count']} behavioral profiles.",
    )


@router.get("/score/ip/{ip_address}", response_model=BehavioralAnomalyResult)
def score_ip(
    ip_address: str,
    window_minutes: int = Query(60, ge=1, le=10080),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> BehavioralAnomalyResult:
    """Scores an IP address for behavioral anomaly using the Isolation Forest engine."""
    result = score_ip_behavior(db, ip_address, window_minutes=window_minutes)
    return BehavioralAnomalyResult(**result)


@router.get("/score/alert/{alert_id}", response_model=BehavioralAnomalyResult)
def score_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> BehavioralAnomalyResult:
    """Scores the behavioral activity associated with a specific alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    result = score_alert_behavior(db, alert)
    return BehavioralAnomalyResult(**result)


@router.get("/anomalies", response_model=list[BehavioralAnomalyResult])
def list_anomalies(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[BehavioralAnomalyResult]:
    """Retrieves ranked anomalous entities identified across active network telemetry."""
    anomalies = get_recent_behavioral_anomalies(db, limit=limit)
    return [BehavioralAnomalyResult(**a) for a in anomalies]
