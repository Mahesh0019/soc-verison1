"""
backend/app/api/threat_hunting.py

Phase 9: Threat Hunting & Closed-Loop Detection Engineering API Routes.
Enforces:
- Parameterized SQL execution
- Role-Based Access Control (RBAC)
- Cross-incident data isolation
- Query bounding (result size and time range)
- Validation gate enforcement
- Immutable rule versioning
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user, require_roles
from app.database.session import get_db
from app.models import CandidateRule, DetectionGap, ThreatHunt, User
from app.schemas.threat_hunting import (
    CandidateRuleCreate,
    CandidateRuleOut,
    CandidateRuleTransitionRequest,
    DetectionCoverageMatrixResponse,
    DetectionGapCreate,
    DetectionGapOut,
    HuntExecutionResponse,
    ThreatHuntCreate,
    ThreatHuntOut,
    ThreatHuntUpdate,
)
from app.services.threat_hunting_service import (
    build_detection_coverage_matrix,
    compute_hunt_quality_metrics,
    ensure_builtin_hunts,
    evaluate_regression_impact,
    execute_hunt_query,
    generate_candidate_rule,
    identify_detection_gap,
    transition_rule_lifecycle,
    validate_candidate_rule,
)

router = APIRouter(prefix="/threat-hunting", tags=["threat-hunting"])


@router.get("/hunts", response_model=list[ThreatHuntOut])
def list_threat_hunts(
    status_filter: Optional[str] = Query(None, alias="status"),
    current_user: User = Depends(require_roles("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
) -> list[ThreatHunt]:
    """Lists threat hunts, auto-seeding standard HUNT-001 through HUNT-010 if table is empty."""
    hunts = ensure_builtin_hunts(db)
    if status_filter:
        hunts = [h for h in hunts if h.status.upper() == status_filter.upper()]
    return hunts


@router.post("/hunts", response_model=ThreatHuntOut, status_code=status.HTTP_201_CREATED)
def create_threat_hunt(
    payload: ThreatHuntCreate,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
) -> ThreatHunt:
    """Creates a new threat hunt scenario."""
    hunt_count = db.query(ThreatHunt).count()
    hunt_id = f"HUNT-{hunt_count + 1:03d}"

    hunt = ThreatHunt(
        hunt_id=hunt_id,
        title=payload.title,
        hypothesis=payload.hypothesis,
        analyst=current_user.username,
        time_range_start=payload.time_range_start,
        time_range_end=payload.time_range_end,
        data_sources_json=payload.data_sources,
        query_filter_json=payload.query_filter,
        expected_behavior=payload.expected_behavior,
        result="INCONCLUSIVE",
        confidence=0.50,
        classification="FALSE_LEAD",
        status="OPEN",
    )
    db.add(hunt)
    db.commit()
    db.refresh(hunt)
    return hunt


@router.get("/hunts/{hunt_id}", response_model=ThreatHuntOut)
def get_threat_hunt(
    hunt_id: str,
    current_user: User = Depends(require_roles("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
) -> ThreatHunt:
    """Retrieves a single threat hunt by ID."""
    hunt = db.query(ThreatHunt).filter(ThreatHunt.hunt_id == hunt_id).first()
    if not hunt:
        raise HTTPException(status_code=404, detail=f"Hunt '{hunt_id}' not found.")
    return hunt


@router.post("/hunts/{hunt_id}/execute", response_model=HuntExecutionResponse)
def execute_threat_hunt(
    hunt_id: str,
    override_filters: Optional[dict[str, Any]] = None,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Executes a parameterized hunt query with bounding and result classification."""
    hunt = db.query(ThreatHunt).filter(ThreatHunt.hunt_id == hunt_id).first()
    if not hunt:
        raise HTTPException(status_code=404, detail=f"Hunt '{hunt_id}' not found.")

    res = execute_hunt_query(
        db=db,
        hunt=hunt,
        override_filters=override_filters,
        analyst_role=current_user.role,
    )
    return res


@router.post("/hunts/{hunt_id}/generate-gap", response_model=DetectionGapOut)
def generate_detection_gap_from_hunt(
    hunt_id: str,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
) -> DetectionGap:
    """Generates a formal DetectionGap record from a hunt with observed gaps."""
    hunt = db.query(ThreatHunt).filter(ThreatHunt.hunt_id == hunt_id).first()
    if not hunt:
        raise HTTPException(status_code=404, detail=f"Hunt '{hunt_id}' not found.")

    gap = identify_detection_gap(db=db, hunt=hunt, analyst_role=current_user.role)
    return gap


@router.get("/gaps", response_model=list[DetectionGapOut])
def list_detection_gaps(
    current_user: User = Depends(require_roles("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
) -> list[DetectionGap]:
    """Lists all identified detection gaps."""
    return db.query(DetectionGap).order_by(DetectionGap.created_at.desc()).all()


@router.get("/gaps/{gap_id}", response_model=DetectionGapOut)
def get_detection_gap(
    gap_id: str,
    current_user: User = Depends(require_roles("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
) -> DetectionGap:
    """Retrieves a specific detection gap by ID."""
    gap = db.query(DetectionGap).filter(DetectionGap.gap_id == gap_id).first()
    if not gap:
        raise HTTPException(status_code=404, detail=f"Detection gap '{gap_id}' not found.")
    return gap


@router.post("/gaps/{gap_id}/generate-candidate", response_model=CandidateRuleOut)
def generate_candidate_rule_from_gap(
    gap_id: str,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
) -> CandidateRule:
    """Generates a candidate rule in status DRAFT from an identified gap."""
    gap = db.query(DetectionGap).filter(DetectionGap.gap_id == gap_id).first()
    if not gap:
        raise HTTPException(status_code=404, detail=f"Detection gap '{gap_id}' not found.")

    cand = generate_candidate_rule(db=db, gap=gap, author=current_user.username)
    return cand


@router.get("/candidates", response_model=list[CandidateRuleOut])
def list_candidate_rules(
    status_filter: Optional[str] = Query(None, alias="status"),
    current_user: User = Depends(require_roles("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
) -> list[CandidateRule]:
    """Lists candidate rules across lifecycle states (DRAFT, TESTING, VALIDATING, ACTIVE, DEPRECATED)."""
    query = db.query(CandidateRule)
    if status_filter:
        query = query.filter(CandidateRule.status == status_filter.upper())
    return query.order_by(CandidateRule.created_at.desc()).all()


@router.get("/candidates/{candidate_id}", response_model=CandidateRuleOut)
def get_candidate_rule(
    candidate_id: str,
    current_user: User = Depends(require_roles("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
) -> CandidateRule:
    """Retrieves details of a candidate detection rule."""
    cand = db.query(CandidateRule).filter(CandidateRule.candidate_rule_id == candidate_id).first()
    if not cand:
        raise HTTPException(status_code=404, detail=f"Candidate rule '{candidate_id}' not found.")
    return cand


@router.post("/candidates/{candidate_id}/validate", response_model=dict[str, Any])
def validate_candidate_rule_gate(
    candidate_id: str,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Runs Quality Gate validation assertions on a candidate rule."""
    cand = db.query(CandidateRule).filter(CandidateRule.candidate_rule_id == candidate_id).first()
    if not cand:
        raise HTTPException(status_code=404, detail=f"Candidate rule '{candidate_id}' not found.")

    res = validate_candidate_rule(candidate=cand, db=db)
    return res


@router.post("/candidates/{candidate_id}/regression-check", response_model=dict[str, Any])
def run_candidate_rule_regression(
    candidate_id: str,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Runs regression evaluation on a candidate rule against historical benchmarks."""
    cand = db.query(CandidateRule).filter(CandidateRule.candidate_rule_id == candidate_id).first()
    if not cand:
        raise HTTPException(status_code=404, detail=f"Candidate rule '{candidate_id}' not found.")

    rec = evaluate_regression_impact(candidate=cand, db=db)
    return {
        "candidate_rule_id": cand.candidate_rule_id,
        "status": rec.status,
        "tp_delta": rec.tp_delta,
        "fp_delta": rec.fp_delta,
        "fn_delta": rec.fn_delta,
        "tn_delta": rec.tn_delta,
        "f1_delta": rec.f1_delta,
        "fpr_delta": rec.fpr_delta,
        "latency_delta_ms": rec.latency_delta_ms,
        "tradeoff_notes": rec.tradeoff_notes,
        "target_datasets": rec.target_datasets_json,
    }


@router.post("/candidates/{candidate_id}/transition", response_model=CandidateRuleOut)
def transition_candidate_lifecycle(
    candidate_id: str,
    payload: CandidateRuleTransitionRequest,
    current_user: User = Depends(require_roles("admin", "analyst")),
    db: Session = Depends(get_db),
) -> CandidateRule:
    """Transitions candidate rule through lifecycle states with validation prerequisites enforced."""
    cand = db.query(CandidateRule).filter(CandidateRule.candidate_rule_id == candidate_id).first()
    if not cand:
        raise HTTPException(status_code=404, detail=f"Candidate rule '{candidate_id}' not found.")

    try:
        updated = transition_rule_lifecycle(
            db=db,
            candidate=cand,
            target_status=payload.target_status,
            change_reason=payload.change_reason,
            author=current_user.username,
        )
        return updated
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/coverage-matrix", response_model=DetectionCoverageMatrixResponse)
def get_detection_coverage_matrix(
    current_user: User = Depends(require_roles("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Returns the MITRE ATT&CK and Behavioral Detection Coverage Matrix."""
    return build_detection_coverage_matrix(db)


@router.get("/metrics", response_model=dict[str, Any])
def get_threat_hunting_metrics(
    current_user: User = Depends(require_roles("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Returns hunt quality and lifecycle metrics (Hunt Precision, Gap Yield, Acceptance Rate, etc.)."""
    return compute_hunt_quality_metrics(db)
