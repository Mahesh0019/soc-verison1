"""
backend/app/rules/correlation.py

Event and Alert Correlation Engine
Groups related alerts and normalized events into meaningful multi-stage incident activity chains.

Correlation factors:
- Shared entity: source IP and/or username
- Sliding time window (default 45 minutes)
- Multi-stage attack progression (reconnaissance -> probing -> exploitation -> credential testing -> C2/threat intel)
- Deduplication: updates existing active incidents rather than creating redundant incidents
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import Alert, Incident, IncidentAlert


SEVERITY_WEIGHTS = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

ATTACK_STAGES = {
    "reconnaissance": [
        "suspicious user agent",
        "high number of 404 responses",
        "large request volume burst",
    ],
    "probing": [
        "possible directory brute force",
        "repeated sensitive path access",
        "login attempt from unusual country",
    ],
    "exploitation": [
        "sql injection attempt detected",
        "path traversal attempt detected",
        "cross-site scripting probe detected",
    ],
    "credential_testing": [
        "multiple failed login attempts from same ip",
        "successful login after failed attempts",
        "suspicious admin login",
    ],
    "c2_lateral_movement": [
        "firewall denied traffic spike",
        "repeated access from blacklisted indicator",
        "blacklisted indicator matched",
    ],
}


def classify_alert_stage(alert_title: str) -> str:
    title_lower = alert_title.lower()
    for stage, patterns in ATTACK_STAGES.items():
        if any(p in title_lower for p in patterns):
            return stage
    return "general_suspicious"


def calculate_correlation_metrics(alerts: list[Alert]) -> dict[str, Any]:
    """
    Computes correlation strength and stage progression across grouped alerts.
    """
    if not alerts:
        return {
            "correlation_strength": 0.0,
            "stages_observed": [],
            "stage_count": 0,
            "highest_severity": "low",
        }

    stages_set = {classify_alert_stage(a.title) for a in alerts}
    stages_observed = sorted(stages_set)

    # Determine highest severity
    highest_severity = "low"
    max_weight = 0
    for a in alerts:
        weight = SEVERITY_WEIGHTS.get(a.severity.lower(), 1)
        if weight > max_weight:
            max_weight = weight
            highest_severity = a.severity.lower()

    # Correlation strength formula:
    # 0.40 baseline for entity match + 0.35 * (unique stages / 4 cap) + 0.25 * (alert count / 5 cap)
    stage_factor = min(len(stages_observed) / 4.0, 1.0)
    volume_factor = min(len(alerts) / 5.0, 1.0)
    strength = min(1.0, 0.40 + (0.35 * stage_factor) + (0.25 * volume_factor))

    return {
        "correlation_strength": round(strength, 2),
        "stages_observed": stages_observed,
        "stage_count": len(stages_observed),
        "highest_severity": highest_severity,
    }


def next_incident_number(db: Session) -> str:
    """Generates the next sequential INC-xxx identifier."""
    count = db.query(func.count(Incident.id)).scalar() or 0
    return f"INC-{(count + 1):03d}"


def correlate_incidents(
    db: Session,
    touched_alert_ids: set[int],
    window_minutes: int = 45,
) -> list[Incident]:
    """
    Takes a set of alert IDs, correlates them by entity and time window,
    and upserts Incident records with multi-stage attack timelines.
    """
    if not touched_alert_ids:
        return []

    alerts = db.query(Alert).filter(Alert.id.in_(touched_alert_ids)).all()
    affected_incidents: dict[int, Incident] = {}

    for alert in alerts:
        source_ip = alert.source_ip
        affected_user = alert.affected_user

        # Build correlation key (prefer IP, fallback to user)
        if source_ip and source_ip not in ("0.0.0.0", "127.0.0.1", ""):
            corr_key = f"ip:{source_ip}"
        elif affected_user:
            corr_key = f"user:{affected_user.lower()}"
        else:
            corr_key = f"alert:{alert.id}"

        window_start = alert.first_seen - timedelta(minutes=window_minutes)

        # Look for existing open/investigating incident matching this key within the sliding window
        incident = (
            db.query(Incident)
            .filter(
                Incident.correlation_key == corr_key,
                Incident.status.in_(["open", "investigating"]),
                Incident.last_seen >= window_start,
            )
            .order_by(Incident.last_seen.desc())
            .first()
        )

        first_seen_aware = alert.first_seen
        last_seen_aware = alert.last_seen

        if incident:
            # Check if alert is already linked
            already_linked = (
                db.query(IncidentAlert)
                .filter(
                    IncidentAlert.incident_id == incident.id,
                    IncidentAlert.alert_id == alert.id,
                )
                .first()
            )
            if not already_linked:
                db.add(IncidentAlert(incident_id=incident.id, alert_id=alert.id))
                db.flush()

            # Extend timestamps
            from app.services.correlation_service import ensure_utc
            if ensure_utc(first_seen_aware) < ensure_utc(incident.first_seen):
                incident.first_seen = first_seen_aware
            if ensure_utc(last_seen_aware) > ensure_utc(incident.last_seen):
                incident.last_seen = last_seen_aware

            # Update metrics from linked alerts
            linked_alerts = (
                db.query(Alert)
                .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
                .filter(IncidentAlert.incident_id == incident.id)
                .all()
            )

            metrics = calculate_correlation_metrics(linked_alerts)
            incident.alert_count = len(linked_alerts)
            incident.event_count = sum(a.event_count for a in linked_alerts)
            incident.severity = metrics["highest_severity"]

            stages_str = " -> ".join(s.replace("_", " ").title() for s in metrics["stages_observed"])
            incident.description = (
                f"Multi-stage activity chain from {source_ip or affected_user or 'unknown entity'}. "
                f"Observed stages: {stages_str} (correlation strength: {metrics['correlation_strength']})."
            )

            affected_incidents[incident.id] = incident

        else:
            # Create a new Incident
            inc_number = next_incident_number(db)
            metrics = calculate_correlation_metrics([alert])
            stage_name = classify_alert_stage(alert.title).replace("_", " ").title()

            title_entity = f"from {source_ip}" if source_ip else f"for {affected_user}" if affected_user else "Activity"
            incident_title = f"Suspicious Security Incident {title_entity} [{stage_name}]"
            incident_desc = (
                f"Correlated security activity {title_entity}. "
                f"Initial detection: {alert.title} (severity: {alert.severity})."
            )

            new_incident = Incident(
                incident_number=inc_number,
                title=incident_title[:255],
                description=incident_desc,
                severity=alert.severity,
                status="open",
                source_ip=source_ip,
                affected_user=affected_user,
                correlation_key=corr_key,
                first_seen=first_seen_aware,
                last_seen=last_seen_aware,
                alert_count=1,
                event_count=alert.event_count,
            )
            db.add(new_incident)
            db.flush()

            db.add(IncidentAlert(incident_id=new_incident.id, alert_id=alert.id))
            db.flush()

            affected_incidents[new_incident.id] = new_incident

    # Enrich affected incidents with Phase 6 Unified timeline, graph, and explainable scores
    from app.models import AlertEvent, NormalizedEvent
    from app.services.correlation_service import (
        build_incident_graph,
        build_incident_timeline,
        calculate_explainable_correlation_score,
        evaluate_correlation_rules,
    )

    for inc in affected_incidents.values():
        linked_alerts = (
            db.query(Alert)
            .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
            .filter(IncidentAlert.incident_id == inc.id)
            .all()
        )
        linked_alert_ids = [a.id for a in linked_alerts]
        linked_events = (
            db.query(NormalizedEvent)
            .join(AlertEvent, AlertEvent.event_id == NormalizedEvent.id)
            .filter(AlertEvent.alert_id.in_(linked_alert_ids))
            .all()
        ) if linked_alert_ids else []

        if not inc.primary_entity:
            inc.primary_entity = f"ip:{inc.source_ip}" if inc.source_ip else f"user:{inc.affected_user}" if inc.affected_user else "entity:unspecified"

        sources = list({e.source_type.upper() for e in linked_events if e.source_type})
        inc.source_types_json = sources or ["WEB"]

        attack_status, _, _ = evaluate_correlation_rules(linked_events, window_seconds=window_minutes * 60)
        score, confidence, _ = calculate_explainable_correlation_score(linked_events, linked_alerts, window_seconds=window_minutes * 60)
        inc.correlation_score = score
        inc.confidence = confidence
        inc.attack_chain_status = attack_status
        inc.risk_score = round(min(100.0, max(20.0, score * 100.0)), 1)
        inc.timeline_json = build_incident_timeline(linked_events, linked_alerts)
        inc.graph_json = build_incident_graph(inc.id, inc.incident_number, linked_events, linked_alerts)

    return list(affected_incidents.values())
