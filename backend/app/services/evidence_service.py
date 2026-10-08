"""
backend/app/services/evidence_service.py

Evidence Engine: extracts, structures, stores, and evaluates evidence packages
for alerts and incidents.

Evidence Dimensions:
1. Triggering Event: Anchor event that tripped the detection threshold/pattern.
2. Related Events: Correlated supporting events within the detection window.
3. Detection Rule: The logic, thresholds, and conditions behind the detection.
4. Entity Context: Attribution to source IP, hostname, affected username, geo-location.
5. Threat Intelligence: Matches against indicators of compromise (IOCs).
6. Attack Progression / Timeline: Chronological sequence and dwell time.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models import Alert, AlertEvent, DetectionRule, Evidence, Incident, IncidentAlert, ThreatIndicator


def generate_evidence_hash(evidence_type: str, title: str, data_json: dict[str, Any]) -> str:
    """Computes a deterministic SHA-256 evidence integrity hash over canonical evidence JSON."""
    canonical_payload = json.dumps(
        {
            "evidence_type": evidence_type,
            "title": title,
            "data_json": data_json,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()



CORE_EVIDENCE_DIMENSIONS = {
    "triggering_event": 0.25,
    "related_events": 0.25,
    "detection_rule": 0.20,
    "entity_context": 0.15,
    "timeline": 0.15,
}


def calculate_evidence_completeness(evidence_items: list[Evidence]) -> float:
    """
    Computes explainable evidence completeness score (0.0 to 1.0) based on present dimensions.
    """
    if not evidence_items:
        return 0.0

    present_types = {item.evidence_type for item in evidence_items}
    score = 0.0
    for dim, weight in CORE_EVIDENCE_DIMENSIONS.items():
        if dim in present_types:
            score += weight

    # Optional bonus for threat intel or behavioral evidence
    if "threat_intel" in present_types:
        score = min(1.0, score + 0.10)
    if "behavioral" in present_types:
        score = min(1.0, score + 0.10)

    return round(score, 2)


def build_evidence_package(db: Session, alert: Alert) -> list[Evidence]:
    """
    Generates or refreshes the first-class evidence records for an alert.
    """
    existing_items = db.query(Evidence).filter(Evidence.alert_id == alert.id).all()
    if existing_items:
        for item in existing_items:
            if not item.sha256_hash:
                item.sha256_hash = generate_evidence_hash(item.evidence_type, item.title, item.data_json or {})
        return existing_items

    evidence_records: list[Evidence] = []

    # 1. Detection Rule Evidence
    rule_data: dict[str, Any] = {}
    if alert.rule:
        rule_data = {
            "rule_id": alert.rule.id,
            "rule_name": alert.rule.name,
            "rule_description": alert.rule.description,
            "severity": alert.rule.severity,
            "threshold": alert.rule.threshold,
            "time_window_minutes": alert.rule.time_window_minutes,
            "conditions_json": alert.rule.conditions_json,
        }
    else:
        rule_data = {"rule_name": alert.title, "description": alert.description}

    title1 = f"Detection Rule: {alert.rule.name if alert.rule else alert.title}"
    evidence_records.append(
        Evidence(
            alert_id=alert.id,
            evidence_type="detection_rule",
            title=title1,
            description="The security detection rule criteria and threshold that flagged this activity.",
            data_json=rule_data,
            sha256_hash=generate_evidence_hash("detection_rule", title1, rule_data),
            confidence=1.0,
            is_verified=True,
        )
    )

    # 2. Related & Triggering Events Evidence
    alert_event_links = (
        db.query(AlertEvent)
        .filter(AlertEvent.alert_id == alert.id)
        .all()
    )
    events = [link.event for link in alert_event_links if link.event]
    events_sorted = sorted(events, key=lambda e: e.timestamp)

    if events_sorted:
        anchor_event = events_sorted[-1]
        trig_title = f"Triggering Event #{anchor_event.id}"
        trig_data = {
            "event_id": anchor_event.id,
            "timestamp": anchor_event.timestamp.isoformat(),
            "source_ip": anchor_event.source_ip,
            "destination_ip": anchor_event.destination_ip,
            "username": anchor_event.username,
            "request_path": anchor_event.request_path,
            "http_method": anchor_event.http_method,
            "status_code": anchor_event.status_code,
            "user_agent": anchor_event.user_agent,
            "geo_country": anchor_event.geo_country,
            "raw_log": anchor_event.raw_log,
        }
        # Multi-Source & Network Telemetry fields (Zeek / EDR)
        if getattr(anchor_event, "source_type", None):
            trig_data["source_type"] = anchor_event.source_type
        if getattr(anchor_event, "source_port", None) is not None:
            trig_data["source_port"] = anchor_event.source_port
        if getattr(anchor_event, "destination_port", None) is not None:
            trig_data["destination_port"] = anchor_event.destination_port
        if getattr(anchor_event, "protocol", None):
            trig_data["protocol"] = anchor_event.protocol
        if getattr(anchor_event, "connection_state", None):
            trig_data["connection_state"] = anchor_event.connection_state
        if getattr(anchor_event, "bytes_in", None) is not None:
            trig_data["bytes_in"] = anchor_event.bytes_in
        if getattr(anchor_event, "bytes_out", None) is not None:
            trig_data["bytes_out"] = anchor_event.bytes_out
        if getattr(anchor_event, "response_time_ms", None) is not None:
            trig_data["response_time_ms"] = anchor_event.response_time_ms
        if getattr(anchor_event, "dns_query", None):
            trig_data["dns_query"] = anchor_event.dns_query
        if getattr(anchor_event, "dns_response", None):
            trig_data["dns_response"] = anchor_event.dns_response
        if getattr(anchor_event, "raw_reference", None):
            trig_data["raw_reference"] = anchor_event.raw_reference

        evidence_records.append(
            Evidence(
                alert_id=alert.id,
                evidence_type="triggering_event",
                title=trig_title,
                description=f"Event that tripped rule threshold: {anchor_event.message}",
                data_json=trig_data,
                sha256_hash=generate_evidence_hash("triggering_event", trig_title, trig_data),
                confidence=1.0,
                is_verified=True,
            )
        )

        rel_title = f"Supporting Events ({len(events_sorted)} Total)"
        rel_data = {
            "total_count": len(events_sorted),
            "event_ids": [e.id for e in events_sorted],
            "sample_messages": [e.message for e in events_sorted[:10]],
        }
        # Include distinct ports and Zeek UIDs if present
        dest_ports = [e.destination_port for e in events_sorted if getattr(e, "destination_port", None) is not None]
        if dest_ports:
            rel_data["destination_ports"] = sorted(list(set(dest_ports)))
        protocols = [e.protocol for e in events_sorted if getattr(e, "protocol", None)]
        if protocols:
            rel_data["protocols"] = sorted(list(set(protocols)))
        raw_refs = [e.raw_reference for e in events_sorted if getattr(e, "raw_reference", None)]
        if raw_refs:
            rel_data["zeek_uids"] = raw_refs[:10]
        evidence_records.append(
            Evidence(
                alert_id=alert.id,
                evidence_type="related_events",
                title=rel_title,
                description=f"{len(events_sorted)} correlated telemetry events linked to this alert.",
                data_json=rel_data,
                sha256_hash=generate_evidence_hash("related_events", rel_title, rel_data),
                confidence=1.0,
                is_verified=True,
            )
        )

    # 3. Entity Context Evidence
    ent_title = f"Entity Attribution: {alert.source_ip or 'No IP'}"
    ent_data = {
        "source_ip": alert.source_ip,
        "affected_user": alert.affected_user,
        "first_seen": alert.first_seen.isoformat(),
        "last_seen": alert.last_seen.isoformat(),
        "total_events": alert.event_count,
    }
    evidence_records.append(
        Evidence(
            alert_id=alert.id,
            evidence_type="entity_context",
            title=ent_title,
            description="Attributed host and user entity metadata.",
            data_json=ent_data,
            sha256_hash=generate_evidence_hash("entity_context", ent_title, ent_data),
            confidence=0.90 if alert.source_ip else 0.50,
            is_verified=True,
        )
    )

    # 4. Attack Timeline Evidence
    duration_seconds = max(0.0, (alert.last_seen - alert.first_seen).total_seconds())
    time_title = f"Activity Window ({duration_seconds:.1f}s)"
    time_data = {
        "first_seen": alert.first_seen.isoformat(),
        "last_seen": alert.last_seen.isoformat(),
        "duration_seconds": duration_seconds,
    }
    evidence_records.append(
        Evidence(
            alert_id=alert.id,
            evidence_type="timeline",
            title=time_title,
            description=f"Observed between {alert.first_seen.isoformat()} and {alert.last_seen.isoformat()}.",
            data_json=time_data,
            sha256_hash=generate_evidence_hash("timeline", time_title, time_data),
            confidence=1.0,
            is_verified=True,
        )
    )

    # 5. Threat Intelligence Check
    if alert.source_ip:
        matched_ti = db.query(ThreatIndicator).filter(
            ThreatIndicator.type == "ip",
            ThreatIndicator.value == alert.source_ip,
        ).first()
        if matched_ti:
            ti_title = f"Threat Intel Match: {matched_ti.value}"
            ti_data = {
                "indicator_id": matched_ti.id,
                "type": matched_ti.type,
                "value": matched_ti.value,
                "severity": matched_ti.severity,
                "description": matched_ti.description,
            }
            evidence_records.append(
                Evidence(
                    alert_id=alert.id,
                    evidence_type="threat_intel",
                    title=ti_title,
                    description=f"Known malicious indicator: {matched_ti.description}",
                    data_json=ti_data,
                    sha256_hash=generate_evidence_hash("threat_intel", ti_title, ti_data),
                    confidence=1.0,
                    is_verified=True,
                )
            )

    # Persist evidence records
    db.add_all(evidence_records)
    db.flush()

    return evidence_records


def build_incident_evidence_package(db: Session, incident: Incident) -> list[Evidence]:
    """
    Synthesizes and returns incident-level evidence items.
    """
    existing_items = db.query(Evidence).filter(Evidence.incident_id == incident.id).all()
    if existing_items:
        for item in existing_items:
            if not item.sha256_hash:
                item.sha256_hash = generate_evidence_hash(item.evidence_type, item.title, item.data_json or {})
        return existing_items

    incident_evidence: list[Evidence] = []

    # Incident Overview Evidence
    inc_title = f"Correlated Activity: {incident.title}"
    inc_data = {
        "incident_number": incident.incident_number,
        "correlation_key": incident.correlation_key,
        "source_ip": incident.source_ip,
        "affected_user": incident.affected_user,
        "alert_count": incident.alert_count,
        "event_count": incident.event_count,
        "severity": incident.severity,
    }
    incident_evidence.append(
        Evidence(
            incident_id=incident.id,
            evidence_type="incident_summary",
            title=inc_title,
            description=incident.description,
            data_json=inc_data,
            sha256_hash=generate_evidence_hash("incident_summary", inc_title, inc_data),
            confidence=1.0,
            is_verified=True,
        )
    )

    # Correlated Alerts Evidence
    links = db.query(IncidentAlert).filter(IncidentAlert.incident_id == incident.id).all()
    alert_ids = [l.alert_id for l in links]
    alerts = db.query(Alert).filter(Alert.id.in_(alert_ids)).all() if alert_ids else []

    corr_title = f"Component Alerts ({len(alerts)} Total)"
    corr_data = {
        "alerts": [
            {
                "alert_id": a.id,
                "title": a.title,
                "severity": a.severity,
                "event_count": a.event_count,
                "first_seen": a.first_seen.isoformat(),
            }
            for a in alerts
        ]
    }
    incident_evidence.append(
        Evidence(
            incident_id=incident.id,
            evidence_type="correlated_alerts",
            title=corr_title,
            description=f"All security alerts chained within incident {incident.incident_number}.",
            data_json=corr_data,
            sha256_hash=generate_evidence_hash("correlated_alerts", corr_title, corr_data),
            confidence=1.0,
            is_verified=True,
        )
    )

    db.add_all(incident_evidence)
    db.flush()
    return incident_evidence

