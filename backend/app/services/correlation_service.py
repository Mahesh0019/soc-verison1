"""
backend/app/services/correlation_service.py

Phase 6: Cross-Source Telemetry Correlation & Unified Incident Reconstruction Engine.

Correlates telemetry across independent sources:
  - WEB / AUTH
  - ZEEK NETWORK TELEMETRY
  - WINDOWS SYSMON TELEMETRY

Features:
  1. Deterministic Entity Resolution (source_ip, destination_ip, hostname, username, process, raw_ref)
  2. Configurable Temporal Windows (30s, 120s, 300s default, 600s)
  3. Explicit Correlation Rules:
     - CORR-001: Web attack + same source IP + Zeek connection (CORRELATED ACTIVITY)
     - CORR-002: Web attack + same host + Sysmon process creation (POTENTIAL ATTACK CHAIN)
     - CORR-003: Zeek network anomaly + Sysmon network connection (POTENTIAL ATTACK CHAIN)
     - CORR-004: Sysmon suspicious process + Sysmon DNS + Zeek DNS/network (POTENTIAL ATTACK CHAIN)
  4. Explainable Correlation Scoring Formula with fallback to "INSUFFICIENT CORRELATION EVIDENCE"
  5. Unified Incident Reconstruction (Timeline & Incident Graph generation from stored telemetry)
  6. Tamper-evident Cross-Source Evidence creation
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
import logging
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models import (
    Alert,
    AlertEvent,
    Evidence,
    Incident,
    IncidentAlert,
    NormalizedEvent,
)

logger = logging.getLogger(__name__)

# Supported standard temporal windows in seconds
SUPPORTED_WINDOWS_SECONDS = [30, 120, 300, 600]
DEFAULT_WINDOW_SECONDS = 300

# Severity weights for scoring
SEVERITY_WEIGHT_MAP = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
}

IGNORE_IPS = {"0.0.0.0", "127.0.0.1", "::1", "localhost", ""}


def ensure_utc(dt: Optional[datetime]) -> datetime:
    """Ensures a datetime object is timezone-aware in UTC."""
    if dt is None:
        return datetime.now(UTC)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def normalize_entity_value(val: Optional[str]) -> Optional[str]:
    """Deterministically normalizes an entity identifier (lowercase, stripped)."""
    if not val:
        return None
    cleaned = val.strip().lower()
    return cleaned if cleaned else None


def extract_entities_from_event(event: NormalizedEvent) -> dict[str, Any]:
    """
    Extracts all deterministic identity entities available in the normalized event.
    Does not infer identity when telemetry does not support it.
    """
    entities: dict[str, Any] = {}

    if event.source_ip and event.source_ip not in IGNORE_IPS:
        entities["source_ip"] = event.source_ip.strip()
    if event.destination_ip and event.destination_ip not in IGNORE_IPS:
        entities["destination_ip"] = event.destination_ip.strip()

    norm_host = normalize_entity_value(event.hostname)
    if norm_host:
        entities["hostname"] = norm_host

    norm_user = normalize_entity_value(event.username)
    if norm_user:
        entities["username"] = norm_user

    norm_proc = normalize_entity_value(event.process)
    if norm_proc:
        entities["process"] = norm_proc

    if event.process_id is not None:
        entities["process_id"] = event.process_id
    if event.parent_process_id is not None:
        entities["parent_process_id"] = event.parent_process_id

    if event.dns_query:
        entities["dns_query"] = normalize_entity_value(event.dns_query)
    if event.request_path:
        entities["request_path"] = event.request_path.strip()

    # Raw reference (Zeek UID, Sysmon GUID, event ID)
    raw_ref = event.raw_reference or event.event_id
    if raw_ref:
        entities["raw_reference"] = str(raw_ref).strip()

    return entities


def extract_entities_from_alert(alert: Alert) -> dict[str, Any]:
    """Extracts deterministic entities from an alert record."""
    entities: dict[str, Any] = {}
    if alert.source_ip and alert.source_ip not in IGNORE_IPS:
        entities["source_ip"] = alert.source_ip.strip()
    if alert.affected_user:
        norm_user = normalize_entity_value(alert.affected_user)
        if norm_user:
            entities["username"] = norm_user
    return entities


def match_entities(
    ent_a: dict[str, Any],
    ent_b: dict[str, Any],
) -> list[tuple[str, str]]:
    """
    Deterministically matches entities between two event/alert representations.
    Returns list of tuples (matched_field, matched_value).
    """
    matches: list[tuple[str, str]] = []

    # Direct field comparison
    for field in ["source_ip", "destination_ip", "hostname", "username", "process", "raw_reference"]:
        val_a = ent_a.get(field)
        val_b = ent_b.get(field)
        if val_a and val_b and str(val_a).lower() == str(val_b).lower():
            matches.append((field, str(val_a)))

    # Process and process_id combo on same host
    if ent_a.get("hostname") and ent_a.get("hostname") == ent_b.get("hostname"):
        if ent_a.get("process_id") and ent_a.get("process_id") == ent_b.get("process_id"):
            matches.append(("host_and_pid", f"{ent_a['hostname']}:{ent_a['process_id']}"))

    # DNS query match
    if ent_a.get("dns_query") and ent_b.get("dns_query"):
        if str(ent_a["dns_query"]).lower() == str(ent_b["dns_query"]).lower():
            matches.append(("dns_query", str(ent_a["dns_query"])))

    # Source IP to Destination IP relationship (e.g. Zeek conn dest is Sysmon local host or vice-versa)
    if ent_a.get("source_ip") and ent_b.get("destination_ip"):
        if str(ent_a["source_ip"]) == str(ent_b["destination_ip"]):
            matches.append(("ip_route_match", f"{ent_a['source_ip']}->{ent_b['destination_ip']}"))
    if ent_b.get("source_ip") and ent_a.get("destination_ip"):
        if str(ent_b["source_ip"]) == str(ent_a["destination_ip"]):
            matches.append(("ip_route_match", f"{ent_b['source_ip']}->{ent_a['destination_ip']}"))

    return matches


def evaluate_correlation_rules(
    events: list[NormalizedEvent],
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> tuple[Optional[str], list[str], list[dict[str, Any]]]:
    """
    Evaluates explicit rules CORR-001 through CORR-004 over a group of events.
    Returns (status_label, matched_rules, explanations).
    """
    matched_rules: list[str] = []
    explanations: list[dict[str, Any]] = []

    if len(events) < 2:
        return "SINGLE_SOURCE", [], []

    # Sort events chronologically
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    source_types = {e.source_type.upper() for e in sorted_events if e.source_type}

    # Group by source type
    web_events = [e for e in sorted_events if e.source_type in ("WEB", "AUTH")]
    zeek_events = [e for e in sorted_events if e.source_type == "ZEEK"]
    sysmon_events = [e for e in sorted_events if e.source_type == "SYSMON"]

    # CORR-001: Web attack + same source IP + Zeek connection + same time window
    for w_ev in web_events:
        for z_ev in zeek_events:
            dt = abs((ensure_utc(w_ev.timestamp) - ensure_utc(z_ev.timestamp)).total_seconds())
            if dt <= window_seconds:
                # Match source IP
                if w_ev.source_ip and z_ev.source_ip and w_ev.source_ip == z_ev.source_ip and w_ev.source_ip not in IGNORE_IPS:
                    rule = "CORR-001"
                    if rule not in matched_rules:
                        matched_rules.append(rule)
                    explanations.append({
                        "rule": rule,
                        "title": "Correlated Web & Zeek Activity (Same Source IP)",
                        "matched_field": "source_ip",
                        "matched_value": w_ev.source_ip,
                        "time_delta_seconds": round(dt, 2),
                        "window_seconds": window_seconds,
                        "events": [w_ev.id, z_ev.id],
                        "summary": f"Matched source_ip={w_ev.source_ip} between Web and Zeek within {round(dt, 1)}s (window={window_seconds}s).",
                    })

    # CORR-002: Web attack + same host + Sysmon process creation
    for w_ev in web_events:
        for s_ev in sysmon_events:
            dt = abs((ensure_utc(w_ev.timestamp) - ensure_utc(s_ev.timestamp)).total_seconds())
            if dt <= window_seconds:
                host_w = normalize_entity_value(w_ev.hostname)
                host_s = normalize_entity_value(s_ev.hostname)
                if (host_w and host_s and host_w == host_s) or (w_ev.destination_ip and s_ev.source_ip and w_ev.destination_ip == s_ev.source_ip):
                    rule = "CORR-002"
                    if rule not in matched_rules:
                        matched_rules.append(rule)
                    explanations.append({
                        "rule": rule,
                        "title": "Possible Web-to-Host Attack Chain",
                        "matched_field": "hostname" if (host_w and host_w == host_s) else "ip_match",
                        "matched_value": host_w or w_ev.destination_ip,
                        "time_delta_seconds": round(dt, 2),
                        "window_seconds": window_seconds,
                        "events": [w_ev.id, s_ev.id],
                        "summary": f"Web activity preceded Sysmon process execution on host '{host_s or host_w}' within {round(dt, 1)}s.",
                    })

    # CORR-003: Zeek network anomaly + Sysmon network connection (same src/dest)
    for z_ev in zeek_events:
        for s_ev in sysmon_events:
            dt = abs((ensure_utc(z_ev.timestamp) - ensure_utc(s_ev.timestamp)).total_seconds())
            if dt <= window_seconds:
                # Compare IPs and ports
                ip_match = False
                if z_ev.destination_ip and s_ev.destination_ip and z_ev.destination_ip == s_ev.destination_ip:
                    ip_match = True
                elif z_ev.source_ip and s_ev.source_ip and z_ev.source_ip == s_ev.source_ip:
                    ip_match = True

                if ip_match:
                    rule = "CORR-003"
                    if rule not in matched_rules:
                        matched_rules.append(rule)
                    explanations.append({
                        "rule": rule,
                        "title": "Correlated Endpoint & Network Connection",
                        "matched_field": "destination_ip" if (z_ev.destination_ip == s_ev.destination_ip) else "source_ip",
                        "matched_value": z_ev.destination_ip or z_ev.source_ip,
                        "time_delta_seconds": round(dt, 2),
                        "window_seconds": window_seconds,
                        "events": [z_ev.id, s_ev.id],
                        "summary": f"Sysmon process network connection corresponds to Zeek network flow within {round(dt, 1)}s.",
                    })

    # CORR-004: Sysmon suspicious process + Sysmon DNS + Zeek DNS/network
    for s_ev in sysmon_events:
        for z_ev in zeek_events:
            dt = abs((ensure_utc(s_ev.timestamp) - ensure_utc(z_ev.timestamp)).total_seconds())
            if dt <= window_seconds:
                dns_s = normalize_entity_value(s_ev.dns_query)
                dns_z = normalize_entity_value(z_ev.dns_query)
                if dns_s and dns_z and dns_s == dns_z:
                    rule = "CORR-004"
                    if rule not in matched_rules:
                        matched_rules.append(rule)
                    explanations.append({
                        "rule": rule,
                        "title": "Correlated Endpoint DNS & Network Activity",
                        "matched_field": "dns_query",
                        "matched_value": dns_s,
                        "time_delta_seconds": round(dt, 2),
                        "window_seconds": window_seconds,
                        "events": [s_ev.id, z_ev.id],
                        "summary": f"Sysmon DNS resolution for '{dns_s}' correlates with Zeek DNS telemetry within {round(dt, 1)}s.",
                    })

    if "CORR-002" in matched_rules or "CORR-003" in matched_rules or "CORR-004" in matched_rules:
        status = "POTENTIAL ATTACK CHAIN"
    elif "CORR-001" in matched_rules or len(matched_rules) > 0:
        status = "CORRELATED ACTIVITY"
    else:
        status = "CORRELATED ACTIVITY" if len(source_types) > 1 else "SINGLE_SOURCE"

    return status, matched_rules, explanations


def calculate_explainable_correlation_score(
    events: list[NormalizedEvent],
    alerts: list[Alert],
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> tuple[float, str, dict[str, Any]]:
    """
    Computes an explainable correlation score:
      Score = (0.35 * F_entity) + (0.25 * F_time) + (0.20 * F_source) + (0.20 * F_severity)

    Returns:
      (score, confidence_string, breakdown_dict)

    If insufficient evidence exists, returns score < 0.35 with 'INSUFFICIENT CORRELATION EVIDENCE'.
    """
    if not events and not alerts:
        return 0.0, "INSUFFICIENT CORRELATION EVIDENCE", {
            "entity_factor": 0.0,
            "time_factor": 0.0,
            "source_factor": 0.0,
            "severity_factor": 0.0,
            "formula": "Score = 0.35*F_ent + 0.25*F_time + 0.20*F_src + 0.20*F_sev",
            "reason": "No events or alerts provided.",
        }

    # Extract all entity dictionaries
    entity_dicts = [extract_entities_from_event(e) for e in events]
    for a in alerts:
        entity_dicts.append(extract_entities_from_alert(a))

    # 1. Entity Match Factor (0.0 to 1.0)
    matched_pairs = 0
    total_comparisons = 0
    strong_entity_matches = 0

    for i in range(len(entity_dicts)):
        for j in range(i + 1, len(entity_dicts)):
            total_comparisons += 1
            matches = match_entities(entity_dicts[i], entity_dicts[j])
            if matches:
                matched_pairs += 1
                for field, _ in matches:
                    if field in ("source_ip", "destination_ip", "hostname", "process", "host_and_pid"):
                        strong_entity_matches += 1

    if total_comparisons == 0:
        f_entity = 0.5  # single item
    else:
        match_ratio = matched_pairs / max(total_comparisons, 1)
        if strong_entity_matches >= 2:
            f_entity = min(1.0, 0.70 + 0.30 * match_ratio)
        elif strong_entity_matches == 1:
            f_entity = min(0.85, 0.50 + 0.35 * match_ratio)
        elif matched_pairs > 0:
            f_entity = 0.50
        else:
            f_entity = 0.10

    # 2. Time Proximity Factor (0.0 to 1.0)
    timestamps = [ensure_utc(e.timestamp) for e in events] + [ensure_utc(a.first_seen) for a in alerts]
    if len(timestamps) >= 2:
        earliest = min(timestamps)
        latest = max(timestamps)
        span_seconds = abs((latest - earliest).total_seconds())
        # Proximity decay: 1.0 at dt=0, down to 0.0 at span_seconds >= window_seconds
        f_time = max(0.0, min(1.0, 1.0 - (span_seconds / max(float(window_seconds), 1.0))))
    else:
        span_seconds = 0.0
        f_time = 0.70

    # 3. Source Diversity Factor (0.0 to 1.0)
    sources = set()
    for e in events:
        if e.source_type:
            sources.add(e.source_type.upper())
    num_sources = len(sources)
    if num_sources >= 3:
        f_source = 1.0
    elif num_sources == 2:
        f_source = 0.75
    elif num_sources == 1:
        f_source = 0.40
    else:
        f_source = 0.20

    # 4. Severity Factor (0.0 to 1.0)
    severities = [a.severity.lower() for a in alerts] + [e.severity.lower() for e in events if e.severity]
    max_sev_weight = max([SEVERITY_WEIGHT_MAP.get(s, 0.2) for s in severities], default=0.5)
    f_severity = max_sev_weight

    raw_score = (0.35 * f_entity) + (0.25 * f_time) + (0.20 * f_source) + (0.20 * f_severity)
    score = round(raw_score, 3)

    if score >= 0.75:
        confidence = "HIGH"
    elif score >= 0.50:
        confidence = "MEDIUM"
    elif score >= 0.35:
        confidence = "LOW"
    else:
        confidence = "INSUFFICIENT CORRELATION EVIDENCE"

    breakdown = {
        "entity_factor": round(f_entity, 3),
        "time_factor": round(f_time, 3),
        "source_factor": round(f_source, 3),
        "severity_factor": round(f_severity, 3),
        "span_seconds": round(span_seconds, 2),
        "window_seconds": window_seconds,
        "distinct_sources": sorted(list(sources)),
        "formula": "Score = 0.35*F_entity + 0.25*F_time + 0.20*F_source + 0.20*F_severity",
        "explanation": f"F_entity={round(f_entity,2)} ({matched_pairs} matches), F_time={round(f_time,2)} (span={round(span_seconds,1)}s/{window_seconds}s), F_source={round(f_source,2)} ({num_sources} sources), F_sev={round(f_severity,2)}.",
    }

    return score, confidence, breakdown


def build_incident_timeline(
    events: list[NormalizedEvent],
    alerts: list[Alert],
) -> list[dict[str, Any]]:
    """
    Constructs a strictly chronological timeline of actual recorded telemetry events and alerts.
    Does NOT fabricate missing steps. Deduplicates identical events/alerts.
    """
    timeline_items: list[dict[str, Any]] = []
    seen_event_ids: set[Any] = set()
    seen_alert_ids: set[Any] = set()

    # Include normalized events
    for ev in events:
        if ev.id is not None and ev.id in seen_event_ids:
            continue
        if ev.id is not None:
            seen_event_ids.add(ev.id)

        entities = extract_entities_from_event(ev)
        raw_ref = entities.get("raw_reference") or f"EVT-{ev.id}"
        timeline_items.append({
            "timestamp": ev.timestamp.isoformat(),
            "source_type": (ev.source_type or "WEB").upper(),
            "stage": ev.event_category or "suspicious_activity",
            "title": f"[{ev.source_type or 'WEB'}] {ev.event_type}",
            "description": ev.message or f"Event {ev.event_type} on {ev.hostname or ev.source_ip or 'unknown'}",
            "event_id": str(ev.id),
            "alert_id": None,
            "raw_reference": raw_ref,
            "evidence_ref": f"EVID-EVT-{ev.id}",
            "entities": entities,
        })

    # Include alerts
    for al in alerts:
        if al.id is not None and al.id in seen_alert_ids:
            continue
        if al.id is not None:
            seen_alert_ids.add(al.id)

        entities = extract_entities_from_alert(al)
        timeline_items.append({
            "timestamp": al.first_seen.isoformat(),
            "source_type": "DETECTION_ALERT",
            "stage": "detection_alert",
            "title": f"[ALERT] {al.title}",
            "description": al.description,
            "event_id": None,
            "alert_id": al.id,
            "raw_reference": f"ALT-{al.id}",
            "evidence_ref": f"EVID-ALT-{al.id}",
            "entities": entities,
        })

    # Sort strictly by timestamp ascending
    timeline_items.sort(key=lambda item: item["timestamp"])

    # Compute relative time deltas from the earliest entry
    earliest_dt = None
    if timeline_items:
        try:
            earliest_dt = datetime.fromisoformat(timeline_items[0]["timestamp"])
        except Exception:
            earliest_dt = None

    for item in timeline_items:
        if earliest_dt:
            try:
                curr_dt = datetime.fromisoformat(item["timestamp"])
                item["relative_time_seconds"] = round(abs((curr_dt - earliest_dt).total_seconds()), 2)
            except Exception:
                item["relative_time_seconds"] = 0.0
        else:
            item["relative_time_seconds"] = 0.0

    return timeline_items



def build_incident_graph(
    incident_id: int,
    incident_number: str,
    events: list[NormalizedEvent],
    alerts: list[Alert],
) -> dict[str, Any]:
    """
    Builds a telemetry-backed incident graph representation.
    Nodes: IP, Host, User, Process, Event, Alert, Incident, Domain, URL.
    Edges: REQUESTED, CONNECTED_TO, EXECUTED, QUERIED, GENERATED, ASSOCIATED_WITH.
    Every graph edge is backed by real telemetry fields.
    """
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str, str]] = set()

    def add_node(node_id: str, label: str, node_type: str, properties: dict[str, Any] | None = None):
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "label": label,
                "type": node_type,
                "properties": properties or {},
            }

    def add_edge(source: str, target: str, rel: str, timestamp: Optional[datetime] = None, evidence_ref: Optional[str] = None):
        key = (source, target, rel)
        if key not in seen_edges:
            seen_edges.add(key)
            edges.append({
                "source": source,
                "target": target,
                "relationship": rel,
                "timestamp": timestamp.isoformat() if timestamp else None,
                "evidence_ref": evidence_ref,
            })

    # Incident Node
    inc_node_id = f"incident:{incident_id}"
    add_node(inc_node_id, incident_number, "Incident", {"incident_id": incident_id})

    # Alert Nodes and Edges
    for al in alerts:
        al_node_id = f"alert:{al.id}"
        add_node(al_node_id, al.title[:30], "Alert", {
            "alert_id": al.id,
            "severity": al.severity,
            "title": al.title,
        })
        add_edge(inc_node_id, al_node_id, "ASSOCIATED_WITH", al.first_seen, f"ALT-{al.id}")

        if al.source_ip and al.source_ip not in IGNORE_IPS:
            ip_id = f"ip:{al.source_ip}"
            add_node(ip_id, al.source_ip, "IP", {"ip": al.source_ip})
            add_edge(al_node_id, ip_id, "OBSERVED_IP", al.first_seen)

    # Event Nodes and Edges
    for ev in events:
        ev_node_id = f"event:{ev.id}"
        add_node(ev_node_id, f"{ev.source_type}:{ev.event_type}"[:32], "Event", {
            "event_id": ev.id,
            "source_type": ev.source_type,
            "event_type": ev.event_type,
            "severity": ev.severity,
        })

        # Telemetry Relationships
        # 1. Source IP
        if ev.source_ip and ev.source_ip not in IGNORE_IPS:
            src_ip_id = f"ip:{ev.source_ip}"
            add_node(src_ip_id, ev.source_ip, "IP", {"ip": ev.source_ip})
            add_edge(ev_node_id, src_ip_id, "FROM_SOURCE", ev.timestamp, f"EVT-{ev.id}")

            # Destination IP / Host Connection
            if ev.destination_ip and ev.destination_ip not in IGNORE_IPS:
                dst_ip_id = f"ip:{ev.destination_ip}"
                add_node(dst_ip_id, ev.destination_ip, "IP", {"ip": ev.destination_ip})
                add_edge(src_ip_id, dst_ip_id, "CONNECTED_TO", ev.timestamp, f"EVT-{ev.id}")

            # Web URL Requested
            if ev.request_path:
                url_id = f"url:{ev.request_path[:50]}"
                add_node(url_id, ev.request_path[:30], "URL", {"path": ev.request_path})
                add_edge(src_ip_id, url_id, "REQUESTED", ev.timestamp, f"EVT-{ev.id}")

        # 2. Host and Execution
        if ev.hostname:
            host_id = f"host:{ev.hostname.lower()}"
            add_node(host_id, ev.hostname, "Host", {"hostname": ev.hostname})
            add_edge(ev_node_id, host_id, "OCCURRED_ON", ev.timestamp, f"EVT-{ev.id}")

            # Process execution on host
            if ev.process:
                proc_id = f"proc:{ev.process.lower()}"
                add_node(proc_id, ev.process, "Process", {
                    "process": ev.process,
                    "process_id": ev.process_id,
                    "command_line": ev.command_line,
                })
                add_edge(host_id, proc_id, "EXECUTED", ev.timestamp, f"EVT-{ev.id}")

                # Process connecting to outbound destination
                if ev.destination_ip and ev.destination_ip not in IGNORE_IPS:
                    dst_ip_id = f"ip:{ev.destination_ip}"
                    add_node(dst_ip_id, ev.destination_ip, "IP", {"ip": ev.destination_ip})
                    add_edge(proc_id, dst_ip_id, "CONNECTED_TO", ev.timestamp, f"EVT-{ev.id}")

                # Process querying domain
                if ev.dns_query:
                    domain_id = f"domain:{ev.dns_query.lower()}"
                    add_node(domain_id, ev.dns_query, "Domain", {"query": ev.dns_query})
                    add_edge(proc_id, domain_id, "QUERIED", ev.timestamp, f"EVT-{ev.id}")

        # 3. User Identity
        if ev.username:
            user_id = f"user:{ev.username.lower()}"
            add_node(user_id, ev.username, "User", {"username": ev.username})
            add_edge(ev_node_id, user_id, "ASSOCIATED_USER", ev.timestamp, f"EVT-{ev.id}")
            if ev.hostname:
                host_id = f"host:{ev.hostname.lower()}"
                add_edge(user_id, host_id, "AUTHENTICATED_ON", ev.timestamp, f"EVT-{ev.id}")

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
    }


def record_cross_source_evidence(
    db: Session,
    incident: Incident,
    explanations: list[dict[str, Any]],
    score_breakdown: dict[str, Any],
) -> None:
    """
    Persists tamper-evident Evidence items for cross-source correlation matches.
    """
    for item in explanations:
        rule = item.get("rule", "CORR-000")
        evidence_payload = {
            "correlation_rule": rule,
            "title": item.get("title"),
            "matched_field": item.get("matched_field"),
            "matched_value": item.get("matched_value"),
            "time_delta_seconds": item.get("time_delta_seconds"),
            "window_seconds": item.get("window_seconds"),
            "supporting_events": item.get("events"),
            "score_breakdown": score_breakdown,
        }
        serialized = json.dumps(evidence_payload, sort_keys=True)
        sha256 = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        # Check if identical evidence already recorded
        existing = (
            db.query(Evidence)
            .filter(
                Evidence.incident_id == incident.id,
                Evidence.evidence_type == f"CROSS_SOURCE_{rule}",
            )
            .first()
        )
        if not existing:
            ev_record = Evidence(
                incident_id=incident.id,
                evidence_type=f"CROSS_SOURCE_{rule}",
                title=f"Cross-Source Correlation: {item.get('title')}",
                description=item.get("summary", ""),
                data_json=evidence_payload,
                sha256_hash=sha256,
                confidence=1.0,
                is_verified=True,
            )
            db.add(ev_record)
            db.flush()


def run_cross_source_correlation(
    db: Session,
    alert_ids: Optional[list[int]] = None,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> list[Incident]:
    """
    Main orchestration entry point:
      1. Gathers candidate alerts and their associated normalized events
      2. Performs deterministic entity resolution across available attributes
      3. Applies temporal window filtering
      4. Evaluates explicit correlation rules CORR-001 through CORR-004
      5. Calculates explainable correlation score
      6. Synthesizes Unified Incident with Timeline and Incident Graph
      7. Upserts Incident records and Evidence
    """
    # 1. Fetch alerts
    if alert_ids:
        alerts = db.query(Alert).filter(Alert.id.in_(alert_ids)).all()
    else:
        # Default: open/investigating alerts
        alerts = db.query(Alert).filter(Alert.status.in_(["open", "investigating"])).all()

    if not alerts:
        return []

    # Map alerts to their events
    alert_events_map: dict[int, list[NormalizedEvent]] = {}
    for alert in alerts:
        evs = (
            db.query(NormalizedEvent)
            .join(AlertEvent, AlertEvent.event_id == NormalizedEvent.id)
            .filter(AlertEvent.alert_id == alert.id)
            .all()
        )
        alert_events_map[alert.id] = evs

    # Group alerts into clusters by deterministic entity overlap within window_seconds
    clusters: list[list[Alert]] = []
    visited: set[int] = set()

    for i, a1 in enumerate(alerts):
        if a1.id in visited:
            continue
        cluster = [a1]
        visited.add(a1.id)
        e1_ents = extract_entities_from_alert(a1)
        for ev in alert_events_map.get(a1.id, []):
            e1_ents.update(extract_entities_from_event(ev))

        for j, a2 in enumerate(alerts):
            if a2.id in visited:
                continue

            # Check time window
            dt = abs((ensure_utc(a1.first_seen) - ensure_utc(a2.first_seen)).total_seconds())
            if dt > window_seconds:
                continue

            e2_ents = extract_entities_from_alert(a2)
            for ev in alert_events_map.get(a2.id, []):
                e2_ents.update(extract_entities_from_event(ev))

            # Deterministic entity match
            matches = match_entities(e1_ents, e2_ents)
            if matches:
                cluster.append(a2)
                visited.add(a2.id)

        clusters.append(cluster)

    results: list[Incident] = []

    for cluster in clusters:
        # Gather all events in cluster
        all_cluster_events: list[NormalizedEvent] = []
        for al in cluster:
            all_cluster_events.extend(alert_events_map.get(al.id, []))

        # Evaluate rules and score
        attack_status, matched_rules, explanations = evaluate_correlation_rules(all_cluster_events, window_seconds)
        score, confidence, breakdown = calculate_explainable_correlation_score(all_cluster_events, cluster, window_seconds)

        # Primary entity selection
        primary_entity = None
        for al in cluster:
            if al.source_ip and al.source_ip not in IGNORE_IPS:
                primary_entity = f"ip:{al.source_ip}"
                break
            elif al.affected_user:
                primary_entity = f"user:{al.affected_user}"
                break
        if not primary_entity and all_cluster_events:
            ev = all_cluster_events[0]
            if ev.hostname:
                primary_entity = f"host:{ev.hostname}"
            elif ev.source_ip:
                primary_entity = f"ip:{ev.source_ip}"
            else:
                primary_entity = "entity:unspecified"

        # Unique sources
        sources = list({ev.source_type.upper() for ev in all_cluster_events if ev.source_type})
        if not sources:
            sources = ["WEB"]

        # Related entities list
        related_entities: list[dict[str, Any]] = []
        for ev in all_cluster_events:
            ents = extract_entities_from_event(ev)
            for k, v in ents.items():
                entry = {"type": k, "value": v}
                if entry not in related_entities:
                    related_entities.append(entry)

        # Timestamps
        all_times = [ensure_utc(al.first_seen) for al in cluster] + [ensure_utc(e.timestamp) for e in all_cluster_events]
        first_seen = min(all_times) if all_times else datetime.now(UTC)
        last_seen = max(all_times) if all_times else datetime.now(UTC)

        # Severities
        severities = [al.severity.lower() for al in cluster]
        highest_sev = "medium"
        for s in ["critical", "high", "medium", "low"]:
            if s in severities:
                highest_sev = s
                break

        # Check for existing incident matching primary_entity or cluster alerts
        existing_inc = None
        cluster_alert_ids = [al.id for al in cluster]
        existing_link = (
            db.query(IncidentAlert)
            .filter(IncidentAlert.alert_id.in_(cluster_alert_ids))
            .first()
        )
        if existing_link:
            existing_inc = db.get(Incident, existing_link.incident_id)

        if not existing_inc and primary_entity:
            existing_inc = (
                db.query(Incident)
                .filter(
                    Incident.primary_entity == primary_entity,
                    Incident.status.in_(["open", "investigating"]),
                    Incident.last_seen >= (first_seen - timedelta(seconds=window_seconds)),
                )
                .order_by(Incident.last_seen.desc())
                .first()
            )

        if existing_inc:
            incident = existing_inc
            # Update fields
            incident.last_seen = max(ensure_utc(incident.last_seen), last_seen)
            incident.first_seen = min(ensure_utc(incident.first_seen), first_seen)
            incident.severity = highest_sev
            incident.correlation_score = score
            incident.confidence = confidence
            incident.attack_chain_status = attack_status
            incident.source_types_json = sources
            incident.related_entities_json = related_entities
        else:
            # Create next incident
            count = db.query(Incident).count()
            inc_number = f"INC-{(count + 1):03d}"
            title_entity = primary_entity or "Correlated Activity"
            inc_title = f"Correlated Incident {title_entity} [{attack_status}]"
            inc_desc = (
                f"Unified cross-source incident reconstructed from {len(cluster)} alert(s) "
                f"and {len(all_cluster_events)} event(s) across sources: {', '.join(sources)}. "
                f"Rules matched: {', '.join(matched_rules) if matched_rules else 'Deterministic Entity Match'}."
            )

            incident = Incident(
                incident_number=inc_number,
                title=inc_title[:255],
                description=inc_desc,
                severity=highest_sev,
                status="open",
                source_ip=cluster[0].source_ip if cluster else None,
                affected_user=cluster[0].affected_user if cluster else None,
                correlation_key=primary_entity,
                primary_entity=primary_entity,
                related_entities_json=related_entities,
                source_types_json=sources,
                correlation_score=score,
                confidence=confidence,
                risk_score=min(100.0, score * 100.0),
                attack_chain_status=attack_status,
                first_seen=first_seen,
                last_seen=last_seen,
                alert_count=len(cluster),
                event_count=len(all_cluster_events),
            )
            db.add(incident)
            db.flush()

        # Link all alerts in cluster
        for al in cluster:
            linked = (
                db.query(IncidentAlert)
                .filter(IncidentAlert.incident_id == incident.id, IncidentAlert.alert_id == al.id)
                .first()
            )
            if not linked:
                db.add(IncidentAlert(incident_id=incident.id, alert_id=al.id))

        db.flush()

        # Build timeline and graph
        timeline_items = build_incident_timeline(all_cluster_events, cluster)
        graph_data = build_incident_graph(incident.id, incident.incident_number, all_cluster_events, cluster)

        incident.timeline_json = timeline_items
        incident.graph_json = graph_data
        incident.alert_count = len(cluster)
        incident.event_count = len(all_cluster_events)

        # Record evidence
        record_cross_source_evidence(db, incident, explanations, breakdown)

        db.flush()
        results.append(incident)

    return results


def calculate_correlation_score(
    matched_entities: dict[str, Any] | list[Any],
    time_delta_seconds: Optional[float] = None,
    source_types: Optional[set[str]] = None,
    max_severity: str = "LOW",
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> tuple[float, str, str]:
    """
    Direct helper to evaluate explainable score without full event objects.
    Returns: (score, explanation, confidence)
    """
    if not matched_entities and time_delta_seconds is None and not source_types:
        return 0.0, "INSUFFICIENT CORRELATION EVIDENCE: No entities matched", "LOW"

    # Entity Factor
    if isinstance(matched_entities, dict):
        match_count = len(matched_entities)
    elif isinstance(matched_entities, (list, set)):
        match_count = len(matched_entities)
    else:
        match_count = 0

    if match_count >= 2:
        f_entity = 1.0
    elif match_count == 1:
        f_entity = 0.7
    else:
        f_entity = 0.1

    # Time Factor
    if time_delta_seconds is not None:
        f_time = max(0.0, min(1.0, 1.0 - (time_delta_seconds / max(float(window_seconds), 1.0))))
    else:
        f_time = 0.5

    # Source Factor
    sources = source_types or set()
    if len(sources) >= 3:
        f_source = 1.0
    elif len(sources) == 2:
        f_source = 0.75
    elif len(sources) == 1:
        f_source = 0.4
    else:
        f_source = 0.2

    # Severity Factor
    f_sev = SEVERITY_WEIGHT_MAP.get(max_severity.lower(), 0.3)

    raw_score = (0.35 * f_entity) + (0.25 * f_time) + (0.20 * f_source) + (0.20 * f_sev)
    score = round(raw_score, 3)

    if score >= 0.75:
        confidence = "HIGH"
    elif score >= 0.50:
        confidence = "MEDIUM"
    elif score >= 0.35:
        confidence = "LOW"
    else:
        confidence = "INSUFFICIENT CORRELATION EVIDENCE"

    explanation = f"Score={score} (Entity={f_entity}, Time={f_time}, Source={f_source}, Sev={f_sev})"
    return score, explanation, confidence


class CrossSourceCorrelationEngineResult:
    """Wrapper holding run results."""
    def __init__(self, incidents: list[Incident], window_seconds: int):
        self.incidents = incidents
        self.incidents_created = len(incidents)
        self.window_seconds = window_seconds


class CrossSourceCorrelationEngine:
    """Convenience wrapper around run_cross_source_correlation."""
    def __init__(self, db: Session, window_seconds: int = DEFAULT_WINDOW_SECONDS):
        self.db = db
        self.window_seconds = window_seconds

    def correlate_all(self, alert_ids: Optional[list[int]] = None) -> CrossSourceCorrelationEngineResult:
        incidents = run_cross_source_correlation(self.db, alert_ids=alert_ids, window_seconds=self.window_seconds)
        return CrossSourceCorrelationEngineResult(incidents, self.window_seconds)

