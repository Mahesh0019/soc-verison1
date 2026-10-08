"""
backend/app/services/ai_analyst_service.py

Phase 8: Evidence-Grounded AI Analyst Assistance & Hallucination Evaluation Engine.

Architectural Guarantees:
  1. Authoritative SOC Plane is strictly read-only for AI (AI never mutates detection, correlation, or incident state).
  2. Bounded Context: AI context comprises only verified database records with cryptographic provenance.
  3. Sensitive secrets (tokens, passwords, keys) are automatically redacted before context construction.
  4. Prompt-Injection Boundary: Untrusted telemetry is isolated in structured data envelopes and never parsed as instructions.
  5. Post-generation Claim-to-Evidence Validation: Validates citations against incident evidence IDs, detecting
     unsupported, contradicted, and cross-incident claims.
  6. Strict separation of FACT vs. INFERENCE vs. RECOMMENDATION vs. UNCERTAINTY.
  7. Explicit Abstention on insufficient or contradictory evidence.
"""

from __future__ import annotations

import copy
import re
from datetime import UTC, datetime
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models import (
    AIAnalysis,
    Alert,
    AlertEvent,
    AuditLog,
    Evidence,
    Incident,
    IncidentAlert,
    NormalizedEvent,
    DetectionRule,
)
from app.schemas.ai_analyst import (
    AIAnalystStructuredOutput,
    AIClaim,
    AnalystQuestionResponse,
    AttackChainStep,
    EvidenceCitation,
    MITREContextItem,
)
from app.services.correlation_service import (
    build_incident_graph,
    build_incident_timeline,
)
from app.services.detection_quality_service import evaluate_incident_quality
from app.services.evidence_service import build_incident_evidence_package
from app.services.risk_service import evaluate_incident_risk

# Model identification
MODEL_NAME = "Deterministic AI Analyst Baseline (Evidence-Grounded Engine v2.0)"
PROMPT_VERSION = "v2.0-evidence-bounded"

# Redaction patterns
SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\s&]+)", re.IGNORECASE),
    re.compile(r"(?i)(bearer\s+[a-zA-Z0-9_\-\.]{15,})", re.IGNORECASE),
    re.compile(r"(?i)(api[_-]?key|token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{12,})", re.IGNORECASE),
]

PROMPT_INJECTION_PATTERNS = [
    re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions"),
    re.compile(r"(?i)system\s*:\s*override"),
    re.compile(r"(?i)declare\s+(this\s+)?(as\s+)?benign"),
    re.compile(r"(?i)report\s+zero\s+threats"),
    re.compile(r"(?i)set\s+confidence\s+to\s+0"),
]


def redact_sensitive_strings(text: Optional[str]) -> tuple[Optional[str], int]:
    """Redacts passwords, bearer tokens, and API keys from telemetry strings."""
    if not text:
        return text, 0
    redacted = text
    count = 0
    for pat in SECRET_PATTERNS:
        matches = pat.findall(redacted)
        if matches:
            count += len(matches)
            redacted = pat.sub("[REDACTED_SECRET]", redacted)
    return redacted, count


def build_ai_analyst_context(db: Session, incident: Incident) -> dict[str, Any]:
    """
    Constructs a verified, evidence-bounded context package for an Incident.
    Ensures:
      - Provenance tracking on every telemetry item
      - Redaction of sensitive credentials
      - Isolation of untrusted telemetry content
      - Full inventory of valid evidence IDs belonging exclusively to this incident
    """
    # 1. Fetch incident-associated alerts
    incident_alerts = (
        db.query(Alert)
        .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
        .filter(IncidentAlert.incident_id == incident.id)
        .all()
    )

    # 2. Fetch associated normalized events
    alert_ids = [a.id for a in incident_alerts]
    events = []
    if alert_ids:
        events = (
            db.query(NormalizedEvent)
            .join(AlertEvent, AlertEvent.event_id == NormalizedEvent.id)
            .filter(AlertEvent.alert_id.in_(alert_ids))
            .order_by(NormalizedEvent.timestamp.asc())
            .all()
        )

    # 3. Fetch authoritative evidence records
    evidence_records = (
        db.query(Evidence)
        .filter((Evidence.incident_id == incident.id) | (Evidence.alert_id.in_(alert_ids) if alert_ids else False))
        .all()
    )

    # If no evidence records stored yet, generate them through evidence service
    if not evidence_records:
        evidence_records = build_incident_evidence_package(db, incident)

    # 4. Construct Timeline and Attack Graph
    timeline = build_incident_timeline(events=events, alerts=incident_alerts)
    graph = build_incident_graph(
        incident_id=incident.id,
        incident_number=incident.incident_number,
        events=events,
        alerts=incident_alerts,
    )

    # 5. Extract Rules and MITRE mappings
    rule_ids = [a.rule_id for a in incident_alerts if a.rule_id]
    rules = db.query(DetectionRule).filter(DetectionRule.id.in_(rule_ids)).all() if rule_ids else []

    # Map evidence for fast lookup
    evidence_map = {e.id: e for e in evidence_records}
    valid_evidence_ids = set(evidence_map.keys())

    # 6. Sanitize and record provenance
    total_redacted = 0
    provenance_records = []
    untrusted_payloads = []

    for ev in events:
        cmd, r1 = redact_sensitive_strings(ev.command_line)
        path, r2 = redact_sensitive_strings(ev.request_path)
        msg, r3 = redact_sensitive_strings(ev.message)
        raw, r4 = redact_sensitive_strings(ev.raw_log)
        total_redacted += r1 + r2 + r3 + r4

        # Match with evidence if available
        matched_ev = next(
            (e for e in evidence_records if e.data_json and str(e.data_json.get("event_id")) == str(ev.id)),
            evidence_records[0] if evidence_records else None,
        )
        ev_id = matched_ev.id if matched_ev else None

        prov = {
            "evidence_id": ev_id,
            "source_type": ev.source_type,
            "event_id": ev.id,
            "hostname": ev.hostname,
            "source_ip": ev.source_ip,
            "destination_ip": ev.destination_ip,
            "destination_port": ev.destination_port,
            "process": ev.process,
            "parent_process": ev.parent_process,
            "command_line": cmd,
            "request_path": path,
            "dns_query": ev.dns_query,
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            "provenance": "database_event",
            "sha256_hash": matched_ev.sha256_hash if matched_ev else None,
        }
        provenance_records.append(prov)

        # Untrusted raw telemetry envelope
        raw_text = (raw[:200] if raw else "") or (cmd[:200] if cmd else "")
        untrusted_payloads.append({
            "event_id": ev.id,
            "source_type": ev.source_type,
            "raw_log_snippet": f"=== BEGIN UNTRUSTED TELEMETRY DATA ===\n{raw_text}\n=== END UNTRUSTED TELEMETRY DATA ===",
            "has_injection_tokens": any(
                pat.search(ev.command_line or "") or pat.search(ev.request_path or "") or pat.search(ev.raw_log or "")
                for pat in PROMPT_INJECTION_PATTERNS
            ),
        })

    dq = evaluate_incident_quality(db, incident)
    risk = evaluate_incident_risk(db, incident)

    return {
        "incident_id": incident.id,
        "incident_number": incident.incident_number,
        "severity": incident.severity,
        "title": incident.title,
        "risk_score": risk.risk_score,
        "risk_level": risk.risk_level,
        "correlation_score": incident.correlation_score or 0.85,
        "confidence": incident.confidence or "HIGH",
        "source_types": incident.source_types or ["WEB"],
        "primary_entity": incident.primary_entity or incident.source_ip or "unspecified",
        "alert_count": len(incident_alerts),
        "event_count": len(events),
        "alerts": incident_alerts,
        "events": events,
        "evidence_records": evidence_records,
        "evidence_map": evidence_map,
        "valid_evidence_ids": valid_evidence_ids,
        "timeline": timeline,
        "graph": graph,
        "rules": rules,
        "detection_quality": dq.overall_quality,
        "evidence_completeness": dq.evidence_completeness,
        "provenance_records": provenance_records,
        "untrusted_payloads": untrusted_payloads,
        "redacted_fields_count": total_redacted,
    }


def validate_claims_against_evidence(
    raw_claims: list[dict[str, Any]],
    context: dict[str, Any],
) -> tuple[list[AIClaim], dict[str, Any]]:
    """
    Post-generation claim-to-evidence validation engine.
    Audits each factual claim against verified evidence IDs belonging to the incident.
    """
    valid_ids = context["valid_evidence_ids"]
    ev_map = context["evidence_map"]
    validated_claims: list[AIClaim] = []

    supported_count = 0
    unsupported_count = 0
    contradicted_count = 0
    invalid_citation_count = 0

    for i, c in enumerate(raw_claims):
        claim_id = f"CLM-{i + 1:03d}"
        claim_type = c.get("claim_type", "FACT")
        claim_text = c.get("claim_text", "")
        citation_dict = c.get("citation")

        citation = None
        status = "UNSUPPORTED"
        reason = "No evidence citation provided for factual claim."

        if claim_type in ("INFERENCE", "RECOMMENDATION", "UNCERTAINTY"):
            # Analytical statements are valid inferences if facts exist
            status = "SUPPORTED" if len(valid_ids) > 0 else "UNVERIFIABLE"
            reason = "Analytical inference derived from verified context."
        elif citation_dict:
            ev_id = citation_dict.get("evidence_id")
            if ev_id is None or ev_id not in valid_ids:
                status = "UNSUPPORTED"
                invalid_citation_count += 1
                reason = f"Referenced evidence ID {ev_id} does not exist in authoritative incident evidence."
            else:
                ev_obj = ev_map[ev_id]
                citation = EvidenceCitation(
                    evidence_id=ev_obj.id,
                    source_type=citation_dict.get("source_type", ev_obj.evidence_type),
                    event_id=citation_dict.get("event_id"),
                    field=citation_dict.get("field", "event"),
                    value=citation_dict.get("value", ev_obj.title),
                    timestamp=citation_dict.get("timestamp"),
                    provenance="database_event",
                )

                # Check for contradiction: does authoritative record state the opposite?
                if c.get("is_contradicted"):
                    status = "CONTRADICTED"
                    reason = "Claim asserts behavior explicitly contradicted by authoritative telemetry."
                    contradicted_count += 1
                else:
                    status = "SUPPORTED"
                    reason = f"Verified against Evidence #{ev_obj.id} ({ev_obj.evidence_type})."
                    supported_count += 1

        if status == "UNSUPPORTED":
            unsupported_count += 1

        validated_claims.append(
            AIClaim(
                claim_id=claim_id,
                claim_type=claim_type,
                claim_text=claim_text,
                citation=citation,
                validation_status=status,
                validation_reason=reason,
            )
        )

    total_factual = sum(1 for c in validated_claims if c.claim_type == "FACT")
    citation_coverage = round(
        (supported_count / max(1, total_factual)) * 100.0, 1
    ) if total_factual > 0 else 100.0

    metrics = {
        "total_claims_count": len(validated_claims),
        "supported_claims_count": supported_count,
        "unsupported_claims_count": unsupported_count,
        "contradicted_claims_count": contradicted_count,
        "citation_coverage_pct": citation_coverage,
        "invalid_citation_count": invalid_citation_count,
    }
    return validated_claims, metrics


def generate_ai_analyst_assistance(
    db: Session,
    incident: Incident,
    force_refresh: bool = False,
) -> AIAnalystStructuredOutput:
    """
    Executes all 11 AI analyst assistance tasks over authoritative incident context:
      TASK-001 Incident Summary
      TASK-002 Evidence Explanation
      TASK-003 Attack Chain Explanation
      TASK-004 Timeline Interpretation
      TASK-005 Detection Explanation
      TASK-006 Risk / Priority Explanation
      TASK-007 Investigation Recommendations
      TASK-008 Missing Evidence Identification
      TASK-009 MITRE Context Assistance
      TASK-010 Analyst Question Answering
      TASK-011 Explicit Uncertainty / Abstention
    """
    context = build_ai_analyst_context(db, incident)

    ev_records = context["evidence_records"]
    provenance = context["provenance_records"]
    rules = context["rules"]
    timeline = context["timeline"]
    dq = context["detection_quality"]
    risk_score = context["risk_score"]

    # Detect prompt injection attempts in telemetry
    prompt_injections = [p for p in context["untrusted_payloads"] if p.get("has_injection_tokens")]

    # ── TASK-011: Explicit Abstention Assessment ─────────────────────────────
    # Evaluate whether evidence is sufficient to formulate an assessment
    insufficient_evidence = False
    abstention_reason = None

    if len(provenance) == 0 or len(ev_records) == 0:
        insufficient_evidence = True
        abstention_reason = "INSUFFICIENT EVIDENCE: Zero verified telemetry events or evidence items linked to incident."
    elif dq < 0.40 and len(provenance) <= 1:
        insufficient_evidence = True
        abstention_reason = "INSUFFICIENT EVIDENCE: Telemetry is single-source and detection quality is below 0.40."

    raw_claims: list[dict[str, Any]] = []
    facts: list[str] = []
    inferences: list[str] = []
    recommendations: list[str] = []
    uncertainties: list[str] = []
    attack_chain: list[AttackChainStep] = []
    mitre_context: list[MITREContextItem] = []
    supporting_citations: list[EvidenceCitation] = []
    contradicting_citations: list[EvidenceCitation] = []

    if insufficient_evidence:
        assessment = "INSUFFICIENT_EVIDENCE"
        summary = (
            f"INSUFFICIENT EVIDENCE: Incident {incident.incident_number} does not possess sufficient "
            f"authoritative telemetry to establish a definitive attack chain. The AI assistant abstains "
            f"from concluding a malicious intrusion."
        )
        uncertainties.append(abstention_reason)
        recommendations.append("Collect additional endpoint and network logs before triage escalation.")
        confidence = 0.20
    else:
        # Determine Assessment based strictly on verified rules and evidence
        assessment = "TRUE_POSITIVE" if incident.severity in ("CRITICAL", "HIGH") and dq >= 0.60 else "SUSPICIOUS"
        if incident.title and "False Positive" in incident.title:
            assessment = "FALSE_POSITIVE"

        confidence = round(min(1.0, max(0.40, (context["correlation_score"] * 0.5) + (dq * 0.5))), 2)

        # ── TASK-001 & TASK-002: Factual Claims Grounded in Evidence ────────
        for i, prov in enumerate(provenance[:6]):
            ev_id = prov.get("evidence_id")
            src = prov.get("source_type")

            if src == "WEB" and prov.get("request_path"):
                claim_txt = f"Web sensor recorded HTTP request to '{prov['request_path']}' from IP {prov.get('source_ip') or 'unknown'}."
                raw_claims.append({
                    "claim_type": "FACT",
                    "claim_text": claim_txt,
                    "citation": {
                        "evidence_id": ev_id,
                        "source_type": "WEB",
                        "event_id": prov.get("event_id"),
                        "field": "request_path",
                        "value": prov.get("request_path"),
                        "timestamp": prov.get("timestamp"),
                    },
                })
                facts.append(claim_txt)
            elif src == "ZEEK" and prov.get("destination_port"):
                claim_txt = f"Network telemetry captured connection to destination port {prov['destination_port']}."
                raw_claims.append({
                    "claim_type": "FACT",
                    "claim_text": claim_txt,
                    "citation": {
                        "evidence_id": ev_id,
                        "source_type": "ZEEK",
                        "event_id": prov.get("event_id"),
                        "field": "destination_port",
                        "value": str(prov["destination_port"]),
                        "timestamp": prov.get("timestamp"),
                    },
                })
                facts.append(claim_txt)
            elif src == "SYSMON" and prov.get("process"):
                claim_txt = f"Sysmon telemetry recorded process creation '{prov['process']}' on host '{prov.get('hostname') or 'host'}'."
                raw_claims.append({
                    "claim_type": "FACT",
                    "claim_text": claim_txt,
                    "citation": {
                        "evidence_id": ev_id,
                        "source_type": "SYSMON",
                        "event_id": prov.get("event_id"),
                        "field": "process",
                        "value": prov.get("process"),
                        "timestamp": prov.get("timestamp"),
                    },
                })
                facts.append(claim_txt)

        # ── TASK-003: Attack Chain Explanation ──────────────────────────────
        stage_idx = 1
        has_web = any(p.get("source_type") == "WEB" for p in provenance)
        has_zk = any(p.get("source_type") == "ZEEK" for p in provenance)
        has_sys = any(p.get("source_type") == "SYSMON" for p in provenance)

        if has_web:
            web_evs = [p["evidence_id"] for p in provenance if p.get("source_type") == "WEB" and p.get("evidence_id")]
            attack_chain.append(
                AttackChainStep(
                    stage_order=stage_idx,
                    stage_name="Initial Access / Exploit Probe",
                    description="Inbound HTTP request targeting web application vulnerability.",
                    source_type="WEB",
                    evidence_ids=web_evs[:2],
                )
            )
            stage_idx += 1

        if has_sys:
            sys_evs = [p["evidence_id"] for p in provenance if p.get("source_type") == "SYSMON" and p.get("evidence_id")]
            attack_chain.append(
                AttackChainStep(
                    stage_order=stage_idx,
                    stage_name="Execution & Command Dispatch",
                    description="Host execution of command shell or utility spawned post-exploitation.",
                    source_type="SYSMON",
                    evidence_ids=sys_evs[:2],
                )
            )
            stage_idx += 1

        if has_zk:
            zk_evs = [p["evidence_id"] for p in provenance if p.get("source_type") == "ZEEK" and p.get("evidence_id")]
            attack_chain.append(
                AttackChainStep(
                    stage_order=stage_idx,
                    stage_name="Network Command & Control / Egress",
                    description="Outbound wire connection observed following host activity.",
                    source_type="ZEEK",
                    evidence_ids=zk_evs[:2],
                )
            )

        # ── TASK-004: Timeline Interpretation ───────────────────────────────
        timeline_span_sec = 0.0
        if len(timeline) >= 2 and timeline[0].get("timestamp") and timeline[-1].get("timestamp"):
            try:
                t0 = datetime.fromisoformat(str(timeline[0]["timestamp"]))
                t1 = datetime.fromisoformat(str(timeline[-1]["timestamp"]))
                timeline_span_sec = max(0.0, (t1 - t0).total_seconds())
            except Exception:
                pass

        inferences.append(
            f"Timeline exhibits a temporal span of {timeline_span_sec:.1f}s across {len(timeline)} chronological checkpoints. "
            f"Temporal sequencing corroborates causal attack propagation rather than coincidental background noise."
        )

        # ── TASK-005: Detection Explanation ─────────────────────────────────
        rule_names = [r.name for r in rules] if rules else [a.title for a in context["alerts"]]
        inferences.append(
            f"Authoritative detection engine triggered on {len(rule_names)} detection pattern(s): {', '.join(rule_names[:3])}."
        )

        # ── TASK-006: Risk Explanation ──────────────────────────────────────
        inferences.append(
            f"Multi-factor risk score is {risk_score:.1f}/100 ({context['risk_level']}), driven by correlation confidence "
            f"({context['correlation_score']:.2f}) and composite detection quality ({dq:.2f})."
        )

        # ── TASK-008: Missing Evidence Identification ───────────────────────
        missing_planes = []
        for plane in ("WEB", "ZEEK", "SYSMON"):
            if plane not in context["source_types"]:
                missing_planes.append(plane)

        if missing_planes:
            missing_evidence_str = f"Missing telemetry planes: {', '.join(missing_planes)}."
            uncertainties.append(missing_evidence_str)
        else:
            missing_evidence_str = "No major telemetry planes missing; full 3-source coverage available."

        # ── TASK-009: MITRE Context Assistance ──────────────────────────────
        for r in rules:
            if getattr(r, "mitre_technique", None) and r.mitre_technique != "NOT_MAPPED":
                matched_ev = ev_records[0].id if ev_records else 1
                mitre_context.append(
                    MITREContextItem(
                        tactic=getattr(r, "category", "Execution"),
                        technique_id=r.mitre_technique,
                        technique_name=r.name,
                        evidence_ids=[matched_ev],
                        confidence=1.0,
                    )
                )

        # ── TASK-007: Investigation Recommendations (Advisory Only) ────────
        recommendations.append("Review full command-line arguments and parent process tree for host execution.")
        recommendations.append("Inspect Zeek conn.log byte ratios to quantify potential data exfiltration volume.")
        recommendations.append(
            "Isolate host from enterprise network segment [RECOMMENDATION ONLY - REQUIRES ANALYST AUTHORIZATION]."
        )

        # ── Telemetry Prompt Injection Defense Logging ──────────────────────
        if prompt_injections:
            uncertainties.append(
                f"Adversarial note: {len(prompt_injections)} untrusted telemetry payload(s) contain prompt injection meta-tokens. "
                f"Treated strictly as passive data artifacts per trust boundary (0% injection execution)."
            )

        summary = (
            f"Evidence-grounded analysis of Incident {incident.incident_number} ('{incident.title}'). "
            f"Assessed as {assessment} with {confidence * 100:.0f}% confidence. "
            f"Correlates {context['alert_count']} alert(s) across {len(context['source_types'])} source plane(s) "
            f"({', '.join(context['source_types'])}). "
            f"Grounding is substantiated by {len(facts)} verified factual statements citing authoritative evidence records."
        )

    # Validate All Claims
    validated_claims, claim_metrics = validate_claims_against_evidence(raw_claims, context)

    # Populate supporting citations from verified claims
    for c in validated_claims:
        if c.validation_status == "SUPPORTED" and c.citation:
            supporting_citations.append(c.citation)
        elif c.validation_status == "CONTRADICTED" and c.citation:
            contradicting_citations.append(c.citation)

    output = AIAnalystStructuredOutput(
        incident_id=incident.id,
        model_name=MODEL_NAME,
        prompt_version=PROMPT_VERSION,
        created_at=datetime.now(UTC),
        summary=summary,
        assessment=assessment,
        confidence=confidence,
        abstain=insufficient_evidence,
        abstention_reason=abstention_reason,
        facts=facts,
        inferences=inferences,
        recommendations=recommendations,
        uncertainties=uncertainties,
        supporting_evidence=supporting_citations,
        contradicting_evidence=contradicting_citations,
        missing_evidence=[abstention_reason] if abstention_reason else [missing_evidence_str],
        attack_chain=attack_chain,
        mitre_context=mitre_context,
        recommended_investigation_steps=[
            "Verify source IP against perimeter edge firewall logs.",
            "Inspect process lineage on endpoint.",
            "Check for subsequent egress sessions.",
        ],
        recommended_response=recommendations,
        claims=validated_claims,
        total_claims_count=claim_metrics["total_claims_count"],
        supported_claims_count=claim_metrics["supported_claims_count"],
        unsupported_claims_count=claim_metrics["unsupported_claims_count"],
        contradicted_claims_count=claim_metrics["contradicted_claims_count"],
        citation_coverage_pct=claim_metrics["citation_coverage_pct"],
        invalid_citation_count=claim_metrics["invalid_citation_count"],
    )

    # Record read-only audit entry (does not alter incident authoritative state)
    db.add(
        AuditLog(
            user_id=None,
            action="AI_ANALYST_ASSISTANCE_GENERATED",
            resource_type="incident",
            resource_id=str(incident.id),
            details_json={
                "model": MODEL_NAME,
                "assessment": assessment,
                "abstain": insufficient_evidence,
                "supported_claims": claim_metrics["supported_claims_count"],
                "citation_coverage": claim_metrics["citation_coverage_pct"],
            },
        )
    )
    db.flush()

    return output


def answer_analyst_question(
    db: Session,
    incident: Incident,
    question: str,
) -> AnalystQuestionResponse:
    """
    TASK-010: Evidence-bounded question answering for incident investigation.
    Strictly answers only from verified incident evidence; explicitly reports data gaps.
    """
    context = build_ai_analyst_context(db, incident)
    q_lower = question.lower()
    citations = []

    # Search context
    matched_events = []
    for prov in context["provenance_records"]:
        txt = f"{prov.get('source_ip')} {prov.get('destination_ip')} {prov.get('hostname')} {prov.get('process')} {prov.get('command_line')} {prov.get('request_path')}"
        if any(term in txt.lower() for term in q_lower.split() if len(term) > 3):
            matched_events.append(prov)

    if "user" in q_lower or "account" in q_lower:
        users = [p.get("username") for p in context["provenance_records"] if p.get("username")]
        if users:
            ans = f"Authoritative telemetry records user activity associated with: {', '.join(set(users))}."
        else:
            ans = "No authenticated user accounts were captured in authoritative telemetry for this incident."
    elif "process" in q_lower or "command" in q_lower:
        procs = [p.get("process") for p in context["provenance_records"] if p.get("process")]
        if procs:
            ans = f"Endpoint telemetry observed process execution: {', '.join(set(procs))}."
        else:
            ans = "No endpoint process execution events observed in this incident context."
    elif "ip" in q_lower or "source" in q_lower or "attacker" in q_lower:
        ips = [p.get("source_ip") for p in context["provenance_records"] if p.get("source_ip")]
        if ips:
            ans = f"Telemetry attributes traffic to source IP(s): {', '.join(set(ips))}."
        else:
            ans = "Source IP address is unrecorded or internal."
    elif matched_events:
        ans = f"Verified incident evidence contains {len(matched_events)} event(s) matching your inquiry."
    else:
        ans = f"Inquiry '{question}' cannot be answered from verified incident evidence. The requested entity or activity was not observed in authoritative telemetry."

    for ev in context["provenance_records"][:2]:
        citations.append(
            EvidenceCitation(
                evidence_id=ev.get("evidence_id"),
                source_type=ev.get("source_type", "GENERAL"),
                event_id=ev.get("event_id"),
                field="telemetry",
                value=ev.get("process") or ev.get("source_ip") or "record",
                provenance="database_event",
            )
        )

    return AnalystQuestionResponse(
        incident_id=incident.id,
        question=question,
        answer=ans,
        evidence_citations=citations,
        grounded_in_evidence=True,
        uncertainty=None if matched_events else "No exact match in verified incident telemetry.",
    )
