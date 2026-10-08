"""
backend/app/services/sysmon_service.py

Sysmon Endpoint Telemetry Ingestion & Replay Engine:
- Ingests and replays Windows Sysmon logs in XML or JSON / JSON Lines format.
- Supports Event IDs 1 (Process Create), 3 (Network Connection), 5 (Process Terminate),
  7 (Image Load), 11 (File Create), 22 (DNS Query).
- Performs streaming normalization, missing field containment, and latency benchmarking.
- Integrates with NormalizedEvent persistence and the endpoint detection engine.
- Measures throughput and latency distinctly:
  * parser_throughput_eps, parse_time_ms
  * ingestion_throughput_eps, db_persistence_time_ms
  * detection_throughput_eps, detection_latency_ms
  * total_soc_throughput_eps, average_latency_ms, maximum_latency_ms
- Adheres to Phase 5 boundary: evaluates detection rules WITHOUT cross-source correlation.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import NormalizedEvent, RawLog
from app.parsers.sysmon_parser import parse_sysmon_log
from app.rules.engine import evaluate_rules_for_events


settings = get_settings()


def ingest_sysmon_telemetry(
    db: Session,
    content: str,
    mode: str = "REPLAY",
    file_name: Optional[str] = None,
    user_id: Optional[int] = None,
) -> dict[str, Any]:
    """
    Ingests and replays Sysmon endpoint telemetry (XML or JSON) with comprehensive metrics tracking.
    Modes: LIVE, REPLAY, SIMULATED.
    """
    start_time = time.perf_counter()

    raw_preview = content[: settings.max_upload_bytes] if content else ""

    # Stage 1: Parse and normalize Sysmon content
    parse_start = time.perf_counter()
    normalized_items, parse_errors = parse_sysmon_log(content)
    parse_time_sec = max(0.000001, time.perf_counter() - parse_start)
    parse_time_ms = round(parse_time_sec * 1000.0, 3)

    if "<Event" in content or "<Events" in content:
        import re
        event_tag_count = len(re.findall(r"<Event[\s>]", content, flags=re.IGNORECASE))
        processed_count = max(len(normalized_items) + len(parse_errors), event_tag_count)
    else:
        raw_count = len([ln for ln in content.strip().splitlines() if ln.strip() and not ln.strip().startswith("#")]) if content.strip() else 0
        processed_count = max(len(normalized_items) + len(parse_errors), raw_count)
    parser_throughput_eps = round(processed_count / parse_time_sec, 2) if processed_count else 0.0

    # Stage 2: Store RawLog provenance & persist NormalizedEvents
    db_start = time.perf_counter()
    raw_log = RawLog(
        source_type=f"SYSMON_{mode.upper()}",
        original_content=raw_preview,
        file_name=file_name or f"sysmon_replay_{int(time.time())}.log",
        uploaded_by=user_id,
    )
    db.add(raw_log)
    db.flush()

    events: list[NormalizedEvent] = []
    latencies: list[float] = []

    seen_event_ids: set[str] = set()
    duplicated_count = 0

    for item in normalized_items:
        t0 = time.perf_counter()
        ev_id = item.get("event_id")
        if ev_id and ev_id in seen_event_ids:
            duplicated_count += 1
            continue
        if ev_id:
            seen_event_ids.add(ev_id)

        ev = NormalizedEvent(raw_log_id=raw_log.id, **item)
        db.add(ev)
        events.append(ev)
        latencies.append((time.perf_counter() - t0) * 1000.0)

    db.flush()
    db_persistence_time_sec = max(0.000001, time.perf_counter() - db_start)
    db_persistence_time_ms = round(db_persistence_time_sec * 1000.0, 3)

    ingestion_time_sec = max(0.000001, parse_time_sec + db_persistence_time_sec)
    ingestion_throughput_eps = round(len(events) / ingestion_time_sec, 2) if events else 0.0

    # Stage 3: Endpoint detection evaluation (auto_correlate=False preserves Phase 5 boundary)
    detect_start = time.perf_counter()
    alert_count = evaluate_rules_for_events(db, events, auto_correlate=False)
    db.commit()
    detection_time_sec = max(0.000001, time.perf_counter() - detect_start)
    detection_time_ms = round(detection_time_sec * 1000.0, 3)
    detection_throughput_eps = round(len(events) / detection_time_sec, 2) if events else 0.0

    total_time_sec = max(0.000001, time.perf_counter() - start_time)
    throughput_eps = round(len(events) / total_time_sec, 2)
    avg_lat = round(sum(latencies) / len(latencies), 3) if latencies else 0.0
    max_lat = round(max(latencies), 3) if latencies else 0.0

    accepted_count = len(events)
    rejected_count = len(parse_errors)

    return {
        "raw_log_id": raw_log.id,
        "source_type": "SYSMON",
        "mode": mode.upper(),
        "events_processed": processed_count,
        "events_accepted": accepted_count,
        "events_rejected": rejected_count,
        "events_duplicated": duplicated_count,
        "throughput_eps": throughput_eps,
        "average_latency_ms": avg_lat,
        "maximum_latency_ms": max_lat,
        "parse_time_ms": parse_time_ms,
        "db_persistence_time_ms": db_persistence_time_ms,
        "detection_latency_ms": detection_time_ms,
        "parser_throughput_eps": parser_throughput_eps,
        "ingestion_throughput_eps": ingestion_throughput_eps,
        "detection_throughput_eps": detection_throughput_eps,
        "total_soc_throughput_eps": throughput_eps,
        "alert_count": alert_count,
        "errors": parse_errors,
        "preview": events[:10],
    }
