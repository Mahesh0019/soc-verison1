"""
backend/app/services/zeek_service.py

Zeek Network Telemetry Ingestion & Replay Engine:
- Ingests and replays Zeek conn.log, http.log, and dns.log files (TSV or JSON).
- Performs streaming normalization, deduplication detection, and latency benchmarking.
- Integrates seamlessly with NormalizedEvent persistence and the detection engine.
- Measures throughput (eps), latency (avg/max ms), accepted, rejected, and duplicated events.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import NormalizedEvent, RawLog
from app.parsers.zeek_parser import detect_zeek_log_type, parse_zeek_content
from app.rules.engine import evaluate_rules_for_events


settings = get_settings()


def ingest_zeek_telemetry(
    db: Session,
    content: str,
    log_type: Optional[str] = None,
    mode: str = "REPLAY",
    file_name: Optional[str] = None,
    user_id: Optional[int] = None,
) -> dict[str, Any]:
    """
    Ingests and replays Zeek telemetry logs (conn, http, dns) with full metrics tracking.
    Modes: LIVE, REPLAY, SIMULATED.
    """
    start_time = time.perf_counter()

    resolved_type = log_type if log_type in ("conn", "http", "dns") else detect_zeek_log_type(content)
    raw_preview = content[: settings.max_upload_bytes] if content else ""

    # Parse and normalize content
    parse_start = time.perf_counter()
    normalized_items, parse_errors, stats = parse_zeek_content(content, forced_type=resolved_type)
    parse_time_sec = max(0.000001, time.perf_counter() - parse_start)
    parse_time_ms = round(parse_time_sec * 1000.0, 3)
    parser_throughput_eps = round(stats["processed"] / parse_time_sec, 2) if stats["processed"] else 0.0

    # Store RawLog provenance & persist NormalizedEvents (Ingestion DB stage)
    db_start = time.perf_counter()
    raw_log = RawLog(
        source_type=f"ZEEK_{resolved_type.upper()}_{mode.upper()}",
        original_content=raw_preview,
        file_name=file_name or f"zeek_{resolved_type}_{int(time.time())}.log",
        uploaded_by=user_id,
    )
    db.add(raw_log)
    db.flush()

    events: list[NormalizedEvent] = []
    latencies: list[float] = []

    for item in normalized_items:
        t0 = time.perf_counter()
        ev = NormalizedEvent(raw_log_id=raw_log.id, **item)
        db.add(ev)
        events.append(ev)
        latencies.append((time.perf_counter() - t0) * 1000.0)

    db.flush()
    db_persistence_time_sec = max(0.000001, time.perf_counter() - db_start)
    db_persistence_time_ms = round(db_persistence_time_sec * 1000.0, 3)

    ingestion_time_sec = max(0.000001, parse_time_sec + db_persistence_time_sec)
    ingestion_throughput_eps = round(len(events) / ingestion_time_sec, 2) if events else 0.0

    # Natural detection evaluation & alert generation
    detect_start = time.perf_counter()
    alert_count = evaluate_rules_for_events(db, events, auto_correlate=True)
    db.commit()
    detection_time_sec = max(0.000001, time.perf_counter() - detect_start)
    detection_time_ms = round(detection_time_sec * 1000.0, 3)
    detection_throughput_eps = round(len(events) / detection_time_sec, 2) if events else 0.0

    total_time_sec = max(0.000001, time.perf_counter() - start_time)
    throughput_eps = round(len(events) / total_time_sec, 2)
    avg_lat = round(sum(latencies) / len(latencies), 3) if latencies else 0.0
    max_lat = round(max(latencies), 3) if latencies else 0.0

    return {
        "raw_log_id": raw_log.id,
        "log_type": resolved_type,
        "mode": mode.upper(),
        "events_processed": stats["processed"],
        "events_accepted": stats["accepted"],
        "events_rejected": stats["rejected"],
        "events_duplicated": stats["duplicated"],
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
