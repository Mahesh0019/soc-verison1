"""
backend/app/parsers/zeek_parser.py

Multi-Source Telemetry Parser: Zeek Network Telemetry Engine.
Supports:
- conn.log (connection state, duration, bytes in/out, protocol, ports)
- http.log (web methods, hostnames, URIs, status codes, user agents)
- dns.log (DNS queries, query types, response codes, answer records)
Supports both standard Zeek TSV (with #fields header) and Zeek streaming JSON lines.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any, Optional


def parse_zeek_timestamp(val: Any) -> datetime:
    """Parses Zeek epoch float or ISO timestamp safely."""
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=UTC)
    if not val or val in ("-", "(empty)"):
        return datetime.now(UTC)

    # Attempt float epoch parse (e.g. 1728374400.123456)
    try:
        f_val = float(val)
        return datetime.fromtimestamp(f_val, UTC)
    except (ValueError, TypeError, OverflowError):
        pass

    # Attempt ISO timestamp parse
    text = str(val).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        pass

    # Zeek formatted string e.g. 2026-10-08-08-00-00
    for fmt in ("%Y-%m-%d-%H-%M-%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed.replace(tzinfo=UTC)
        except ValueError:
            continue

    return datetime.now(UTC)


def safe_int(val: Any) -> Optional[int]:
    """Safely converts Zeek counts/ports to int, mapping '-' or invalid strings to None."""
    if val is None or val in ("-", "(empty)", ""):
        return None
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return None


def safe_float(val: Any) -> Optional[float]:
    """Safely converts Zeek intervals/durations to float."""
    if val is None or val in ("-", "(empty)", ""):
        return None
    try:
        return float(val)
    except (ValueError, TypeError):
        return None


def safe_str(val: Any, max_len: int = 512) -> Optional[str]:
    """Cleans Zeek string values, mapping '-' and '(empty)' to None."""
    if val is None or val in ("-", "(empty)", ""):
        return None
    cleaned = str(val).strip()
    return cleaned[:max_len] if cleaned else None


def detect_zeek_log_type(header_or_sample: str) -> str:
    """Infers whether content is conn.log, http.log, or dns.log."""
    lower = header_or_sample.lower()
    if "#path\tconn" in lower or '"_path":"conn"' in lower:
        return "conn"
    if "#path\thttp" in lower or '"_path":"http"' in lower:
        return "http"
    if "#path\tdns" in lower or '"_path":"dns"' in lower:
        return "dns"

    # Heuristic detection based on field names
    if "dns_query" in lower or "qtype" in lower or "answers" in lower:
        return "dns"
    if "request_body_len" in lower or "user_agent" in lower or "uri" in lower:
        return "http"
    if "conn_state" in lower or "orig_bytes" in lower or "resp_bytes" in lower or "proto" in lower:
        return "conn"

    return "conn"


def normalize_zeek_conn(data: dict[str, Any], raw_line: str) -> dict[str, Any]:
    """Normalizes Zeek conn.log record into NormalizedEvent representation."""
    src_ip = safe_str(data.get("id.orig_h") or data.get("id_orig_h") or data.get("orig_h"), 64)
    dst_ip = safe_str(data.get("id.resp_h") or data.get("id_resp_h") or data.get("resp_h"), 64)
    src_port = safe_int(data.get("id.orig_p") or data.get("id_orig_p") or data.get("orig_p"))
    dst_port = safe_int(data.get("id.resp_p") or data.get("id_resp_p") or data.get("resp_p"))
    proto = safe_str(data.get("proto") or "tcp", 32).lower()
    conn_state = safe_str(data.get("conn_state"), 32)
    duration = safe_float(data.get("duration"))
    duration_ms = round(duration * 1000.0, 2) if duration is not None else None
    orig_bytes = safe_int(data.get("orig_bytes"))
    resp_bytes = safe_int(data.get("resp_bytes"))
    uid = safe_str(data.get("uid"), 64)

    # Severity and event classification
    is_rejected = conn_state in ("REJ", "RSTO", "RSTR")
    is_suspicious_port = dst_port in (1337, 31337, 4444, 6667)
    if is_rejected:
        severity = "medium"
        event_type = "zeek_conn_rejected"
    elif is_suspicious_port:
        severity = "high"
        event_type = "zeek_suspicious_port"
    else:
        severity = "low"
        event_type = "zeek_connection"

    dur_text = f" ({duration_ms}ms)" if duration_ms is not None else ""
    msg = f"Zeek conn: {proto.upper()} {src_ip or 'unknown'}:{src_port or 0} -> {dst_ip or 'unknown'}:{dst_port or 0} [{conn_state or 'N/A'}]{dur_text}"

    return {
        "event_id": uid,
        "timestamp": parse_zeek_timestamp(data.get("ts")),
        "source_type": "ZEEK",
        "source_name": "zeek-conn",
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "protocol": proto,
        "connection_state": conn_state,
        "bytes_in": orig_bytes,
        "bytes_out": resp_bytes,
        "response_time_ms": duration_ms,
        "event_type": event_type,
        "event_category": "network",
        "severity": severity,
        "message": msg[:4000],
        "raw_reference": uid,
        "raw_log": raw_line[:8192],
    }


def normalize_zeek_http(data: dict[str, Any], raw_line: str) -> dict[str, Any]:
    """Normalizes Zeek http.log record into NormalizedEvent representation."""
    src_ip = safe_str(data.get("id.orig_h") or data.get("id_orig_h") or data.get("orig_h"), 64)
    dst_ip = safe_str(data.get("id.resp_h") or data.get("id_resp_h") or data.get("resp_h"), 64)
    src_port = safe_int(data.get("id.orig_p") or data.get("id_orig_p") or data.get("orig_p"))
    dst_port = safe_int(data.get("id.resp_p") or data.get("id_resp_p") or data.get("resp_p"))
    method = safe_str(data.get("method"), 16)
    host = safe_str(data.get("host"), 255)
    uri = safe_str(data.get("uri"), 2048)
    user_agent = safe_str(data.get("user_agent"), 1024)
    status_code = safe_int(data.get("status_code"))
    req_len = safe_int(data.get("request_body_len"))
    resp_len = safe_int(data.get("response_body_len"))
    uid = safe_str(data.get("uid"), 64)

    if status_code == 404:
        severity = "low"
        event_type = "http_404"
    elif status_code and status_code >= 500:
        severity = "medium"
        event_type = "http_server_error"
    elif uri and any(uri.lower().startswith(s) for s in ("/admin", "/login", "/.env", "/config")):
        severity = "medium"
        event_type = "sensitive_path_access"
    else:
        severity = "low"
        event_type = "zeek_http"

    msg = f"Zeek HTTP: {method or 'GET'} {host or dst_ip or 'unknown'}{uri or '/'} -> {status_code or 200}"

    return {
        "event_id": uid,
        "timestamp": parse_zeek_timestamp(data.get("ts")),
        "source_type": "ZEEK",
        "source_name": "zeek-http",
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "protocol": "tcp",
        "hostname": host,
        "http_method": method,
        "request_path": uri,
        "user_agent": user_agent,
        "status_code": status_code,
        "bytes_in": req_len,
        "bytes_out": resp_len,
        "event_type": event_type,
        "event_category": "web",
        "severity": severity,
        "message": msg[:4000],
        "raw_reference": uid,
        "raw_log": raw_line[:8192],
    }


def normalize_zeek_dns(data: dict[str, Any], raw_line: str) -> dict[str, Any]:
    """Normalizes Zeek dns.log record into NormalizedEvent representation."""
    src_ip = safe_str(data.get("id.orig_h") or data.get("id_orig_h") or data.get("orig_h"), 64)
    dst_ip = safe_str(data.get("id.resp_h") or data.get("id_resp_h") or data.get("resp_h"), 64)
    src_port = safe_int(data.get("id.orig_p") or data.get("id_orig_p") or data.get("orig_p"))
    dst_port = safe_int(data.get("id.resp_p") or data.get("id_resp_p") or data.get("resp_p"))
    proto = safe_str(data.get("proto") or "udp", 32).lower()
    query = safe_str(data.get("query"), 512)
    qtype = safe_str(data.get("qtype_name") or data.get("qtype"), 32) or "A"
    rcode = safe_str(data.get("rcode_name") or data.get("rcode"), 32) or "NOERROR"
    answers_val = data.get("answers")
    if isinstance(answers_val, list):
        answers = ", ".join(str(a) for a in answers_val if a not in ("-", "(empty)"))
    else:
        answers = safe_str(answers_val, 1024) or ""
    uid = safe_str(data.get("uid"), 64)

    is_nxdomain = rcode in ("NXDOMAIN", "REFUSED")
    severity = "medium" if is_nxdomain else "low"
    event_type = "zeek_dns_nxdomain" if is_nxdomain else "zeek_dns"

    ans_text = f" [{answers}]" if answers else ""
    msg = f"Zeek DNS: query {query or 'N/A'} ({qtype}) -> {rcode}{ans_text}"

    return {
        "event_id": uid,
        "timestamp": parse_zeek_timestamp(data.get("ts")),
        "source_type": "ZEEK",
        "source_name": "zeek-dns",
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "protocol": proto,
        "dns_query": query,
        "dns_response": answers or rcode,
        "event_type": event_type,
        "event_category": "network",
        "severity": severity,
        "message": msg[:4000],
        "raw_reference": uid,
        "raw_log": raw_line[:8192],
    }


def parse_zeek_tsv(content: str, forced_type: Optional[str] = None) -> tuple[list[dict[str, Any]], list[str], dict[str, int]]:
    """
    Parses standard Zeek TSV log format with dynamic #fields header.
    Returns: (normalized_events, error_lines, stats_dict)
    """
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    stats = {"processed": 0, "accepted": 0, "rejected": 0, "duplicated": 0}

    fields: list[str] = []
    log_type = forced_type
    seen_references: set[str] = set()

    for line_no, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue

        if "\t" not in line and "\\t" in line:
            line = line.replace("\\t", "\t")

        # Check Zeek header directives
        if line.startswith("#"):
            if line.startswith("#path"):
                parts = line.split("\t")
                if len(parts) >= 2 and not forced_type:
                    log_type = parts[1].strip()
            elif line.startswith("#fields"):
                fields = [f.strip() for f in line.split("\t")[1:]]
            continue

        stats["processed"] += 1

        if not fields:
            # Fallback if no #fields directive was found prior to data lines
            errors.append(f"Line {line_no}: Missing #fields header directive in Zeek TSV")
            stats["rejected"] += 1
            continue

        tokens = line.split("\t")
        if len(tokens) != len(fields):
            # Attempt recovery or reject malformed line
            if len(tokens) < len(fields) and len(tokens) >= 5:
                # Pad with '-'
                tokens.extend(["-"] * (len(fields) - len(tokens)))
            else:
                errors.append(f"Line {line_no}: Field count mismatch (expected {len(fields)}, found {len(tokens)})")
                stats["rejected"] += 1
                continue

        record = dict(zip(fields, tokens))
        resolved_type = log_type or detect_zeek_log_type("\t".join(fields))

        try:
            if resolved_type == "http":
                norm = normalize_zeek_http(record, line)
            elif resolved_type == "dns":
                norm = normalize_zeek_dns(record, line)
            else:
                norm = normalize_zeek_conn(record, line)

            # Check duplication by raw_reference
            ref = norm.get("raw_reference")
            if ref and ref in seen_references:
                stats["duplicated"] += 1
            if ref:
                seen_references.add(ref)

            events.append(norm)
            stats["accepted"] += 1
        except Exception as exc:
            errors.append(f"Line {line_no}: Normalization error: {exc}")
            stats["rejected"] += 1

    return events, errors, stats


def parse_zeek_json(content: str, forced_type: Optional[str] = None) -> tuple[list[dict[str, Any]], list[str], dict[str, int]]:
    """
    Parses streaming Zeek JSON lines format.
    Returns: (normalized_events, error_lines, stats_dict)
    """
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    stats = {"processed": 0, "accepted": 0, "rejected": 0, "duplicated": 0}
    seen_references: set[str] = set()

    for line_no, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue

        stats["processed"] += 1

        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError("JSON line is not an object")
        except Exception as exc:
            errors.append(f"Line {line_no}: Malformed JSON line: {exc}")
            stats["rejected"] += 1
            continue

        # Flatten nested 'id' dictionary if present (e.g. {"id": {"orig_h": ...}})
        if "id" in record and isinstance(record["id"], dict):
            for k, v in record["id"].items():
                record[f"id.{k}"] = v
                record[f"id_{k}"] = v

        resolved_type = forced_type or record.get("_path") or detect_zeek_log_type(line)

        try:
            if resolved_type == "http":
                norm = normalize_zeek_http(record, line)
            elif resolved_type == "dns":
                norm = normalize_zeek_dns(record, line)
            else:
                norm = normalize_zeek_conn(record, line)

            ref = norm.get("raw_reference")
            if ref and ref in seen_references:
                stats["duplicated"] += 1
            if ref:
                seen_references.add(ref)

            events.append(norm)
            stats["accepted"] += 1
        except Exception as exc:
            errors.append(f"Line {line_no}: Normalization error: {exc}")
            stats["rejected"] += 1

    return events, errors, stats


def parse_zeek_content(content: str, forced_type: Optional[str] = None) -> tuple[list[dict[str, Any]], list[str], dict[str, int]]:
    """Auto-detects format (TSV vs JSON) and parses Zeek log content."""
    stripped = content.strip()
    if not stripped:
        return [], [], {"processed": 0, "accepted": 0, "rejected": 0, "duplicated": 0}

    # If lines begin with '{' or '[', parse as JSON
    first_char = stripped[0]
    if first_char in ("{", "["):
        return parse_zeek_json(content, forced_type)

    # If first line contains # or tabs, parse as TSV
    first_line = stripped.split("\n", 1)[0]
    if first_line.startswith("#") or "\t" in first_line:
        return parse_zeek_tsv(content, forced_type)

    # Fallback to TSV
    return parse_zeek_tsv(content, forced_type)
