"""
backend/app/parsers/sysmon_parser.py

Multi-Source Telemetry Parser: Windows Sysmon Endpoint Telemetry Engine.
Supports:
- Event ID 1: Process Create
- Event ID 3: Network Connection
- Event ID 5: Process Terminated
- Event ID 7: Image Loaded
- Event ID 11: File Create
- Event ID 22: DNS Query

Input Formats Supported:
- Windows Event XML (<Event>...</Event> or <Events>...</Events>)
- Sysmon JSON / JSON Lines (flat or nested EVTX-JSON)

Guarantees:
- Safe parsing & malformed event containment (does not crash on malformed lines)
- Timestamp normalization (SystemTime, UtcTime, epoch, ISO)
- Bounded field lengths (command_line <= 8192, image_path <= 1024, dns <= 512, hash <= 256)
- Missing field handling (clean None mappings, no hallucinated defaults)
- Deterministic event IDs & raw provenance preservation
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from typing import Any, Optional


MAX_RAW_SIZE = 10 * 1024 * 1024  # 10 MB limit for safety
MAX_COMMAND_LINE_LEN = 8192
MAX_PATH_LEN = 1024
MAX_PROCESS_LEN = 255
MAX_DNS_LEN = 512
MAX_HASH_LEN = 256
MAX_MESSAGE_LEN = 4000

SUPPORTED_EVENT_IDS = {1, 3, 5, 7, 11, 22}

EVENT_ID_TYPE_MAP = {
    1: "sysmon_process_create",
    3: "sysmon_network_connection",
    5: "sysmon_process_terminate",
    7: "sysmon_image_load",
    11: "sysmon_file_create",
    22: "sysmon_dns_query",
}


def parse_sysmon_timestamp(val: Any) -> datetime:
    """Parses Sysmon timestamps safely across ISO, UtcTime, SystemTime, and epoch formats."""
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=UTC)
    if not val or val in ("-", "(empty)"):
        return datetime.now(UTC)

    # Attempt float epoch parse
    try:
        f_val = float(val)
        return datetime.fromtimestamp(f_val, UTC)
    except (ValueError, TypeError, OverflowError):
        pass

    text = str(val).strip()

    # Attempt ISO format (e.g. 2026-10-08T08:00:00.000000000Z or 2026-10-08T08:00:00Z)
    iso_clean = text.replace("Z", "+00:00")
    # Truncate nanoseconds if present (Python fromisoformat accepts up to 6 digits)
    if "." in iso_clean:
        base, frac = iso_clean.split(".", 1)
        tz_part = ""
        if "+" in frac:
            frac, tz_part = frac.split("+", 1)
            tz_part = "+" + tz_part
        elif "-" in frac:
            frac, tz_part = frac.split("-", 1)
            tz_part = "-" + tz_part
        frac = frac[:6]
        iso_clean = f"{base}.{frac}{tz_part}"

    try:
        parsed = datetime.fromisoformat(iso_clean)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        pass

    # Sysmon UtcTime string format: "2026-10-08 08:00:00.123"
    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed.replace(tzinfo=UTC)
        except ValueError:
            continue

    return datetime.now(UTC)


def safe_int(val: Any) -> Optional[int]:
    """Safely converts string or number to int, handling hex (0x...) or None."""
    if val is None or val in ("-", "(empty)", ""):
        return None
    try:
        s = str(val).strip()
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(float(s))
    except (ValueError, TypeError):
        return None


def safe_str(val: Any, max_len: int = 512) -> Optional[str]:
    """Cleans Sysmon string values, truncating to bounded size."""
    if val is None or val in ("-", "(empty)", ""):
        return None
    cleaned = str(val).strip()
    return cleaned[:max_len] if cleaned else None


def extract_process_name(image_path: Optional[str]) -> Optional[str]:
    """Extracts executable basename from Windows image path (e.g. C:\\Windows\\System32\\cmd.exe -> cmd.exe)."""
    if not image_path:
        return None
    # Normalize backslashes
    normalized = image_path.replace("/", "\\")
    name = normalized.split("\\")[-1]
    return safe_str(name, max_len=MAX_PROCESS_LEN)


def _strip_ns(tag: str) -> str:
    """Removes XML namespace prefix from element tag."""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def parse_sysmon_xml_event(event_el: ET.Element) -> dict[str, Any]:
    """Extracts raw key-value dictionary from a single Sysmon <Event> XML element."""
    result: dict[str, Any] = {}

    for child in event_el:
        tag = _strip_ns(child.tag)
        if tag == "System":
            for sys_child in child:
                sys_tag = _strip_ns(sys_child.tag)
                if sys_tag == "EventID":
                    result["EventID"] = sys_child.text.strip() if sys_child.text else None
                elif sys_tag == "TimeCreated":
                    result["SystemTime"] = sys_child.attrib.get("SystemTime")
                elif sys_tag == "Computer":
                    result["Computer"] = sys_child.text.strip() if sys_child.text else None
                elif sys_tag == "EventRecordID":
                    result["EventRecordID"] = sys_child.text.strip() if sys_child.text else None
                elif sys_tag == "Execution":
                    result["ExecutionProcessID"] = sys_child.attrib.get("ProcessID")
        elif tag == "EventData":
            for data_child in child:
                data_tag = _strip_ns(data_child.tag)
                if data_tag == "Data":
                    name = data_child.attrib.get("Name")
                    if name:
                        result[name] = data_child.text.strip() if data_child.text else ""
                else:
                    # Direct element name (e.g. <ProcessId>123</ProcessId>)
                    if data_child.text:
                        result[data_tag] = data_child.text.strip()

    return result


def parse_sysmon_xml(xml_content: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Safely parses Windows Event XML content (single or multiple <Event> elements)."""
    events: list[dict[str, Any]] = []
    errors: list[str] = []

    clean_xml = xml_content.strip()
    if not clean_xml:
        return events, errors

    # Check length
    if len(clean_xml) > MAX_RAW_SIZE:
        return events, ["XML content exceeds 10MB safety limit"]

    # Wrap in root if multiple events without a common root
    wrapped_xml = clean_xml
    if not (clean_xml.startswith("<Events") or clean_xml.startswith("<?xml")):
        if clean_xml.startswith("<Event"):
            # Check if multiple <Event> tags exist
            event_count = clean_xml.count("<Event")
            if event_count > 1:
                wrapped_xml = f"<Events>{clean_xml}</Events>"

    try:
        root = ET.fromstring(wrapped_xml)
    except ET.ParseError as e:
        # Attempt line-by-line or regex fallback for malformed multi-event XML
        event_matches = re.findall(r"<Event[\s\S]*?</Event>", clean_xml, flags=re.IGNORECASE)
        if not event_matches:
            errors.append(f"Malformed XML syntax: {str(e)[:120]}")
            return events, errors

        for idx, match_str in enumerate(event_matches, 1):
            try:
                el = ET.fromstring(match_str)
                raw_dict = parse_sysmon_xml_event(el)
                norm = normalize_sysmon_event(raw_dict, raw_log=match_str)
                events.append(norm)
            except Exception as item_err:
                errors.append(f"Event #{idx} XML parse error: {str(item_err)[:100]}")
        return events, errors

    # Root parsed successfully
    root_tag = _strip_ns(root.tag)
    if root_tag == "Event":
        try:
            raw_dict = parse_sysmon_xml_event(root)
            norm = normalize_sysmon_event(raw_dict, raw_log=ET.tostring(root, encoding="unicode"))
            events.append(norm)
        except Exception as e:
            errors.append(f"Failed to normalize XML Event: {str(e)[:120]}")
    else:
        for idx, child in enumerate(root, 1):
            if _strip_ns(child.tag) == "Event":
                try:
                    raw_dict = parse_sysmon_xml_event(child)
                    raw_str = ET.tostring(child, encoding="unicode")
                    norm = normalize_sysmon_event(raw_dict, raw_log=raw_str)
                    events.append(norm)
                except Exception as child_err:
                    errors.append(f"Event #{idx} parse error: {str(child_err)[:100]}")

    return events, errors


def parse_sysmon_json(json_content: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Parses JSON or JSON Lines formatted Sysmon telemetry."""
    events: list[dict[str, Any]] = []
    errors: list[str] = []

    clean_content = json_content.strip()
    if not clean_content:
        return events, errors

    # Check if single JSON array or object
    if (clean_content.startswith("[") and clean_content.endswith("]")) or (
        clean_content.startswith("{") and clean_content.endswith("}") and "\n" not in clean_content
    ):
        try:
            data = json.loads(clean_content)
            if isinstance(data, list):
                for idx, item in enumerate(data, 1):
                    if isinstance(item, dict):
                        norm = normalize_sysmon_event(item, raw_log=json.dumps(item))
                        events.append(norm)
                    else:
                        errors.append(f"Item #{idx} is not a valid JSON object")
            elif isinstance(data, dict):
                norm = normalize_sysmon_event(data, raw_log=clean_content)
                events.append(norm)
            return events, errors
        except json.JSONDecodeError:
            pass  # Fall through to JSON Lines

    # JSON Lines parsing
    for line_num, line in enumerate(clean_content.splitlines(), 1):
        s_line = line.strip()
        if not s_line or s_line.startswith("#"):
            continue
        try:
            item = json.loads(s_line)
            if isinstance(item, dict):
                norm = normalize_sysmon_event(item, raw_log=s_line)
                events.append(norm)
            else:
                errors.append(f"Line {line_num}: item is not a JSON object")
        except json.JSONDecodeError as jde:
            errors.append(f"Line {line_num}: malformed JSON: {str(jde)[:80]}")

    return events, errors


def parse_sysmon_log(content: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Auto-detects format (XML vs JSON/JSONL) and parses Sysmon events safely."""
    clean = content.strip()
    if not clean:
        return [], []

    # XML detection
    if clean.startswith("<") or "<Event" in clean:
        return parse_sysmon_xml(clean)

    # Otherwise parse as JSON / JSONL
    return parse_sysmon_json(clean)


def _first_val(data: dict[str, Any], *keys: str) -> Any:
    """Finds first matching key in dictionary (case-insensitive key search)."""
    # Direct check
    for k in keys:
        if k in data and data[k] not in (None, ""):
            return data[k]

    # Lowercase lookup map
    lower_map = {k.lower(): v for k, v in data.items()}
    for k in keys:
        lk = k.lower()
        if lk in lower_map and lower_map[lk] not in (None, ""):
            return lower_map[lk]

    return None


def normalize_sysmon_event(event_dict: dict[str, Any], raw_log: str = "") -> dict[str, Any]:
    """
    Maps raw Sysmon event dictionary (XML or JSON) into standardized NormalizedEvent schema.
    Supports Event IDs 1, 3, 5, 7, 11, 22.
    """
    # Handle nested EVTX JSON format if present
    data = dict(event_dict)
    system_data = data.get("System", {})
    event_data = data.get("EventData", {})
    if isinstance(system_data, dict):
        data.update(system_data)
    if isinstance(event_data, dict):
        data.update(event_data)

    # 1. Extract Event ID
    event_id_raw = _first_val(data, "EventID", "event_id", "EventId", "Id")
    event_id_num = safe_int(event_id_raw)

    # 2. Extract Timestamp
    ts_val = _first_val(data, "UtcTime", "SystemTime", "TimeCreated", "@SystemTime", "timestamp", "Time")
    timestamp = parse_sysmon_timestamp(ts_val)

    # 3. Host and User
    computer = safe_str(_first_val(data, "Computer", "computer", "hostname", "Host"), max_len=255)
    username = safe_str(_first_val(data, "User", "user", "username", "UserName"), max_len=128)

    # 4. Process Attributes
    image = safe_str(_first_val(data, "Image", "image", "image_path", "ImagePath"), max_len=MAX_PATH_LEN)
    process = extract_process_name(image) or safe_str(_first_val(data, "process", "ProcessName"), max_len=MAX_PROCESS_LEN)

    parent_image = safe_str(_first_val(data, "ParentImage", "parent_image", "ParentImagePath"), max_len=MAX_PATH_LEN)
    parent_process = extract_process_name(parent_image) or safe_str(_first_val(data, "parent_process"), max_len=MAX_PROCESS_LEN)

    process_id = safe_int(_first_val(data, "ProcessId", "process_id", "ProcessID", "pid"))
    parent_process_id = safe_int(_first_val(data, "ParentProcessId", "parent_process_id", "ParentProcessID", "ppid"))

    command_line = safe_str(_first_val(data, "CommandLine", "command_line", "CmdLine"), max_len=MAX_COMMAND_LINE_LEN)
    file_hash = safe_str(_first_val(data, "Hashes", "hashes", "file_hash", "Hash"), max_len=MAX_HASH_LEN)

    # 5. Network Attributes (Event 3)
    source_ip = safe_str(_first_val(data, "SourceIp", "source_ip", "SrcIp"), max_len=64)
    destination_ip = safe_str(_first_val(data, "DestinationIp", "destination_ip", "DstIp"), max_len=64)
    source_port = safe_int(_first_val(data, "SourcePort", "source_port", "SrcPort"))
    destination_port = safe_int(_first_val(data, "DestinationPort", "destination_port", "DstPort"))
    protocol = safe_str(_first_val(data, "Protocol", "protocol", "proto"), max_len=32)

    # 6. DNS Attributes (Event 22)
    dns_query = safe_str(_first_val(data, "QueryName", "query_name", "dns_query", "Query"), max_len=MAX_DNS_LEN)
    dns_response = safe_str(_first_val(data, "QueryResults", "query_results", "dns_response", "Answers"), max_len=2048)

    # 7. File & Image Load Attributes (Event 7, 11)
    target_filename = safe_str(_first_val(data, "TargetFilename", "target_filename", "FileName"), max_len=MAX_PATH_LEN)
    image_loaded = safe_str(_first_val(data, "ImageLoaded", "image_loaded"), max_len=MAX_PATH_LEN)

    # 8. Provenance & Entity Identifiers
    process_guid = safe_str(_first_val(data, "ProcessGuid", "process_guid", "ProcessGUID"), max_len=128)
    event_record_id = safe_str(_first_val(data, "EventRecordID", "event_record_id"), max_len=64)
    raw_reference = process_guid or event_record_id or target_filename or dns_query

    # Deterministic event identifier
    if event_record_id and computer:
        event_uid = f"SYSMON-{computer}-{event_record_id}"
    elif process_guid and event_id_num:
        event_uid = f"SYSMON-E{event_id_num}-{process_guid}"
    else:
        digest_input = f"{timestamp.isoformat()}-{computer}-{event_id_num}-{process_id}-{image}-{raw_reference}"
        event_uid = "SYSMON-" + hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:16]

    # Map Event Type
    event_type = EVENT_ID_TYPE_MAP.get(event_id_num or 0, f"sysmon_event_{event_id_num or 'unknown'}")

    # Build Contextual Message
    if event_id_num == 1:
        msg = f"Process Create: {process or 'unknown'} (PID: {process_id}) by {parent_process or 'unknown'} (PPID: {parent_process_id})"
    elif event_id_num == 3:
        msg = f"Network Connection: {process or 'unknown'} (PID: {process_id}) {source_ip}:{source_port} -> {destination_ip}:{destination_port} ({protocol or 'unknown'})"
    elif event_id_num == 5:
        msg = f"Process Terminated: {process or 'unknown'} (PID: {process_id})"
    elif event_id_num == 7:
        loaded_name = extract_process_name(image_loaded) or image_loaded
        msg = f"Image Loaded: {loaded_name} by {process or 'unknown'} (PID: {process_id})"
    elif event_id_num == 11:
        msg = f"File Create: {target_filename} by {process or 'unknown'} (PID: {process_id})"
    elif event_id_num == 22:
        msg = f"DNS Query: {dns_query} by {process or 'unknown'} (PID: {process_id})"
    else:
        msg = f"Sysmon Event ID {event_id_num}: {process or 'endpoint activity'}"

    # Use TargetFilename or ImageLoaded as image_path or raw_reference if appropriate
    effective_image_path = image or image_loaded
    if event_id_num == 11 and target_filename:
        # For file create, image_path is the creating process image, raw_reference is target file
        raw_reference = target_filename

    return {
        "event_id": event_uid,
        "timestamp": timestamp,
        "source_type": "SYSMON",
        "source_name": "Microsoft-Windows-Sysmon",
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol.lower() if protocol else None,
        "connection_state": None,
        "bytes_in": None,
        "bytes_out": None,
        "response_time_ms": None,
        "dns_query": dns_query,
        "dns_response": dns_response,
        "username": username,
        "hostname": computer,
        "process": process,
        "parent_process": parent_process,
        "process_id": process_id,
        "parent_process_id": parent_process_id,
        "command_line": command_line,
        "image_path": effective_image_path,
        "file_hash": file_hash,
        "event_type": event_type,
        "event_category": "endpoint",
        "severity": "low",
        "message": msg[:MAX_MESSAGE_LEN],
        "raw_reference": raw_reference,
        "raw_log": raw_log[:MAX_COMMAND_LINE_LEN] if raw_log else json.dumps(data)[:MAX_COMMAND_LINE_LEN],
        "user_agent": None,
        "request_path": None,
        "http_method": None,
        "status_code": None,
        "geo_country": None,
    }
