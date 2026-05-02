import csv
import json
import re
from datetime import UTC, datetime
from io import StringIO
from typing import Any


WEB_ACCESS_RE = re.compile(
    r'(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+[^"]+"\s+(?P<status>\d{3})\s+\S+\s+"[^"]*"\s+"(?P<ua>[^"]*)"'
)
SSH_FAILED_RE = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<username>\S+) from (?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})"
)
SSH_ACCEPTED_RE = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+sshd\[\d+\]:\s+Accepted password for (?P<username>\S+) from (?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})"
)
FIREWALL_RE = re.compile(
    r"(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<action>ALLOW|DENY|DROP)\s+src=(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})\s+dst=(?P<destination_ip>\d{1,3}(?:\.\d{1,3}){3}).*?(?:msg=(?P<message>.*))?$",
    re.IGNORECASE,
)

SUSPICIOUS_UA = ("curl", "sqlmap", "nikto", "python-requests")
SENSITIVE_PATHS = ("/admin", "/login", "/wp-admin", "/.env", "/config", "/backup")


def sanitize_text(content: str) -> str:
    return content.replace("\x00", "").replace("\r\n", "\n")


def parse_content(source_type: str, content: str) -> tuple[list[dict[str, Any]], list[str]]:
    content = sanitize_text(content)
    if source_type == "json" or content.lstrip().startswith(("{", "[")):
        return parse_json_content(content)
    if source_type == "csv":
        return parse_csv_content(content)
    return parse_text_content(content)


def parse_json_content(content: str) -> tuple[list[dict[str, Any]], list[str]]:
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    stripped = content.strip()
    try:
        if stripped.startswith("["):
            payload = json.loads(stripped)
            for index, item in enumerate(payload, start=1):
                if isinstance(item, dict):
                    events.append(normalize_object(item, json.dumps(item)))
                else:
                    errors.append(f"JSON item {index} is not an object")
            return events, errors
    except json.JSONDecodeError:
        pass

    for line_no, line in enumerate(content.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError("line is not a JSON object")
            events.append(normalize_object(item, line))
        except (json.JSONDecodeError, ValueError) as exc:
            errors.append(f"Line {line_no}: {exc}")
            events.append(unknown_event(line))
    return events, errors


def parse_csv_content(content: str) -> tuple[list[dict[str, Any]], list[str]]:
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    reader = csv.DictReader(StringIO(content))
    if not reader.fieldnames:
        return [], ["CSV file has no header row"]
    for row_no, row in enumerate(reader, start=2):
        try:
            events.append(normalize_object(row, json.dumps(row)))
        except Exception as exc:
            errors.append(f"Row {row_no}: {exc}")
            events.append(unknown_event(json.dumps(row)))
    return events, errors


def parse_text_content(content: str) -> tuple[list[dict[str, Any]], list[str]]:
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    for line_no, raw in enumerate(content.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        parsed = parse_text_line(line)
        if parsed["event_type"] == "unknown":
            errors.append(f"Line {line_no}: stored as unknown event")
        events.append(parsed)
    return events, errors


def parse_text_line(line: str) -> dict[str, Any]:
    if match := WEB_ACCESS_RE.match(line):
        data = match.groupdict()
        status = int(data["status"])
        path = data["path"]
        user_agent = data["ua"]
        event_type = "http_404" if status == 404 else "web_request"
        if path.lower() in SENSITIVE_PATHS or any(path.lower().startswith(p + "/") for p in SENSITIVE_PATHS):
            event_type = "sensitive_path_access"
        severity = "medium" if status == 404 or is_suspicious_user_agent(user_agent) else "low"
        return {
            "timestamp": parse_timestamp(data["timestamp"]),
            "source_ip": data["source_ip"],
            "destination_ip": None,
            "username": None if data["user"] == "-" else data["user"],
            "hostname": "web-01",
            "event_type": event_type,
            "event_category": "web",
            "severity": severity,
            "message": f"{data['method']} {path} returned {status}",
            "raw_log": line,
            "user_agent": user_agent,
            "request_path": path,
            "http_method": data["method"],
            "status_code": status,
            "geo_country": infer_country(data["source_ip"]),
        }

    if match := SSH_FAILED_RE.match(line):
        data = match.groupdict()
        return {
            "timestamp": parse_timestamp(data["timestamp"]),
            "source_ip": data["source_ip"],
            "destination_ip": None,
            "username": data["username"],
            "hostname": data["hostname"],
            "event_type": "failed_login",
            "event_category": "authentication",
            "severity": "medium",
            "message": f"Failed SSH login for {data['username']}",
            "raw_log": line,
            "user_agent": None,
            "request_path": None,
            "http_method": None,
            "status_code": None,
            "geo_country": infer_country(data["source_ip"]),
        }

    if match := SSH_ACCEPTED_RE.match(line):
        data = match.groupdict()
        return {
            "timestamp": parse_timestamp(data["timestamp"]),
            "source_ip": data["source_ip"],
            "destination_ip": None,
            "username": data["username"],
            "hostname": data["hostname"],
            "event_type": "successful_login",
            "event_category": "authentication",
            "severity": "low",
            "message": f"Successful SSH login for {data['username']}",
            "raw_log": line,
            "user_agent": None,
            "request_path": None,
            "http_method": None,
            "status_code": None,
            "geo_country": infer_country(data["source_ip"]),
        }

    if match := FIREWALL_RE.match(line):
        data = match.groupdict()
        denied = data["action"].upper() in {"DENY", "DROP"}
        return {
            "timestamp": parse_timestamp(data["timestamp"]),
            "source_ip": data["source_ip"],
            "destination_ip": data["destination_ip"],
            "username": None,
            "hostname": data["hostname"],
            "event_type": "firewall_denied" if denied else "firewall_allowed",
            "event_category": "network",
            "severity": "medium" if denied else "low",
            "message": data.get("message") or f"Firewall {data['action'].upper()} traffic",
            "raw_log": line,
            "user_agent": None,
            "request_path": None,
            "http_method": None,
            "status_code": None,
            "geo_country": infer_country(data["source_ip"]),
        }

    return unknown_event(line)


def normalize_object(item: dict[str, Any], raw: str | None = None) -> dict[str, Any]:
    source_ip = first(item, "source_ip", "src_ip", "src", "client_ip", "remote_addr", "ip")
    destination_ip = first(item, "destination_ip", "dst_ip", "dst", "server_ip")
    username = first(item, "username", "user", "account", "principal")
    status_code = as_int(first(item, "status_code", "status", "http_status"))
    path = first(item, "request_path", "path", "url", "uri")
    method = first(item, "http_method", "method", "verb")
    user_agent = first(item, "user_agent", "ua", "agent")
    action = str(first(item, "event_type", "action", "event", "type") or "").lower()
    category = str(first(item, "event_category", "category", "source_type") or "").lower()
    message = str(first(item, "message", "msg", "detail") or raw or "Structured log event")

    event_type = action or infer_event_type(message, status_code, path, user_agent)
    event_category = category or infer_category(event_type, status_code)
    severity = str(first(item, "severity", "level") or infer_severity(event_type, status_code, path, user_agent)).lower()

    return {
        "timestamp": parse_timestamp(first(item, "timestamp", "time", "@timestamp", "date")),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "username": username,
        "hostname": first(item, "hostname", "host", "server"),
        "event_type": normalize_event_type(event_type),
        "event_category": event_category or "generic",
        "severity": normalize_severity(severity),
        "message": message[:4000],
        "raw_log": raw,
        "user_agent": user_agent,
        "request_path": path,
        "http_method": method,
        "status_code": status_code,
        "geo_country": first(item, "geo_country", "country") or infer_country(source_ip),
    }


def unknown_event(raw: str) -> dict[str, Any]:
    return {
        "timestamp": datetime.now(UTC),
        "source_ip": extract_ip(raw),
        "destination_ip": None,
        "username": None,
        "hostname": None,
        "event_type": "unknown",
        "event_category": "generic",
        "severity": "low",
        "message": raw[:4000],
        "raw_log": raw,
        "user_agent": None,
        "request_path": None,
        "http_method": None,
        "status_code": None,
        "geo_country": infer_country(extract_ip(raw)),
    }


def first(item: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in item and item[key] not in (None, ""):
            return item[key]
    return None


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not value:
        return datetime.now(UTC)
    text = str(value).strip()
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S"):
        try:
            parsed = datetime.strptime(text, fmt)
            if fmt == "%b %d %H:%M:%S":
                parsed = parsed.replace(year=datetime.now(UTC).year)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        return datetime.now(UTC)


def infer_event_type(message: str, status_code: int | None, path: str | None, user_agent: str | None) -> str:
    text = message.lower()
    if "failed" in text and "login" in text:
        return "failed_login"
    if ("accepted" in text or "success" in text) and "login" in text:
        return "successful_login"
    if "deny" in text or "drop" in text:
        return "firewall_denied"
    if status_code == 404:
        return "http_404"
    if path and any(path.lower().startswith(prefix) for prefix in SENSITIVE_PATHS):
        return "sensitive_path_access"
    if is_suspicious_user_agent(user_agent):
        return "suspicious_user_agent"
    return "generic_event"


def infer_category(event_type: str, status_code: int | None) -> str:
    if "login" in event_type:
        return "authentication"
    if event_type.startswith("firewall"):
        return "network"
    if event_type in {"web_request", "http_404", "sensitive_path_access", "suspicious_user_agent"} or status_code:
        return "web"
    return "generic"


def infer_severity(event_type: str, status_code: int | None, path: str | None, user_agent: str | None) -> str:
    if event_type in {"firewall_denied", "failed_login", "http_404", "sensitive_path_access"}:
        return "medium"
    if status_code and status_code >= 500:
        return "high"
    if path and path.lower() in SENSITIVE_PATHS:
        return "medium"
    if is_suspicious_user_agent(user_agent):
        return "high"
    return "low"


def normalize_event_type(value: str) -> str:
    cleaned = value.lower().strip().replace(" ", "_").replace("-", "_")
    aliases = {
        "login_failed": "failed_login",
        "auth_failure": "failed_login",
        "login_success": "successful_login",
        "auth_success": "successful_login",
        "deny": "firewall_denied",
        "drop": "firewall_denied",
    }
    return aliases.get(cleaned, cleaned or "generic_event")


def normalize_severity(value: str) -> str:
    cleaned = value.lower().strip()
    if cleaned in {"critical", "high", "medium", "low"}:
        return cleaned
    if cleaned in {"warn", "warning"}:
        return "medium"
    if cleaned in {"error", "err"}:
        return "high"
    return "low"


def as_int(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def extract_ip(text: str) -> str | None:
    match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    return match.group(0) if match else None


def is_suspicious_user_agent(user_agent: str | None) -> bool:
    if not user_agent:
        return False
    lowered = user_agent.lower()
    return any(token in lowered for token in SUSPICIOUS_UA)


def infer_country(ip: str | None) -> str | None:
    if not ip:
        return None
    if ip.startswith("203.0.113."):
        return "US"
    if ip.startswith("198.51.100."):
        return "DE"
    if ip.startswith("192.0.2."):
        return "TR"
    if ip.startswith("45."):
        return "RU"
    if ip.startswith("91."):
        return "CN"
    if ip.startswith("185."):
        return "NL"
    return "US"

