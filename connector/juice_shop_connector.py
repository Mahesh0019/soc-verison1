"""
Juice Shop Telemetry Connector

Pulls real-time telemetry from OWASP Juice Shop telemetry API endpoint
and forwards formatted log events to the Mini-SIEM ingestion API.
"""

import argparse
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("JuiceShopConnector")

# Default Constants
DEFAULT_TELEMETRY_URL = "https://demo-victim-1.onrender.com/api/telemetry/events"
DEFAULT_SIEM_INGEST_URL = "http://localhost:8000/api/logs/ingest"
DEFAULT_POLL_INTERVAL = 10.0
DEFAULT_BATCH_SIZE = 50
CHECKPOINT_FILE_PATH = Path(__file__).parent / ".checkpoint"


class ConnectorConfig:
    def __init__(self) -> None:
        self.telemetry_url = os.getenv("JUICE_SHOP_TELEMETRY_URL", DEFAULT_TELEMETRY_URL)
        self.telemetry_api_key = os.getenv("JUICE_SHOP_TELEMETRY_API_KEY", "")
        self.siem_ingest_url = os.getenv("SIEM_INGEST_URL", DEFAULT_SIEM_INGEST_URL)
        self.siem_jwt_token = os.getenv("SIEM_JWT_TOKEN", "")
        
        try:
            self.poll_interval = float(os.getenv("POLL_INTERVAL_SECONDS", str(DEFAULT_POLL_INTERVAL)))
        except ValueError:
            self.poll_interval = DEFAULT_POLL_INTERVAL

        try:
            self.batch_size = int(os.getenv("BATCH_SIZE", str(DEFAULT_BATCH_SIZE)))
        except ValueError:
            self.batch_size = DEFAULT_BATCH_SIZE

        self.checkpoint_file = CHECKPOINT_FILE_PATH


def load_checkpoint(checkpoint_path: Path) -> str | None:
    """Reads the last processed event_id from the checkpoint file."""
    if not checkpoint_path.exists():
        return None
    try:
        content = checkpoint_path.read_text(encoding="utf-8").strip()
        return content if content else None
    except Exception as exc:
        logger.warning(f"[CONNECTOR] Failed to read checkpoint file: {exc}")
        return None


def save_checkpoint(checkpoint_path: Path, event_id: str) -> None:
    """Saves the last successfully ingested event_id to the checkpoint file."""
    if not event_id:
        return
    try:
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        checkpoint_path.write_text(event_id.strip(), encoding="utf-8")
        print(f"[CONNECTOR] checkpoint updated: {event_id}")
    except Exception as exc:
        logger.error(f"[CONNECTOR] Failed to write checkpoint file: {exc}")


def generate_message(method: str, path: str, status_code: int, response_time_ms: float) -> str:
    """Generates a standardized SIEM message string for a telemetry event."""
    return f"{method} {path} returned {status_code} ({response_time_ms}ms)"


def transform_event(raw_event: dict[str, Any]) -> dict[str, Any] | None:
    """
    Transforms a Juice Shop telemetry event dict into a Mini-SIEM NormalizedEvent schema payload.
    Returns None if the raw_event is invalid or malformed.
    """
    if not isinstance(raw_event, dict):
        logger.warning("[CONNECTOR] Skipping malformed non-dict event payload")
        return None

    timestamp = raw_event.get("timestamp")
    if not timestamp:
        logger.warning("[CONNECTOR] Skipping event missing timestamp")
        return None

    source_ip = raw_event.get("source_ip") or "0.0.0.0"
    method = str(raw_event.get("method") or "GET").upper()
    path = str(raw_event.get("path") or "/")
    
    try:
        status_code = int(raw_event.get("status_code", 200))
    except (ValueError, TypeError):
        status_code = 200

    try:
        response_time_ms = float(raw_event.get("response_time_ms", 0.0))
    except (ValueError, TypeError):
        response_time_ms = 0.0

    user_agent = raw_event.get("user_agent")
    user_identity = raw_event.get("user_identity") or "anonymous"
    raw_event_type = raw_event.get("event_type")

    # Determine SIEM event_type
    if raw_event_type == "HTTP_REQUEST" or not raw_event_type:
        event_type = "web_request"
    else:
        event_type = str(raw_event_type).lower().replace(" ", "_")

    message = generate_message(method, path, status_code, response_time_ms)

    # Mini-SIEM ingest payload format for an individual event
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "http_method": method,
        "request_path": path,
        "status_code": status_code,
        "user_agent": user_agent,
        "username": user_identity,
        "event_type": event_type,
        "event_category": "web",
        "severity": "low",
        "message": message,
    }


def fetch_telemetry(url: str, api_key: str, since: str | None = None, timeout: float = 15.0) -> list[dict[str, Any]]:
    """
    Fetches telemetry events from the OWASP Juice Shop telemetry API endpoint.
    Appends ?since=<since> query param if available.
    Handles HTTP errors, timeouts, and JSON parsing.
    """
    query_params = {}
    if since:
        query_params["since"] = since

    parsed_url = urllib.parse.urlparse(url)
    existing_query = urllib.parse.parse_qs(parsed_url.query)
    for k, v in existing_query.items():
        query_params[k] = v[-1]

    new_query = urllib.parse.urlencode(query_params)
    request_url = urllib.parse.urlunparse((
        parsed_url.scheme,
        parsed_url.netloc,
        parsed_url.path,
        parsed_url.params,
        new_query,
        parsed_url.fragment,
    ))

    req = urllib.request.Request(request_url, method="GET")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "JuiceShopConnector/1.0")
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status = response.getcode()
            if status != 200:
                logger.error(f"[CONNECTOR] Telemetry API responded with non-200 status code: {status}")
                return []
            body = response.read().decode("utf-8")
            if not body.strip():
                return []
            data = json.loads(body)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                # If wrapped in an object like {"events": [...]}
                if "events" in data and isinstance(data["events"], list):
                    return data["events"]
                return [data]
            else:
                logger.warning("[CONNECTOR] Unexpected JSON structure returned by telemetry API")
                return []

    except urllib.error.HTTPError as err:
        if err.code in (401, 403):
            logger.error(f"[CONNECTOR] Authentication/Authorization failure ({err.code}) when calling telemetry API")
        elif err.code == 429:
            logger.warning("[CONNECTOR] Telemetry API rate limit exceeded (429)")
        else:
            logger.error(f"[CONNECTOR] Telemetry API HTTP error: {err.code}")
        raise err
    except urllib.error.URLError as err:
        logger.error(f"[CONNECTOR] Telemetry API connection error or timeout: {err.reason}")
        raise err
    except json.JSONDecodeError as err:
        logger.error(f"[CONNECTOR] Malformed JSON received from telemetry API: {err}")
        return []


def ingest_batch_to_siem(ingest_url: str, jwt_token: str, events: list[dict[str, Any]], timeout: float = 15.0) -> dict[str, Any]:
    """
    Posts a batch of transformed events to the Mini-SIEM POST /api/logs/ingest endpoint.
    """
    payload = {
        "source_type": "juice_shop_connector",
        "events": events,
        "raw_lines": [],
    }

    body_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(ingest_url, data=body_bytes, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "JuiceShopConnector/1.0")
    if jwt_token:
        req.add_header("Authorization", f"Bearer {jwt_token}")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            res_body = response.read().decode("utf-8")
            return json.loads(res_body) if res_body else {}
    except urllib.error.HTTPError as err:
        logger.error(f"[CONNECTOR] SIEM Ingest HTTP error {err.code}")
        raise err
    except urllib.error.URLError as err:
        logger.error(f"[CONNECTOR] SIEM Ingest connection error or timeout: {err.reason}")
        raise err
    except json.JSONDecodeError as err:
        logger.error(f"[CONNECTOR] Malformed response from SIEM Ingest API: {err}")
        raise err


def poll_and_process(config: ConnectorConfig) -> int:
    """
    Executes one poll-transform-ingest iteration.
    Returns the total number of events successfully ingested into the SIEM.
    """
    print("[CONNECTOR] polling telemetry")
    checkpoint = load_checkpoint(config.checkpoint_file)

    raw_events = fetch_telemetry(
        url=config.telemetry_url,
        api_key=config.telemetry_api_key,
        since=checkpoint,
    )

    if not raw_events:
        print("[CONNECTOR] received 0 events")
        return 0

    print(f"[CONNECTOR] received {len(raw_events)} events")

    # Filter out duplicate checkpoint event if present
    valid_items: list[tuple[str, dict[str, Any]]] = []
    for item in raw_events:
        if not isinstance(item, dict):
            continue
        evt_id = str(item.get("event_id") or "")
        if checkpoint and evt_id and evt_id == checkpoint:
            continue
        transformed = transform_event(item)
        if transformed:
            valid_items.append((evt_id, transformed))

    if not valid_items:
        return 0

    total_ingested = 0
    # Process in batches of config.batch_size
    for i in range(0, len(valid_items), config.batch_size):
        batch = valid_items[i : i + config.batch_size]
        batch_events = [transformed for _, transformed in batch]
        
        print(f"[CONNECTOR] sending {len(batch_events)} events to SIEM")
        ingest_batch_to_siem(
            ingest_url=config.siem_ingest_url,
            jwt_token=config.siem_jwt_token,
            events=batch_events,
        )
        print("[CONNECTOR] ingestion successful")
        total_ingested += len(batch_events)

        # Update checkpoint to the last event_id in the successfully ingested batch
        last_evt_id = batch[-1][0]
        if last_evt_id:
            save_checkpoint(config.checkpoint_file, last_evt_id)

    return total_ingested


def run_continuous(config: ConnectorConfig) -> None:
    """Continuously polls telemetry with exponential backoff on transient errors."""
    backoff = 1.0
    max_backoff = 60.0

    while True:
        try:
            poll_and_process(config)
            backoff = 1.0  # Reset backoff on success
        except Exception as exc:
            logger.error(f"[CONNECTOR] Error during cycle: {exc}. Retrying in {backoff:.1f}s...")
            time.sleep(backoff)
            backoff = min(backoff * 2.0, max_backoff)
            continue

        time.sleep(config.poll_interval)


def main() -> None:
    parser = argparse.ArgumentParser(description="OWASP Juice Shop Telemetry Connector for Mini-SIEM")
    parser.add_argument("--once", action="store_true", help="Fetch telemetry once, ingest to SIEM, update checkpoint, and exit")
    args = parser.parse_args()

    config = ConnectorConfig()

    if args.once:
        try:
            poll_and_process(config)
        except Exception as exc:
            logger.error(f"[CONNECTOR] Single cycle failed: {exc}")
            sys.exit(1)
    else:
        run_continuous(config)


if __name__ == "__main__":
    main()
