"""
backend/app/services/juice_shop_background.py

Runs the Juice Shop telemetry connector as a non-blocking asyncio background
task inside the existing FastAPI process.

Architecture
------------
FastAPI lifespan
    └─ asyncio background task (_poll_loop)
            └─ asyncio.to_thread(poll_and_process)  ← blocking I/O on thread pool
                    └─ connector.juice_shop_connector.fetch_telemetry()
                    └─ ingest_api_payload()           ← direct DB call, no HTTP
                    └─ connector.juice_shop_connector.save_checkpoint()

Key design decisions
---------------------
* We reuse fetch_telemetry(), transform_event(), load_checkpoint(),
  save_checkpoint(), and generate_message() from the existing connector
  package verbatim — no duplication.

* Instead of the connector calling POST /api/logs/ingest over HTTP
  (which would require a JWT and a live network hop to itself),
  we call ingest_api_payload() directly.  This is safe because:
    - ingest_api_payload() is a plain synchronous function.
    - It already performs normalization, DB persistence, and rule evaluation.
    - We pass user_id=None (background system ingestion).
    - No authentication bypass — the background task is internal; it never
      touches the public HTTP surface.

* The poll loop runs in asyncio.to_thread() so that urllib / checkpoint file
  I/O never blocks the uvicorn event loop.

* Exactly one task is created per process (guarded by a module-level flag).

* The task is cancelled on application shutdown; the cancellation is caught
  and logged cleanly.

* When ENABLE_JUICE_SHOP_CONNECTOR=false (the default) this module is never
  activated and the application behaves identically to its pre-connector state.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger("JuiceShopBackground")

# Module-level sentinel so we never spawn a second task in the same process.
_task: asyncio.Task[None] | None = None


# ---------------------------------------------------------------------------
# Internal one-shot poll helper (runs inside a thread to avoid blocking)
# ---------------------------------------------------------------------------

def _poll_once(
    telemetry_url: str,
    telemetry_api_key: str,
    poll_interval: float,  # kept for symmetry; not used inside this fn
    batch_size: int,
    checkpoint_path: Any,
) -> int:
    """
    One synchronous poll-transform-ingest cycle.

    Reuses connector primitives verbatim; calls ingest_api_payload() directly
    to avoid an HTTP round-trip.  Returns the number of events ingested.

    This function is intentionally free of asyncio so it can run safely in
    asyncio.to_thread().
    """
    # Lazy imports keep the module importable even if connector is unavailable;
    # errors surface only when the task is actually enabled.
    from connector.juice_shop_connector import (  # type: ignore[import]
        fetch_telemetry,
        load_checkpoint,
        save_checkpoint,
        transform_event,
    )
    from app.database.session import SessionLocal
    from app.services.ingestion import ingest_api_payload

    print("[CONNECTOR] polling telemetry")
    checkpoint = load_checkpoint(checkpoint_path)

    try:
        raw_events = fetch_telemetry(
            url=telemetry_url,
            api_key=telemetry_api_key,
            since=checkpoint,
        )
    except Exception as exc:
        logger.error(f"[CONNECTOR] Telemetry fetch failed: {exc}")
        raise

    if not raw_events:
        print("[CONNECTOR] received 0 events")
        return 0

    print(f"[CONNECTOR] received {len(raw_events)} events")

    # Transform and deduplicate
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

    for i in range(0, len(valid_items), batch_size):
        batch = valid_items[i : i + batch_size]
        batch_events = [t for _, t in batch]

        print(f"[CONNECTOR] sending {len(batch_events)} events to SIEM")

        db = SessionLocal()
        try:
            ingest_api_payload(
                db,
                source_type="juice_shop_connector",
                events=batch_events,
                raw_lines=[],
                user_id=None,
            )
            print("[CONNECTOR] ingestion successful")
            total_ingested += len(batch_events)
        except Exception as exc:
            logger.error(f"[CONNECTOR] Ingestion failed for batch: {exc}")
            raise
        finally:
            db.close()

        # Advance checkpoint only after successful ingestion
        last_evt_id = batch[-1][0]
        if last_evt_id:
            save_checkpoint(checkpoint_path, last_evt_id)

    return total_ingested


# ---------------------------------------------------------------------------
# Async polling loop
# ---------------------------------------------------------------------------

async def _poll_loop(
    telemetry_url: str,
    telemetry_api_key: str,
    poll_interval: float,
    batch_size: int,
    checkpoint_path: Any,
) -> None:
    """
    Async loop that calls _poll_once() in a thread on every interval.
    Uses exponential backoff on transient errors and resets on success.
    Handles asyncio.CancelledError cleanly for graceful shutdown.
    """
    backoff = 1.0
    max_backoff = 60.0

    print("[CONNECTOR] background telemetry collector starting")
    try:
        while True:
            try:
                await asyncio.to_thread(
                    _poll_once,
                    telemetry_url,
                    telemetry_api_key,
                    poll_interval,
                    batch_size,
                    checkpoint_path,
                )
                backoff = 1.0  # reset on success
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(
                    f"[CONNECTOR] cycle error: {exc}. "
                    f"Retrying in {backoff:.1f}s..."
                )
                try:
                    await asyncio.sleep(backoff)
                except asyncio.CancelledError:
                    raise
                backoff = min(backoff * 2.0, max_backoff)
                continue

            try:
                await asyncio.sleep(poll_interval)
            except asyncio.CancelledError:
                raise

    except asyncio.CancelledError:
        pass  # normal shutdown
    finally:
        print("[CONNECTOR] background telemetry collector stopped")


# ---------------------------------------------------------------------------
# Public API called from main.py lifespan
# ---------------------------------------------------------------------------

def start_background_collector() -> None:
    """
    Schedules the connector poll loop as an asyncio Task.
    Must be called from an async context (lifespan / startup handler).
    Safe to call multiple times — only one task will be created.
    """
    global _task

    if _task is not None and not _task.done():
        logger.warning("[CONNECTOR] Background collector already running; skipping duplicate start.")
        return

    from app.config import get_settings
    from connector.juice_shop_connector import CHECKPOINT_FILE_PATH  # type: ignore[import]

    settings = get_settings()

    _task = asyncio.create_task(
        _poll_loop(
            telemetry_url=settings.juice_shop_telemetry_url,
            telemetry_api_key=settings.juice_shop_telemetry_api_key,
            poll_interval=settings.poll_interval_seconds,
            batch_size=settings.batch_size,
            checkpoint_path=CHECKPOINT_FILE_PATH,
        ),
        name="juice_shop_connector",
    )
    logger.info("[CONNECTOR] Background task scheduled.")


def stop_background_collector() -> None:
    """
    Cancels the running background task.  Called from the lifespan shutdown.
    """
    global _task
    if _task is not None and not _task.done():
        _task.cancel()
        logger.info("[CONNECTOR] Background task cancellation requested.")
    _task = None
