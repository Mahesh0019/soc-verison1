import type {
  PipelineHealthState,
  PipelineHealthSummary,
  TelemetryConnectorStatus,
} from "../types";

/**
 * Staleness and recency thresholds (in milliseconds)
 */
export const POLL_STALENESS_THRESHOLD_MS = 60_000; // 60 seconds without upstream poll cycle
export const QUERY_STALENESS_THRESHOLD_MS = 90_000; // 90 seconds without dashboard check
export const RECENT_INGESTION_THRESHOLD_MS = 300_000; // 5 minutes since last event ingestion

/**
 * Formats a date or ISO string into a concise human-readable relative time string.
 */
export function formatRelativeTime(
  isoOrDate: string | Date | null | undefined,
  referenceDate: Date = new Date()
): string {
  if (!isoOrDate) {
    return "Never";
  }

  const date = typeof isoOrDate === "string" ? new Date(isoOrDate) : isoOrDate;
  if (isNaN(date.getTime())) {
    return "Invalid date";
  }

  const diffMs = referenceDate.getTime() - date.getTime();
  if (diffMs < 0) {
    return "just now";
  }

  const seconds = Math.floor(diffMs / 1000);
  if (seconds < 5) {
    return "just now";
  }
  if (seconds < 60) {
    return `${seconds}s ago`;
  }

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes}m ago`;
  }

  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours}h ago`;
  }

  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

/**
 * Evaluates the multi-factor operational health of the live telemetry pipeline.
 *
 * Distinguishes:
 * 1. UNAVAILABLE: Backend unreachable or fetch failure.
 * 2. STOPPED: Connector background task disabled or stopped.
 * 3. STALE: Connector polling has stalled or dashboard status is out of date.
 * 4. DEGRADED: Consecutive failures > 0 or upstream status reports an error.
 * 5. HEALTHY_INGESTING: Polling cleanly with fresh event ingestion within 5 minutes.
 * 6. HEALTHY_IDLE: Polling cleanly on standby (normal when upstream victim has no traffic).
 */
export function calculatePipelineHealth(
  status: TelemetryConnectorStatus | null,
  lastCheckedAt: Date | null,
  referenceDate: Date = new Date(),
  fetchError?: string | null
): PipelineHealthSummary {
  // Scenario 1: Request failure or uninitialized/unreachable status
  if (!status || fetchError) {
    return {
      state: "UNAVAILABLE",
      label: "Pipeline Unavailable",
      details: fetchError ? `Backend error: ${fetchError}` : "Telemetry status unavailable",
      status: null,
      lastCheckedAt,
      isStale: false,
      error: fetchError ?? "Status unavailable",
    };
  }

  // Scenario 2: Connector explicitly disabled or stopped
  if (!status.enabled || !status.running) {
    return {
      state: "STOPPED",
      label: "Connector Stopped",
      details: !status.enabled
        ? "Connector disabled in backend configuration"
        : "Connector background worker is stopped",
      status,
      lastCheckedAt,
      isStale: false,
      error: status.last_error,
    };
  }

  const currentTime = referenceDate.getTime();

  // Evaluate query staleness (how long since the client successfully refreshed)
  const isQueryStale = lastCheckedAt
    ? currentTime - lastCheckedAt.getTime() > QUERY_STALENESS_THRESHOLD_MS
    : true;

  // Evaluate poll staleness (how long since the backend actually ran a poll cycle)
  const pollTime = status.last_poll_attempt ? new Date(status.last_poll_attempt).getTime() : NaN;
  const isPollStale = isNaN(pollTime)
    ? true
    : currentTime - pollTime > POLL_STALENESS_THRESHOLD_MS;

  // Scenario 3: Stale activity (connector loop hung or browser disconnected)
  if (isPollStale || isQueryStale) {
    return {
      state: "STALE",
      label: "Pipeline Stalled",
      details: isPollStale
        ? "Upstream polling stalled (>60s since last poll attempt)"
        : "Dashboard status check stale (>90s without refresh)",
      status,
      lastCheckedAt,
      isStale: true,
      error: status.last_error,
    };
  }

  // Scenario 4: Degraded (consecutive failures or upstream 502/401/error status)
  const hasFailures = status.consecutive_failures > 0;
  const isUpstreamError =
    Boolean(status.last_status) &&
    status.last_status !== "HEALTHY" &&
    status.last_status !== "IDLE";

  if (hasFailures || isUpstreamError) {
    const isSleeping502 = status.last_status === "UPSTREAM_UNAVAILABLE_502";
    const errorPrefix = status.last_status.startsWith("UPSTREAM_")
      ? `Upstream: ${status.last_status}`
      : status.last_status;
    const details = isSleeping502
      ? `${errorPrefix} (${status.consecutive_failures} fails): Upstream victim waking up (Render free tier spin-down)`
      : status.last_error
      ? `${errorPrefix} (${status.consecutive_failures} fails): ${status.last_error}`
      : `${errorPrefix} (${status.consecutive_failures} consecutive failures)`;
    return {
      state: "DEGRADED",
      label: "Pipeline Degraded",
      details,
      status,
      lastCheckedAt,
      isStale: false,
      error: status.last_error,
    };
  }

  // Scenario 5: Check ingestion recency (active vs standby)
  const ingestionTime = status.last_successful_ingestion
    ? new Date(status.last_successful_ingestion).getTime()
    : NaN;
  const isRecentIngestion =
    !isNaN(ingestionTime) &&
    currentTime - ingestionTime <= RECENT_INGESTION_THRESHOLD_MS;

  if (isRecentIngestion) {
    return {
      state: "HEALTHY_INGESTING",
      label: "Pipeline Ingesting",
      details: `Actively ingesting live telemetry (${status.total_events_ingested} total events)`,
      status,
      lastCheckedAt,
      isStale: false,
      error: null,
    };
  }

  // Scenario 6: Healthy standby (normal idle condition between probe / attack bursts)
  return {
    state: "HEALTHY_IDLE",
    label: "Pipeline Standby",
    details: `Polling healthy every ${status.poll_interval_seconds}s; waiting for upstream events`,
    status,
    lastCheckedAt,
    isStale: false,
    error: null,
  };
}
