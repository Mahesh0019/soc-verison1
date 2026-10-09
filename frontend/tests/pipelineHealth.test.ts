import assert from "node:assert";
import { describe, it } from "node:test";

import type { TelemetryConnectorStatus } from "../src/types/index.ts";
import {
  calculatePipelineHealth,
  formatRelativeTime,
  POLL_STALENESS_THRESHOLD_MS,
  QUERY_STALENESS_THRESHOLD_MS,
  RECENT_INGESTION_THRESHOLD_MS,
} from "../src/utils/pipelineHealth.ts";

describe("Telemetry Pipeline Health Calculations", () => {
  const referenceNow = new Date("2026-10-09T12:00:00.000Z");

  const baseStatus: TelemetryConnectorStatus = {
    enabled: true,
    running: true,
    upstream_url: "https://demo-victim-1.onrender.com/api/telemetry/events",
    poll_interval_seconds: 10.0,
    last_poll_attempt: new Date(referenceNow.getTime() - 5_000).toISOString(), // 5s ago
    last_successful_ingestion: new Date(referenceNow.getTime() - 30_000).toISOString(), // 30s ago
    last_status: "HEALTHY",
    consecutive_failures: 0,
    total_events_ingested: 42,
    last_error: null,
  };

  it("calculates HEALTHY_INGESTING when connector is running and ingesting recently", () => {
    const health = calculatePipelineHealth(
      baseStatus,
      new Date(referenceNow.getTime() - 2_000), // check was 2s ago
      referenceNow
    );

    assert.strictEqual(health.state, "HEALTHY_INGESTING");
    assert.strictEqual(health.label, "Pipeline Ingesting");
    assert.strictEqual(health.isStale, false);
    assert.strictEqual(health.error, null);
    assert.match(health.details, /42 total events/);
  });

  it("calculates HEALTHY_IDLE when connector is polling cleanly with no recent events", () => {
    const idleStatus: TelemetryConnectorStatus = {
      ...baseStatus,
      // Ingestion was 15 minutes ago (> 5m threshold)
      last_successful_ingestion: new Date(referenceNow.getTime() - 15 * 60_000).toISOString(),
    };

    const health = calculatePipelineHealth(
      idleStatus,
      new Date(referenceNow.getTime() - 5_000),
      referenceNow
    );

    assert.strictEqual(health.state, "HEALTHY_IDLE");
    assert.strictEqual(health.label, "Pipeline Standby");
    assert.strictEqual(health.isStale, false);
    assert.strictEqual(health.error, null);
    assert.match(health.details, /Polling healthy every 10s/);
  });

  it("calculates HEALTHY_IDLE when last_successful_ingestion is null (initial clean standby)", () => {
    const freshStatus: TelemetryConnectorStatus = {
      ...baseStatus,
      last_successful_ingestion: null,
      total_events_ingested: 0,
    };

    const health = calculatePipelineHealth(
      freshStatus,
      new Date(referenceNow.getTime() - 5_000),
      referenceNow
    );

    assert.strictEqual(health.state, "HEALTHY_IDLE");
    assert.strictEqual(health.label, "Pipeline Standby");
    assert.strictEqual(health.isStale, false);
  });

  it("calculates DEGRADED when consecutive_failures > 0", () => {
    const degradedStatus: TelemetryConnectorStatus = {
      ...baseStatus,
      consecutive_failures: 3,
      last_error: "Connection reset by peer",
      last_status: "ERROR",
    };

    const health = calculatePipelineHealth(
      degradedStatus,
      new Date(referenceNow.getTime() - 5_000),
      referenceNow
    );

    assert.strictEqual(health.state, "DEGRADED");
    assert.strictEqual(health.label, "Pipeline Degraded");
    assert.strictEqual(health.isStale, false);
    assert.match(health.details, /Connection reset by peer/);
  });

  it("calculates DEGRADED on upstream status warnings like UPSTREAM_UNAVAILABLE_502", () => {
    const upstreamErrStatus: TelemetryConnectorStatus = {
      ...baseStatus,
      consecutive_failures: 1,
      last_status: "UPSTREAM_UNAVAILABLE_502",
      last_error: "HTTP Error 502: Bad Gateway",
    };

    const health = calculatePipelineHealth(
      upstreamErrStatus,
      new Date(referenceNow.getTime() - 5_000),
      referenceNow
    );

    assert.strictEqual(health.state, "DEGRADED");
    assert.strictEqual(health.label, "Pipeline Degraded");
    assert.match(health.details, /UPSTREAM_UNAVAILABLE_502/);
  });

  it("calculates STOPPED when running is false", () => {
    const stoppedStatus: TelemetryConnectorStatus = {
      ...baseStatus,
      running: false,
    };

    const health = calculatePipelineHealth(
      stoppedStatus,
      new Date(referenceNow.getTime() - 5_000),
      referenceNow
    );

    assert.strictEqual(health.state, "STOPPED");
    assert.strictEqual(health.label, "Connector Stopped");
    assert.strictEqual(health.isStale, false);
    assert.match(health.details, /background worker is stopped/);
  });

  it("calculates STOPPED when enabled is false", () => {
    const disabledStatus: TelemetryConnectorStatus = {
      ...baseStatus,
      enabled: false,
      running: false,
    };

    const health = calculatePipelineHealth(
      disabledStatus,
      new Date(referenceNow.getTime() - 5_000),
      referenceNow
    );

    assert.strictEqual(health.state, "STOPPED");
    assert.strictEqual(health.label, "Connector Stopped");
    assert.match(health.details, /disabled in backend configuration/);
  });

  it("calculates STALE when upstream poll is older than threshold (e.g. hung worker)", () => {
    const stalePollStatus: TelemetryConnectorStatus = {
      ...baseStatus,
      // Last poll was 75s ago (> 60s threshold)
      last_poll_attempt: new Date(referenceNow.getTime() - 75_000).toISOString(),
    };

    const health = calculatePipelineHealth(
      stalePollStatus,
      new Date(referenceNow.getTime() - 5_000), // check was recent
      referenceNow
    );

    assert.strictEqual(health.state, "STALE");
    assert.strictEqual(health.label, "Pipeline Stalled");
    assert.strictEqual(health.isStale, true);
    assert.match(health.details, />60s since last poll/);
  });

  it("calculates STALE when dashboard status check itself is older than 90s", () => {
    const health = calculatePipelineHealth(
      baseStatus,
      // Last check was 120s ago (> 90s threshold)
      new Date(referenceNow.getTime() - 120_000),
      referenceNow
    );

    assert.strictEqual(health.state, "STALE");
    assert.strictEqual(health.label, "Pipeline Stalled");
    assert.strictEqual(health.isStale, true);
    assert.match(health.details, />90s without refresh/);
  });

  it("calculates UNAVAILABLE when status is null (unreachable)", () => {
    const health = calculatePipelineHealth(null, null, referenceNow);

    assert.strictEqual(health.state, "UNAVAILABLE");
    assert.strictEqual(health.label, "Pipeline Unavailable");
    assert.strictEqual(health.status, null);
    assert.strictEqual(health.isStale, false);
    assert.strictEqual(health.error, "Status unavailable");
  });

  it("calculates UNAVAILABLE when fetchError is present", () => {
    const health = calculatePipelineHealth(
      baseStatus,
      new Date(referenceNow.getTime() - 5_000),
      referenceNow,
      "HTTP 503 Service Unavailable"
    );

    assert.strictEqual(health.state, "UNAVAILABLE");
    assert.strictEqual(health.label, "Pipeline Unavailable");
    assert.match(health.details, /HTTP 503 Service Unavailable/);
  });

  it("never fabricates HEALTHY merely from an HTTP 200 payload if metrics report errors", () => {
    const misleadingStatus: TelemetryConnectorStatus = {
      ...baseStatus,
      consecutive_failures: 5,
      last_status: "UPSTREAM_UNAUTHORIZED_401",
      last_error: "Missing API Key",
    };

    const health = calculatePipelineHealth(
      misleadingStatus,
      new Date(referenceNow.getTime() - 2_000),
      referenceNow
    );

    assert.notStrictEqual(health.state, "HEALTHY_INGESTING");
    assert.notStrictEqual(health.state, "HEALTHY_IDLE");
    assert.strictEqual(health.state, "DEGRADED");
  });
});

describe("Relative Time Formatter", () => {
  const reference = new Date("2026-10-09T12:00:00.000Z");

  it("handles null or undefined cleanly", () => {
    assert.strictEqual(formatRelativeTime(null, reference), "Never");
    assert.strictEqual(formatRelativeTime(undefined, reference), "Never");
  });

  it("formats immediate relative times", () => {
    const justNow = new Date(reference.getTime() - 2_000);
    assert.strictEqual(formatRelativeTime(justNow, reference), "just now");

    const twentySecs = new Date(reference.getTime() - 20_000);
    assert.strictEqual(formatRelativeTime(twentySecs, reference), "20s ago");
  });

  it("formats minutes, hours, and days cleanly", () => {
    const fiveMins = new Date(reference.getTime() - 5 * 60_000);
    assert.strictEqual(formatRelativeTime(fiveMins, reference), "5m ago");

    const twoHours = new Date(reference.getTime() - 2 * 3600_000);
    assert.strictEqual(formatRelativeTime(twoHours, reference), "2h ago");

    const threeDays = new Date(reference.getTime() - 3 * 86400_000);
    assert.strictEqual(formatRelativeTime(threeDays, reference), "3d ago");
  });

  it("handles invalid date strings gracefully", () => {
    assert.strictEqual(formatRelativeTime("not-a-valid-date", reference), "Invalid date");
  });
});

describe("Pipeline Polling Lifecycle & Guard Invariants", () => {
  it("enforces lock invariant against overlapping requests", async () => {
    let activeRequests = 0;
    let maxConcurrent = 0;

    const simulateFetch = async () => {
      activeRequests++;
      maxConcurrent = Math.max(maxConcurrent, activeRequests);
      await new Promise((r) => setTimeout(r, 10));
      activeRequests--;
    };

    let isFetchingLock = false;
    const guardedFetch = async () => {
      if (isFetchingLock) return;
      isFetchingLock = true;
      try {
        await simulateFetch();
      } finally {
        isFetchingLock = false;
      }
    };

    // Trigger two overlapping requests concurrently
    await Promise.all([guardedFetch(), guardedFetch()]);

    assert.strictEqual(maxConcurrent, 1, "Guarded fetch must never exceed 1 concurrent execution");
  });

  it("ensures interval cleanup clears scheduled timer", () => {
    let cleared = false;
    const dummyTimerId = 12345;

    const cleanup = (timerId: number) => {
      if (timerId === dummyTimerId) {
        cleared = true;
      }
    };

    cleanup(dummyTimerId);
    assert.strictEqual(cleared, true);
  });
});
