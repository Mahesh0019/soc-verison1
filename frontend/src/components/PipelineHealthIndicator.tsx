import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  PauseCircle,
  Radio,
  RefreshCw,
  ServerOff,
  XCircle,
} from "lucide-react";
import React, { useEffect, useRef, useState } from "react";

import { fetchTelemetryConnectorStatus } from "../services/api";
import type {
  PipelineHealthState,
  TelemetryConnectorStatus,
} from "../types";
import {
  calculatePipelineHealth,
  formatRelativeTime,
} from "../utils/pipelineHealth";
import { useAuth } from "./AuthProvider";

interface PipelineHealthIndicatorProps {
  /** Polling interval in milliseconds (default: 30,000ms / 30s) */
  pollIntervalMs?: number;
  /** Optional container class name */
  className?: string;
}

export function PipelineHealthIndicator({
  pollIntervalMs = 30_000,
  className = "",
}: PipelineHealthIndicatorProps) {
  const { user } = useAuth();
  const [status, setStatus] = useState<TelemetryConnectorStatus | null>(null);
  const [lastCheckedAt, setLastCheckedAt] = useState<Date | null>(null);
  const [isFetching, setIsFetching] = useState<boolean>(false);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [isOpen, setIsOpen] = useState<boolean>(false);

  const popoverRef = useRef<HTMLDivElement>(null);
  const isFetchingRef = useRef<boolean>(false);

  // Safe fetch helper with lock and unmount check
  const fetchStatus = async () => {
    // Only fetch if authenticated and not already fetching
    if (!user || isFetchingRef.current) {
      return;
    }

    isFetchingRef.current = true;
    setIsFetching(true);

    try {
      const data = await fetchTelemetryConnectorStatus();
      setStatus(data);
      setLastCheckedAt(new Date());
      setFetchError(null);
    } catch (err: unknown) {
      const errorMsg =
        err instanceof Error
          ? err.message
          : typeof err === "string"
          ? err
          : "Network request failed";
      setFetchError(errorMsg);
      // Keep existing status if available, but update check timestamp
      setLastCheckedAt(new Date());
    } finally {
      isFetchingRef.current = false;
      setIsFetching(false);
    }
  };

  // Setup polling interval with visibility awareness and cleanup
  useEffect(() => {
    if (!user) {
      return;
    }

    // Initial fetch on mount
    fetchStatus();

    // Conservative polling timer
    const intervalId = window.setInterval(() => {
      // Pause polling if document is hidden to conserve resources
      if (typeof document !== "undefined" && document.visibilityState === "hidden") {
        return;
      }
      fetchStatus();
    }, pollIntervalMs);

    // Refresh when tab becomes visible again
    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        fetchStatus();
      }
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);

    return () => {
      window.clearInterval(intervalId);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [user, pollIntervalMs]);

  // Click outside listener to close popover
  useEffect(() => {
    if (!isOpen) return;

    const handleClickOutside = (event: MouseEvent) => {
      if (
        popoverRef.current &&
        !popoverRef.current.contains(event.target as Node)
      ) {
        setIsOpen(false);
      }
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setIsOpen(false);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [isOpen]);

  const health = calculatePipelineHealth(
    status,
    lastCheckedAt,
    new Date(),
    fetchError
  );

  const getBadgeVisuals = (state: PipelineHealthState) => {
    switch (state) {
      case "HEALTHY_INGESTING":
        return {
          dotBg: "bg-emerald-400 ring-4 ring-emerald-400/20 animate-pulse",
          text: "text-emerald-300",
          border: "border-emerald-500/30",
          bg: "bg-emerald-950/20",
          icon: Radio,
        };
      case "HEALTHY_IDLE":
        return {
          dotBg: "bg-emerald-400",
          text: "text-emerald-300",
          border: "border-emerald-500/20",
          bg: "bg-surface-raised",
          icon: CheckCircle2,
        };
      case "DEGRADED":
        return {
          dotBg: "bg-amber-400 animate-pulse",
          text: "text-amber-300",
          border: "border-amber-500/30",
          bg: "bg-amber-950/20",
          icon: AlertTriangle,
        };
      case "STOPPED":
        return {
          dotBg: "bg-zinc-500",
          text: "text-zinc-400",
          border: "border-zinc-700",
          bg: "bg-surface-raised",
          icon: PauseCircle,
        };
      case "STALE":
        return {
          dotBg: "bg-orange-400",
          text: "text-orange-300",
          border: "border-orange-500/30",
          bg: "bg-orange-950/20",
          icon: Clock,
        };
      case "UNAVAILABLE":
      default:
        return {
          dotBg: "bg-rose-500",
          text: "text-rose-300",
          border: "border-rose-500/30",
          bg: "bg-rose-950/20",
          icon: ServerOff,
        };
    }
  };

  const visuals = getBadgeVisuals(health.state);
  const StatusIcon = visuals.icon;

  return (
    <div ref={popoverRef} className={`relative inline-block text-left ${className}`}>
      {/* Trigger Button */}
      <button
        type="button"
        onClick={() => setIsOpen((prev) => !prev)}
        aria-expanded={isOpen}
        aria-haspopup="dialog"
        title={`Telemetry Pipeline: ${health.label} — ${health.details}`}
        className={`focus-ring group flex items-center gap-2.5 rounded-lg border ${visuals.border} ${visuals.bg} px-3 py-1.5 text-xs font-medium transition hover:border-zinc-500`}
      >
        <span className="relative flex h-2 w-2">
          <span className={`inline-flex h-2 w-2 rounded-full ${visuals.dotBg}`} />
        </span>
        <span className={`${visuals.text} font-medium`}>{health.label}</span>
        <span className="text-[10px] text-zinc-500 group-hover:text-zinc-400">
          ▾
        </span>
      </button>

      {/* Popover Dropdown Card */}
      {isOpen && (
        <div
          role="dialog"
          aria-label="Telemetry Pipeline Health Details"
          className="absolute right-0 top-full mt-2 w-80 rounded-xl border border-surface-border bg-surface-base/98 p-4 shadow-2xl backdrop-blur-md z-50 animate-in fade-in zoom-in-95 duration-100"
        >
          {/* Header */}
          <div className="flex items-start justify-between border-b border-surface-border pb-3">
            <div className="flex items-center gap-2">
              <StatusIcon className={`h-4 w-4 ${visuals.text}`} />
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-100">
                  Telemetry Pipeline
                </h4>
                <p className="text-[11px] text-zinc-400">{health.details}</p>
              </div>
            </div>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                fetchStatus();
              }}
              disabled={isFetching}
              title="Manual status refresh"
              className="focus-ring -mr-1 -mt-1 rounded-md p-1.5 text-zinc-400 hover:bg-surface-raised hover:text-zinc-100 disabled:opacity-50"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 ${isFetching ? "animate-spin text-cyan-400" : ""}`}
              />
            </button>
          </div>

          {/* Details Table */}
          <div className="mt-3 space-y-2 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-zinc-500">Connector Worker</span>
              <span className="font-mono text-zinc-200">
                {status?.running ? (
                  <span className="text-emerald-400">Active</span>
                ) : (
                  <span className="text-zinc-500">Stopped</span>
                )}
                {status?.enabled ? " (Enabled)" : " (Disabled)"}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-zinc-500">Last Upstream Poll</span>
              <span
                className="font-mono text-zinc-200"
                title={status?.last_poll_attempt ?? "No poll timestamp"}
              >
                {formatRelativeTime(status?.last_poll_attempt)}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-zinc-500">Last Event Ingestion</span>
              <span
                className="font-mono text-zinc-200"
                title={status?.last_successful_ingestion ?? "No ingestion timestamp"}
              >
                {formatRelativeTime(status?.last_successful_ingestion)}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-zinc-500">Total Ingested</span>
              <span className="font-mono text-zinc-200">
                {status?.total_events_ingested?.toLocaleString() ?? 0} events
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-zinc-500">Consecutive Failures</span>
              <span
                className={`font-mono font-semibold ${
                  (status?.consecutive_failures ?? 0) > 0
                    ? "text-rose-400"
                    : "text-zinc-200"
                }`}
              >
                {status?.consecutive_failures ?? 0}
              </span>
            </div>

            {status?.last_error && (
              <div className="rounded-lg border border-rose-500/30 bg-rose-950/20 p-2 text-[11px] text-rose-300 break-words">
                <span className="font-semibold">Last Error: </span>
                {status.last_error}
              </div>
            )}

            <div className="border-t border-surface-border pt-2 flex items-center justify-between text-[11px] text-zinc-500">
              <span>Dashboard Checked</span>
              <span className="font-mono">
                {formatRelativeTime(lastCheckedAt)}
              </span>
            </div>
          </div>

          {/* Upstream target footer */}
          {status?.upstream_url && (
            <div className="mt-2 rounded bg-surface-raised/80 px-2 py-1 text-[10px] text-zinc-500 truncate font-mono">
              Target: {status.upstream_url}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
