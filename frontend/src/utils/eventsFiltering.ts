import type { NormalizedEvent } from "../types";

/**
 * Checks if a telemetry event represents background Socket.IO transport or polling.
 */
export function isSocketIoEvent(event: NormalizedEvent | null | undefined): boolean {
  if (!event) return false;
  const path = (event.request_path || "").toLowerCase();
  const raw = (event.raw_log || "").toLowerCase();
  const msg = (event.message || "").toLowerCase();

  return (
    path.includes("socket.io") ||
    raw.includes("socket.io") ||
    msg.includes("socket.io")
  );
}

/**
 * Filters a list of normalized events based on the UI-only polling noise toggle.
 * Returns the displayed events and the count of excluded background events.
 */
export function filterEvents(
  events: NormalizedEvent[],
  hidePollingNoise: boolean
): {
  displayed: NormalizedEvent[];
  excludedCount: number;
} {
  if (!events || events.length === 0) {
    return { displayed: [], excludedCount: 0 };
  }

  if (!hidePollingNoise) {
    return { displayed: events, excludedCount: 0 };
  }

  const displayed: NormalizedEvent[] = [];
  let excludedCount = 0;

  for (const event of events) {
    if (isSocketIoEvent(event)) {
      excludedCount++;
    } else {
      displayed.push(event);
    }
  }

  return { displayed, excludedCount };
}

export interface PaginationInfo {
  currentPage: number;
  totalPages: number;
  startIndex: number;
  endIndex: number;
  hasPrev: boolean;
  hasNext: boolean;
}

/**
 * Calculates standard 1-indexed pagination boundaries and state.
 */
export function calculatePagination(
  totalItems: number,
  currentPage: number,
  pageSize: number
): PaginationInfo {
  const safeTotal = Math.max(0, totalItems);
  const safePageSize = Math.max(1, pageSize);
  const totalPages = Math.max(1, Math.ceil(safeTotal / safePageSize));
  const safeCurrentPage = Math.min(Math.max(1, currentPage), totalPages);

  const startIndex = safeTotal === 0 ? 0 : (safeCurrentPage - 1) * safePageSize + 1;
  const endIndex = Math.min(safeCurrentPage * safePageSize, safeTotal);

  return {
    currentPage: safeCurrentPage,
    totalPages,
    startIndex,
    endIndex,
    hasPrev: safeCurrentPage > 1,
    hasNext: safeCurrentPage < totalPages,
  };
}

/**
 * Returns a valid page number clamped within [1, totalPages].
 */
export function clampPage(
  targetPage: number,
  totalItems: number,
  pageSize: number
): number {
  const safeTotal = Math.max(0, totalItems);
  const safePageSize = Math.max(1, pageSize);
  const totalPages = Math.max(1, Math.ceil(safeTotal / safePageSize));
  return Math.min(Math.max(1, targetPage), totalPages);
}
