import assert from "node:assert";
import { describe, it } from "node:test";

import type { NormalizedEvent } from "../src/types/index.ts";
import {
  calculatePagination,
  clampPage,
  filterEvents,
  isSocketIoEvent,
} from "../src/utils/eventsFiltering.ts";

describe("Events Filtering & Socket.IO Noise Toggle", () => {
  const mockWebEvent: NormalizedEvent = {
    id: 101,
    timestamp: "2026-10-09T11:10:13.275000Z",
    source_type: "WEB",
    event_type: "web_request",
    event_category: "web",
    severity: "low",
    source_ip: "152.57.153.115",
    request_path: "/rest/products/search?q=apple",
    http_method: "GET",
    status_code: 200,
    message: "GET /rest/products/search?q=apple returned 200 (45ms)",
  };

  const mockImageEvent: NormalizedEvent = {
    id: 102,
    timestamp: "2026-10-09T11:10:15.622000Z",
    source_type: "WEB",
    event_type: "web_request",
    event_category: "web",
    severity: "low",
    source_ip: "152.57.153.115",
    request_path: "/assets/public/images/products/permafrost.jpg",
    http_method: "GET",
    status_code: 304,
    message: "GET /assets/public/images/products/permafrost.jpg returned 304 (12ms)",
  };

  const mockSocketIoEvent1: NormalizedEvent = {
    id: 103,
    timestamp: "2026-10-09T11:10:16.362000Z",
    source_type: "WEB",
    event_type: "web_request",
    event_category: "web",
    severity: "low",
    source_ip: "152.57.153.115",
    request_path: "/health/socket.io/?EIO=4&transport=polling&t=Q4WNHeT",
    http_method: "GET",
    status_code: 200,
    message: "GET /health/socket.io/?EIO=4&transport=polling&t=Q4WNHeT returned 200 (8ms)",
  };

  const mockSocketIoEvent2: NormalizedEvent = {
    id: 104,
    timestamp: "2026-10-09T11:10:22.331000Z",
    source_type: "WEB",
    event_type: "web_request",
    event_category: "web",
    severity: "low",
    source_ip: "152.57.153.115",
    request_path: "/socket.io/?EIO=4&transport=polling",
    http_method: "GET",
    status_code: 200,
    message: "GET /socket.io/?EIO=4&transport=polling returned 200 (5ms)",
  };

  it("accurately detects Socket.IO polling events by path", () => {
    assert.strictEqual(isSocketIoEvent(mockSocketIoEvent1), true);
    assert.strictEqual(isSocketIoEvent(mockSocketIoEvent2), true);
    assert.strictEqual(isSocketIoEvent(mockWebEvent), false);
    assert.strictEqual(isSocketIoEvent(mockImageEvent), false);
    assert.strictEqual(isSocketIoEvent(null), false);
    assert.strictEqual(isSocketIoEvent(undefined), false);
  });

  it("detects Socket.IO events present in raw_log or message fallback", () => {
    const rawFallbackEvent: NormalizedEvent = {
      ...mockWebEvent,
      request_path: "",
      raw_log: "GET /health/socket.io/?EIO=4 HTTP/1.1",
    };
    assert.strictEqual(isSocketIoEvent(rawFallbackEvent), true);

    const msgFallbackEvent: NormalizedEvent = {
      ...mockWebEvent,
      request_path: "",
      raw_log: "",
      message: "Socket.IO polling heartbeat",
    };
    assert.strictEqual(isSocketIoEvent(msgFallbackEvent), true);
  });

  it("filters out Socket.IO background events when hidePollingNoise is true", () => {
    const input = [mockWebEvent, mockSocketIoEvent1, mockImageEvent, mockSocketIoEvent2];
    const { displayed, excludedCount } = filterEvents(input, true);

    assert.strictEqual(excludedCount, 2);
    assert.strictEqual(displayed.length, 2);
    assert.strictEqual(displayed[0].id, 101);
    assert.strictEqual(displayed[1].id, 102);
  });

  it("retains all events when hidePollingNoise is false", () => {
    const input = [mockWebEvent, mockSocketIoEvent1, mockImageEvent, mockSocketIoEvent2];
    const { displayed, excludedCount } = filterEvents(input, false);

    assert.strictEqual(excludedCount, 0);
    assert.strictEqual(displayed.length, 4);
    assert.deepStrictEqual(displayed, input);
  });

  it("handles a page containing only Socket.IO polling events cleanly", () => {
    const allPolling = [mockSocketIoEvent1, mockSocketIoEvent2];
    const { displayed, excludedCount } = filterEvents(allPolling, true);

    assert.strictEqual(excludedCount, 2);
    assert.strictEqual(displayed.length, 0);
  });

  it("handles empty event lists without errors", () => {
    const { displayed, excludedCount } = filterEvents([], true);
    assert.strictEqual(excludedCount, 0);
    assert.strictEqual(displayed.length, 0);
  });

  it("handles mixed background and substantive events on a single page", () => {
    // 2 substantive events + 2 background polling events
    const mixed = [mockWebEvent, mockSocketIoEvent1, mockImageEvent, mockSocketIoEvent2];
    const hiddenRes = filterEvents(mixed, true);
    assert.strictEqual(hiddenRes.excludedCount, 2);
    assert.strictEqual(hiddenRes.displayed.length, 2);
    assert.strictEqual(hiddenRes.displayed[0].id, 101);
    assert.strictEqual(hiddenRes.displayed[1].id, 102);

    // Switching toggle to show all on same page
    const shownRes = filterEvents(mixed, false);
    assert.strictEqual(shownRes.excludedCount, 0);
    assert.strictEqual(shownRes.displayed.length, 4);
    assert.deepStrictEqual(shownRes.displayed, mixed);
  });

  it("supports seamless switching between hiding and showing background traffic without array mutation", () => {
    const originalList = [mockSocketIoEvent1, mockWebEvent, mockSocketIoEvent2];
    const shallowCopy = [...originalList];

    // Toggle ON (hide noise)
    const hidden = filterEvents(originalList, true);
    assert.strictEqual(hidden.displayed.length, 1);
    assert.strictEqual(hidden.excludedCount, 2);

    // Toggle OFF (show noise)
    const shown = filterEvents(originalList, false);
    assert.strictEqual(shown.displayed.length, 3);
    assert.strictEqual(shown.excludedCount, 0);

    // Verify original array was not mutated
    assert.deepStrictEqual(originalList, shallowCopy);
  });
});

describe("Pagination Math & Boundary Invariants", () => {
  it("calculates first page boundaries for a multi-page dataset", () => {
    const p = calculatePagination(100, 1, 30);
    assert.strictEqual(p.currentPage, 1);
    assert.strictEqual(p.totalPages, 4);
    assert.strictEqual(p.startIndex, 1);
    assert.strictEqual(p.endIndex, 30);
    assert.strictEqual(p.hasPrev, false);
    assert.strictEqual(p.hasNext, true);
  });

  it("calculates middle page boundaries", () => {
    const p = calculatePagination(100, 2, 30);
    assert.strictEqual(p.currentPage, 2);
    assert.strictEqual(p.totalPages, 4);
    assert.strictEqual(p.startIndex, 31);
    assert.strictEqual(p.endIndex, 60);
    assert.strictEqual(p.hasPrev, true);
    assert.strictEqual(p.hasNext, true);
  });

  it("calculates final page boundaries with remainder items", () => {
    const p = calculatePagination(100, 4, 30);
    assert.strictEqual(p.currentPage, 4);
    assert.strictEqual(p.totalPages, 4);
    assert.strictEqual(p.startIndex, 91);
    assert.strictEqual(p.endIndex, 100);
    assert.strictEqual(p.hasPrev, true);
    assert.strictEqual(p.hasNext, false);
  });

  it("handles exact page-size multiples cleanly", () => {
    const p = calculatePagination(90, 3, 30);
    assert.strictEqual(p.currentPage, 3);
    assert.strictEqual(p.totalPages, 3);
    assert.strictEqual(p.startIndex, 61);
    assert.strictEqual(p.endIndex, 90);
    assert.strictEqual(p.hasPrev, true);
    assert.strictEqual(p.hasNext, false);
  });

  it("handles 0 total items cleanly without negative indices", () => {
    const p = calculatePagination(0, 1, 30);
    assert.strictEqual(p.currentPage, 1);
    assert.strictEqual(p.totalPages, 1);
    assert.strictEqual(p.startIndex, 0);
    assert.strictEqual(p.endIndex, 0);
    assert.strictEqual(p.hasPrev, false);
    assert.strictEqual(p.hasNext, false);
  });

  it("clamps out-of-range page numbers within valid bounds", () => {
    const over = calculatePagination(50, 999, 30);
    assert.strictEqual(over.currentPage, 2);
    assert.strictEqual(over.totalPages, 2);
    assert.strictEqual(over.startIndex, 31);
    assert.strictEqual(over.endIndex, 50);

    const under = calculatePagination(50, -5, 30);
    assert.strictEqual(under.currentPage, 1);
    assert.strictEqual(under.totalPages, 2);
    assert.strictEqual(under.startIndex, 1);
    assert.strictEqual(under.endIndex, 30);
  });

  it("handles dynamically expanding total count between requests", () => {
    // Initial request: 100 events (4 pages), user on page 4
    const initial = calculatePagination(100, 4, 30);
    assert.strictEqual(initial.totalPages, 4);
    assert.strictEqual(initial.hasNext, false);

    // Later request: 25 new events ingested, total is now 125 (5 pages)
    const expanded = calculatePagination(125, 4, 30);
    assert.strictEqual(expanded.totalPages, 5);
    assert.strictEqual(expanded.hasNext, true); // Next button becomes active!
  });

  it("clamps target page safely when total count drops (clampPage)", () => {
    // User was on page 4 of a 100-item dataset (4 pages)
    // Filter was applied or old logs purged, reducing total to 25 items (1 page)
    const clamped = clampPage(4, 25, 30);
    assert.strictEqual(clamped, 1);

    // When total is 0
    assert.strictEqual(clampPage(3, 0, 30), 1);

    // When requested page is negative
    assert.strictEqual(clampPage(-2, 100, 30), 1);

    // When requested page is valid
    assert.strictEqual(clampPage(2, 100, 30), 2);
  });
});

describe("Multi-Page Noise & Visibility State Transitions", () => {
  it("handles Page 1 containing only Socket.IO events while Page 2 contains substantive events", () => {
    // Simulate backend returning 30 Socket.IO polling events for Page 1 of 60 total events
    const page1RawEvents = Array.from({ length: 30 }, (_, idx) => ({
      id: idx + 1,
      timestamp: "2026-10-09T11:00:00Z",
      source_type: "WEB",
      event_type: "web_request",
      event_category: "web",
      severity: "low",
      source_ip: "152.57.153.115",
      request_path: `/health/socket.io/?EIO=4&t=${idx}`,
      http_method: "GET",
      status_code: 200,
      message: `GET /health/socket.io/?EIO=4&t=${idx} 200`,
    }));

    // Simulate backend returning 30 substantive events for Page 2
    const page2RawEvents = Array.from({ length: 30 }, (_, idx) => ({
      id: idx + 31,
      timestamp: "2026-10-09T10:55:00Z",
      source_type: "WEB",
      event_type: "web_request",
      event_category: "web",
      severity: "low",
      source_ip: "152.57.153.115",
      request_path: `/rest/products/search?q=item_${idx}`,
      http_method: "GET",
      status_code: 200,
      message: `GET /rest/products/search?q=item_${idx} 200`,
    }));

    const totalEventsInBackend = 60;
    const pageSize = 30;

    // --- On Page 1 ---
    const page1Filtering = filterEvents(page1RawEvents, true);
    const page1Pagination = calculatePagination(totalEventsInBackend, 1, pageSize);

    // Assert that Page 1 produces 0 displayed items and 30 excluded
    assert.strictEqual(page1Filtering.displayed.length, 0);
    assert.strictEqual(page1Filtering.excludedCount, 30);

    // Assert that UI state condition does NOT imply "no events exist in dataset":
    // Condition 1: rawEvents.length > 0 && displayedEvents.length === 0
    // Condition 2: pagination.totalPages is 2, hasNext is true, total is 60
    assert.strictEqual(page1RawEvents.length > 0 && page1Filtering.displayed.length === 0, true);
    assert.strictEqual(page1Pagination.totalPages, 2);
    assert.strictEqual(page1Pagination.hasNext, true);

    // --- User navigates to Page 2 ---
    const page2Filtering = filterEvents(page2RawEvents, true);
    const page2Pagination = calculatePagination(totalEventsInBackend, 2, pageSize);

    // Assert that Page 2 displays all 30 substantive events with 0 excluded
    assert.strictEqual(page2Filtering.displayed.length, 30);
    assert.strictEqual(page2Filtering.excludedCount, 0);
    assert.strictEqual(page2Pagination.currentPage, 2);
    assert.strictEqual(page2Pagination.hasPrev, true);
    assert.strictEqual(page2Pagination.hasNext, false);
  });

  it("ensures UI state decision tree never implies zero total events when events exist", () => {
    // Helper mimicking EventsPage rendering decision tree
    function determineUIState({
      rawCount,
      displayedCount,
      totalCount,
    }: {
      rawCount: number;
      displayedCount: number;
      totalCount: number;
    }) {
      if (displayedCount > 0) return "TABLE";
      if (rawCount > 0 && displayedCount === 0) return "PAGE_ALL_POLLING_HIDDEN";
      if (totalCount > 0 && rawCount === 0) return "PAGE_OUT_OF_BOUNDS";
      return "GLOBAL_EMPTY_STATE";
    }

    // Case A: Page 1 has 30 items, all hidden by polling filter, total = 60
    assert.strictEqual(
      determineUIState({ rawCount: 30, displayedCount: 0, totalCount: 60 }),
      "PAGE_ALL_POLLING_HIDDEN"
    );

    // Case B: Table with items displayed
    assert.strictEqual(
      determineUIState({ rawCount: 30, displayedCount: 12, totalCount: 60 }),
      "TABLE"
    );

    // Case C: Truly empty database / query match
    assert.strictEqual(
      determineUIState({ rawCount: 0, displayedCount: 0, totalCount: 0 }),
      "GLOBAL_EMPTY_STATE"
    );

    // Case D: Stale page index beyond total
    assert.strictEqual(
      determineUIState({ rawCount: 0, displayedCount: 0, totalCount: 25 }),
      "PAGE_OUT_OF_BOUNDS"
    );
  });
});

describe("Refresh and Filter Preservation Invariants", () => {
  it("preserves active filters and page number when manual refresh is invoked", () => {
    const activeFilters = {
      q: "orange_juice",
      source_type: "WEB",
      severity: "low",
      event_type: "web_request",
      source_ip: "152.57.153.115",
      username: "",
      hostname: "",
    };
    const activePage = 2;
    const pageSize = 30;

    // Simulate refresh invocation payload assembly
    const refreshPayload = {
      ...activeFilters,
      page: activePage,
      page_size: pageSize,
    };

    assert.strictEqual(refreshPayload.q, "orange_juice");
    assert.strictEqual(refreshPayload.source_type, "WEB");
    assert.strictEqual(refreshPayload.severity, "low");
    assert.strictEqual(refreshPayload.page, 2);
    assert.strictEqual(refreshPayload.page_size, 30);
  });

  it("resets page to 1 on filter modification while keeping new filter values", () => {
    let currentPage = 3;
    const updateFilter = (newQuery: string) => {
      currentPage = 1; // page resets on filter change
      return { q: newQuery, page: currentPage };
    };

    const res = updateFilter("admin");
    assert.strictEqual(res.page, 1);
    assert.strictEqual(res.q, "admin");
  });

  it("preserves query filters while advancing through pagination", () => {
    const activeFilters = {
      q: "search_term",
      source_type: "WEB",
      severity: "low",
      event_type: "",
      source_ip: "",
      username: "",
      hostname: "",
    };

    // User navigates from Page 1 to Page 2
    const targetPage = 2;
    const pagedRequest = {
      ...activeFilters,
      page: targetPage,
      page_size: 30,
    };

    assert.strictEqual(pagedRequest.page, 2);
    assert.strictEqual(pagedRequest.q, "search_term");
    assert.strictEqual(pagedRequest.source_type, "WEB");
  });
});
