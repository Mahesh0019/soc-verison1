# Phase 10C — Events Visibility and Detection Noise Analysis Plan

## 1. Executive Summary & Context

This document outlines the findings of the **Phase 10C Read-Only Diagnostic Audit** and details the implementation plan for improving events visibility on the SOC dashboard and eliminating detection noise caused by client-side background polling.

### Key Audit Findings
1. **Events Page Has Zero Pagination Controls**:
   [`frontend/src/pages/EventsPage.tsx:28`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/frontend/src/pages/EventsPage.tsx#L28) fetches only `{ page_size: 30 }` without page state or next/previous buttons. When more than 30 events exist, older events are pushed off-screen and become invisible unless filtered specifically.
2. **Events Page Lacks Manual Refresh**:
   The Events page only loads upon initial mount or when filter inputs change. Users browsing the victim application in another tab must edit a filter or reload the browser to see newly ingested events.
3. **Background Socket.IO Polling Floods Event Store**:
   When the victim application (OWASP Juice Shop) is visited at or routed through `/health`, its client-side Socket.IO transport continuously polls `GET /health/socket.io/?...` every 6 seconds. Over a 5-minute session, this single background heartbeat produces 50+ events, dominating Page 1 of the Events table.
4. **RULE-008 False Positive Confirmed**:
   Rule `RULE-008` ("Large request volume burst") sets a 5-minute threshold of 60 requests for `event_category == "web"`. Benign browsing (1 catalog load + 15 product images + 50 Socket.IO polling calls) generates 70+ requests within 5 minutes, triggering a **Medium** severity alert for completely benign user activity.

---

## 2. Itemized Diagnostic Findings & Evidence

### A. How the Events Page Fetches, Paginates, Filters, and Searches

- **Fetching**:
  [`frontend/src/pages/EventsPage.tsx:26-31`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/frontend/src/pages/EventsPage.tsx#L26-L31)
  ```tsx
  const loadEvents = () => {
    setLoading(true);
    fetchEvents({ ...filters, page_size: 30 })
      .then(setData)
      .finally(() => setLoading(false));
  };
  ```
- **Pagination Limitation**:
  The backend endpoint `GET /api/events` fully supports `page` and `page_size` pagination ([`backend/app/api/events.py:19-20`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/api/events.py#L19-L20)). However, `EventsPage.tsx` does **not** track `page` state and renders **no pagination UI** (no "Next", "Previous", or page count). Only the first 30 events are ever displayed.
- **Filters & Search**:
  Supported filters in `EventsPage.tsx`: `q` (free-text across 12 fields), `source_type`, `severity`, `event_type`, `source_ip`, `username`, and `hostname`. All are combined and passed to `fetchEvents(filters)`.

### B. Manual Refresh Design Preserving Filters & Pagination

- **Goal**: Allow analysts to fetch the latest event arrivals on demand without resetting their search query, active filters, or current page.
- **Design**:
  - Add explicit `page` state to `EventsPage.tsx` (`const [page, setPage] = useState(1);`).
  - Add a dedicated **Refresh** button in the header bar featuring `<RefreshCw className="h-4 w-4" />`.
  - When Refresh is clicked:
    - Sets `loading = true`.
    - Triggers `fetchEvents({ ...filters, page, page_size: 30 })`.
    - Preserves all current inputs (`filters.q`, `filters.source_type`, `filters.severity`, etc.) and active `page`.
  - Add standard pagination footer:
    - Display: `Showing {(page - 1) * 30 + 1} - {Math.min(page * 30, data.total)} of {data.total} events`.
    - "Previous" (disabled on `page === 1`) and "Next" (disabled on `page * 30 >= data.total`).
    - Filter change resets `page` to `1`.

### C. UI-Only Toggle for Background Polling (Socket.IO) Noise

- **Goal**: Enable analysts to toggle between viewing raw telemetry (including Socket.IO polling) and an operational view focused on substantive web interactions, **without deleting or suppressing database records**.
- **Design Options**:
  1. **Option 1: Pure Client-Side Filter (Zero Backend Changes)**:
     - Add `hidePollingNoise: boolean` state in `EventsPage.tsx` (default: `true`).
     - In `EventsTable`, filter incoming `data.items`:
       ```typescript
       const displayedEvents = hidePollingNoise
         ? events.filter(e => !(e.request_path && e.request_path.includes("socket.io")))
         : events;
       ```
     - Show an informational pill: `"Filtered out X polling events on this page. [Show All]"`.
  2. **Option 2: Hybrid Query Filter (Optimal Pagination)**:
     - Allow passing `exclude_pattern: "socket.io"` or `exclude_noise: true` to `/api/events`.
     - Ensures that when 30 items are requested, the backend returns 30 non-polling events rather than an empty page caused by 30 consecutive Socket.IO events.
- **Safety**: Both options operate read-only; PostgreSQL persistence in `RawLog` and `NormalizedEvent` remains 100% untouched.

---

## 3. Detection Noise Analysis: RULE-008

### Mathematical Breakdown of the False Positive

- **Rule Definition**: [`backend/app/rules/builtin.py:183-205`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/rules/builtin.py#L183-L205)
  - `rule_id`: `"RULE-008"`
  - `name`: `"Large request volume burst"`
  - `category`: `"traffic_anomaly"`
  - `severity`: `"medium"`
  - `conditions_json`: `{"type": "threshold", "filters": {"event_category": "web"}, "group_by": ["source_ip"]}`
  - `time_window_minutes`: `5`
  - `threshold`: `60`
- **Socket.IO Cadence**:
  The Juice Shop Angular client sends polling requests every **6 seconds**:
  $$\frac{60 \text{ seconds}}{6 \text{ seconds}} = 10 \text{ requests/minute}$$
  Over a 5-minute window, Socket.IO alone generates:
  $$10 \times 5 = 50 \text{ requests}$$
- **Benign Browsing Burst**:
  When a user opens the catalog, the browser requests:
  - Catalog search: `GET /rest/products/search?q=` (1 request)
  - Product thumbnails: 15 static images (15 requests)
  - Application configuration & scoreboard APIs: 5 requests
  - Socket.IO heartbeats: 50 requests
  - **Total**: $21 + 50 = 71 \text{ requests} \ge 60$
- **Result**:
  [`backend/app/rules/engine.py:124-125`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/rules/engine.py#L124-L125) fires `upsert_alert()` and generates Alert ID 232 / 233 (**Medium** severity) for ordinary browsing.

---

## 4. Evaluation Framework: Benign Traffic vs. Attack Scenarios

### Labeled Traffic Profiles

| Scenario ID | Traffic Category | Pattern | Path Characteristics | Volume in 5m | Expected Result |
|---|---|---|---|---|---|
| `BENIGN-01` | Normal Browsing | Single user browsing catalog | Images + `/rest/products/search` + Socket.IO | 65–75 reqs | **NO ALERT** (FP if alerted) |
| `BENIGN-02` | Idle Tab Standby | User leaves tab open | 100% Socket.IO polling heartbeats | 50 reqs | **NO ALERT** |
| `ATTACK-01` | Content Scrape / Crawl | Automated crawler collecting all products | Rapid sequential GETs to `/rest/products/*` | 300+ reqs | **ALERT (RULE-008)** |
| `ATTACK-02` | Endpoint Fuzzing / DoS | `ffuf` / `gobuster` directory brute force | High-rate requests to non-existent / API endpoints | 500+ reqs | **ALERT (RULE-008)** |

### Proposed Rule Refinements (To Be Implemented Post-Approval)

1. **Approach A: Exclude Polling Noise from Volume Threshold**:
   Update `conditions_json.filters` in `RULE-008` to count only substantive web traffic:
   ```json
   {
     "type": "threshold",
     "filters": {
       "event_category": "web",
       "exclude_path_contains": ["socket.io", "/assets/public/images/"]
     },
     "group_by": ["source_ip"]
   }
   ```
   *Benefit*: Cleanly isolates application-layer bursts while allowing benign users with open tabs to browse indefinitely.
2. **Approach B: Adjust Threshold to Realistic Attack Volume**:
   Increase threshold from 60 to **180** requests in 5 minutes (36 req/min = 0.6 req/sec).
   *Benefit*: Benign browsing with 10 req/min Socket.IO never exceeds 60 req in 5m, while real scraping attacks (>1 req/sec) remain immediately detectable.

---

## 5. Test Plan for Phase 10C

### A. Frontend Unit Tests (`frontend/tests/eventsPage.test.ts`)
1. **Refresh State Preservation**: Verifies that triggering refresh preserves `filters.q`, `filters.severity`, and `page`.
2. **Pagination Math & Boundary Tests**: Verifies total pages calculation, disabled states on first and last page, and page reset on filter update.
3. **Polling Noise Filter Logic**: Verifies that when `hidePollingNoise` is enabled, `/socket.io/` paths are omitted while genuine `/rest/products/search` events are retained.

### B. Rule Evaluation Tests (`tests/test_rule_008_noise.py`)
1. **Benign Browsing Session (Negative Test)**: Ingests 50 Socket.IO polling events + 15 product images; asserts that `RULE-008` does **not** trigger.
2. **High-Rate Application Burst (Positive Test)**: Ingests 200 rapid requests to `/rest/products/search`; asserts that `RULE-008` triggers an active alert.
3. **Zero False Negative Invariant**: Confirms that existing rules (`RULE-004` SQLi, `RULE-005` XSS, `RULE-009` Suspicious UA) remain 100% functional and unhindered.

---

---

## 7. Pagination Review & Page-Level Filtering Architecture Decision

### Architectural Decision
In accordance with Phase 10C approved scope ("limited to manual refresh, pagination, and a UI-only background-polling visibility toggle; keep backend ingestion and PostgreSQL records unchanged"), the visibility toggle is implemented as a **client-side page-window filter**.

### Evaluated Invariants and Behaviors
1. **Case: Page 1 contains only Socket.IO polling, while Page 2 contains substantive events**:
   - Page 1 retrieves 30 Socket.IO polling events from the backend (total = 60).
   - Client-side noise filtering excludes all 30 polling events (`displayed = 0`, `excludedCount = 30`).
   - The UI displays a dedicated empty-on-this-page banner:
     *"All 30 events on this page are background Socket.IO polling. There are 60 total events matching your query across 2 pages."*
   - Direct action buttons are provided: `[Show Polling Events on This Page]` and `[Go to Next Page (Page 2)]`.
   - The UI never implies the dataset is empty.
2. **Case: Mixture of background and substantive events on one page**:
   - The table renders the substantive events (e.g. 12 displayed, 18 excluded).
   - An informational banner clearly displays the exclusion count with a one-click `[Show All on Page]` button.
   - The pagination footer displays: `Showing 1 – 30 of 100 events (12 substantive displayed, 18 polling excluded on this page)`.
3. **Case: Toggling visibility**:
   - Switching between hiding and showing background events is instantaneous and in-memory.
   - No network re-fetch is triggered; current page number, active search query, and dropdown filters are preserved without array mutation.
4. **Case: Active filters and pagination**:
   - Search term (`q`), `source_type`, `severity`, etc., are preserved when navigating between pages.
   - Any modification to search or dropdown filters immediately resets the current page to 1.
5. **Case: Refresh on a later page & Count Changes**:
   - Manual refresh preserves the active page and filters.
   - If the total event count shrinks between requests (e.g., from 100 to 25 items while the user is on page 4), the application uses `clampPage` to automatically redirect and re-fetch page 1 (`maxPage`), preventing stranded empty pages.
   - Out-of-order responses from rapid filter changes or page clicks are safely discarded using an asynchronous request counter ref.
6. **Case: Total count is zero**:
   - When `total === 0`, `calculatePagination` yields safe zero-boundaries (`startIndex = 0`, `endIndex = 0`, `hasPrev = false`, `hasNext = false`), rendering the standard empty state without showing pagination controls or exclusion banners.

### Documented Page-Level Filtering Limitation
- **Page-Window Scope**: The client-side toggle filters background events **within each 30-event page retrieved from the backend**. It does not query the database for 30 consecutive non-polling events across the entire dataset.
- **Variable Display Count**: As a result, pages may display fewer than 30 rows when background events are hidden.
- **Future Server-Side Option (Phase 11)**: To achieve uniform 30-event substantive pages across the entire dataset, a future enhancement may add an optional query parameter to the backend `GET /api/events` endpoint (e.g., `exclude_noise=true` or `exclude_path_contains=socket.io`). This requires backend approval and is out of scope for Phase 10C.

---

> [!NOTE]
> **Implementation Complete**: Phase 10C frontend pagination, manual refresh, and noise toggle have been implemented and verified with 39 passing tests. No commits, pushes, deployments, or backend detection rule modifications have been executed.
