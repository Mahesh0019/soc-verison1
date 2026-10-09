# Phase 10A — Automated Live Telemetry Pipeline Testing Guide

## 1. Overview & Architecture

Phase 10A provides automated end-to-end verification for genuine live telemetry ingestion across the deployed Mini-SIEM platform:
- **Victim Application**: Juice Shop on Render (`https://demo-victim-1.onrender.com`) instrumented with in-memory telemetry middleware (`GET /api/telemetry/events`).
- **SOC Backend**: FastAPI & PostgreSQL on Render (`https://soc-verison1.onrender.com`).
- **Telemetry Connector**: Asynchronous background polling worker in the backend fetching upstream victim events every 10 seconds.
- **Normalization & Persistence**: Maps victim HTTP events to `NormalizedEvent` (`source_type="WEB"`, `request_path`, `user_agent`, `status_code`, etc.) and persists them to the PostgreSQL database.
- **SOC Events API**: Authenticated search route (`GET /api/events?q=...`) exposing ingested telemetry for analyst dashboards and correlation engines.

```
+-------------------------------------------------------+
|  Stage 1: Preflight Connectivity & Auth Verification   |
|  - GET https://demo-victim-1.onrender.com/api/telemetry/health
|  - GET https://soc-verison1.onrender.com/health       |
|  - POST /api/auth/login -> JWT Bearer Token           |
|  - GET /api/telemetry/connector/status -> running=True |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|  Stage 2: Probe Dispatch                              |
|  - Harmless GET /health to Victim Application         |
|  - Marker: User-Agent: MiniSIEM-Probe-probe-<uuid12>  |
|  - No exploit payload, no destructive data            |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|  Stage 3: Telemetry Ingestion & Schema Polling        |
|  - Polls GET /api/events?q=probe-<uuid12> (max 45s)   |
|  - Asserts event persisted with valid database ID     |
|  - Validates source_type == "WEB"                     |
|  - Validates request_path == "/health"                |
|  - Measures elapsed end-to-end ingestion latency      |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|  Stage 4: Duplicate Ingestion Verification             |
|  - Waits observation window (default: 10s)            |
|  - Verifies count of matching probe events == 1       |
+-------------------------------------------------------+
```

---

## 2. Mandatory Safety & Safeguard Design

1. **Opt-In Guard**: By default, running standard `pytest` **skips** live tests. The live integration test only executes if `ENABLE_LIVE_TELEMETRY_TEST=true` is set.
2. **Offline Unit Tests Independent of Network**: Complete mocked unit tests (`TestLiveTelemetryPipelineMocked`) validate every stage and failure condition offline without network access.
3. **No Exploits / Destructive Requests**: The diagnostic probe calls only the benign `/health` endpoint of the victim application.
4. **No Secret Leakage**: The unique correlation marker `probe-<12-hex>` contains random hex characters only. Passwords and JWT tokens are kept strictly in memory and are never printed to stdout.
5. **Read-Only / Zero Production Pollution**: The test does not seed, delete, or modify existing production events or database tables.

---

## 3. Environment Variables Configuration

| Variable | Default Value | Description |
|---|---|---|
| `ENABLE_LIVE_TELEMETRY_TEST` | *(unset)* | Set to `true`, `1`, or `yes` to enable live pipeline testing. |
| `LIVE_VICTIM_URL` | `https://demo-victim-1.onrender.com` | Base URL of deployed victim application. |
| `LIVE_BACKEND_URL` | `https://soc-verison1.onrender.com` | Base URL of deployed SOC backend. |
| `LIVE_SOC_USERNAME` | `admin` | Administrative account for backend authentication. |
| `LIVE_SOC_PASSWORD` | `AdminPass123!` | Password for backend authentication. |
| `LIVE_TEST_TIMEOUT_SECONDS` | `45.0` | Maximum time to wait for the probe to appear in `/api/events`. |
| `LIVE_POLL_INTERVAL_SECONDS` | `2.5` | Polling cadence when checking `/api/events`. |
| `LIVE_DUPLICATE_CHECK_SECONDS` | `10.0` | Observation duration to confirm no duplicate ingestion occurs. |

---

## 4. Execution Instructions

### A. Run Safe Offline Mocked Unit Tests (CI & Local Safe)
```bash
# Windows / Linux / macOS
python -m pytest tests/test_live_telemetry_pipeline.py -v
```
**Expected Outcome**: 7 tests pass, 1 test (`test_live_telemetry_ingestion_end_to_end`) is safely skipped.

### B. Run Opt-In Live Telemetry Pipeline Test (Production Verification)
#### In PowerShell (Windows):
```powershell
$env:ENABLE_LIVE_TELEMETRY_TEST="true"
python -m pytest tests/test_live_telemetry_pipeline.py -k test_live_telemetry_ingestion_end_to_end -s -v
```

#### In Bash (Linux / macOS):
```bash
ENABLE_LIVE_TELEMETRY_TEST=true python -m pytest tests/test_live_telemetry_pipeline.py -k test_live_telemetry_ingestion_end_to_end -s -v
```

---

## 5. Expected Output

When run with `ENABLE_LIVE_TELEMETRY_TEST=true` against live services:

```text
=======================================================
LIVE TELEMETRY PIPELINE VERIFICATION RESULT
=======================================================
Probe ID: probe-6f3592bc7b0c
Victim:   https://demo-victim-1.onrender.com
Backend:  https://soc-verison1.onrender.com
  stage_1_preflight        : PASSED (Victim healthy, Backend healthy, Connector running)
  stage_2_dispatch_probe   : PASSED (Harmless GET /health dispatched with marker 'probe-6f3592bc7b0c')
  stage_3_poll_for_event   : PASSED (Persisted as Event ID=5042 in 14.82s, source_type='WEB')
  stage_4_check_duplicates : PASSED (Exactly 1 record found; no duplicates)
Elapsed Time: 14.82s
Success:      True
=======================================================
PASSED
```

---

## 6. Localizing Failures & Troubleshooting Guide

| Failed Stage | Possible Root Cause | Diagnostic Steps & Remediation |
|---|---|---|
| **`stage_1_preflight` (Victim)** | Victim service sleeping (HTTP 502/504) or telemetry endpoint down. | Check `https://demo-victim-1.onrender.com/api/telemetry/health`. If sleeping, wait 30s for Render spinup. |
| **`stage_1_preflight` (Backend)** | SOC Backend unresponsive or database connection failed. | Check `https://soc-verison1.onrender.com/health`. Verify PostgreSQL connectivity and Render deployment logs. |
| **`stage_1_preflight` (Auth)** | Credentials rejected or token expired. | Verify `LIVE_SOC_USERNAME` and `LIVE_SOC_PASSWORD`. |
| **`stage_1_preflight` (Connector)** | Telemetry connector background task stopped or disabled. | Check `/api/telemetry/connector/status`. Call `POST /api/telemetry/connector/start` if disabled. |
| **`stage_2_dispatch_probe`** | Victim `/health` route failed or network connection reset. | Confirm victim web server handles `/health`. |
| **`stage_3_poll_for_event` (Timeout)** | Ingestion latency exceeded timeout (45s). Upstream victim buffer did not buffer request, or connector cycle missed it. | Inspect backend Render logs for `[CONNECTOR]` errors. Increase `LIVE_TEST_TIMEOUT_SECONDS=60` if upstream victim is experiencing high latency. |
| **`stage_3_poll_for_event` (Schema)** | Event persisted with incorrect schema (e.g. `source_type != "WEB"` or `request_path != "/health"`). | Verify normalizer logic in `backend/app/services/telemetry_normalizer.py`. |
| **`stage_4_check_duplicates`** | Multiple events ingested for the same probe marker. | Check victim buffer drain logic; ensure buffer clears after read. |

---

## 7. Limitations & Architectural Notes

1. **Free-Tier Spin-Up Delays**: Both the victim application and the SOC backend are hosted on Render free tier. If inactive for >15 minutes, initial requests may encounter a 30–50 second wake-up latency.
2. **Buffer Drain Semantics**: The victim middleware drains events upon reading (`GET /api/telemetry/events`). This prevents duplicate polling ingestion but requires the connector to be actively running to capture ephemeral buffer contents.
3. **Correlation ID Field Preservation**: The victim telemetry captures `User-Agent`, `path`, and `method`. The probe embeds the correlation ID inside the `User-Agent` header (`MiniSIEM-Probe-probe-<uuid>`), which is reliably preserved in the backend `NormalizedEvent.user_agent` and searchable via `GET /api/events?q=...`.
