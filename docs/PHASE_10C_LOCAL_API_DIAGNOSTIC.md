# Phase 10C Local Verification — API & CORS Diagnostic Report

**Target Repository**: [https://github.com/Mahesh0019/soc-verison1](https://github.com/Mahesh0019/soc-verison1)  
**Local Frontend**: `http://localhost:5173/`  
**Production Backend**: `https://soc-verison1.onrender.com/`  
**Production Dashboard**: `https://soc-verison1.vercel.app/`  
**Checkpoint / Baseline**: `6a153ae17c676e92b7fc7208b374c2646e99b4f6` (Frozen Phase 0–9 baseline)  
**Current Branch / Commit**: `main` @ `ddf9c49abb8d2931c52606571df6f177e1890f8c`  
**Diagnostic Status**: **COMPLETED (READ-ONLY)**. Awaiting review and approval before applying any fix.

---

## 1. Executive Summary & Root Cause

When loading `http://localhost:5173/events` in a local browser, the UI displays:
- **Events View**: *"No events found for current filters"*
- **Header KPI**: *"Pipeline Unavailable"*
- **Browser DevTools Network Console**: Preflight `OPTIONS` requests fail with `CORS error` and `HTTP 400 Bad Request`.

### Root Cause
1. **Direct Cross-Origin Targeting**: The local Vite frontend (`http://localhost:5173`) is configured via `VITE_API_URL` to send API requests directly to the production Render backend (`https://soc-verison1.onrender.com/api`).
2. **CORS Preflight Trigger**: Because the requests carry custom headers (`Authorization: Bearer <token>` and `Content-Type: application/json`) across different origins, the browser automatically dispatches an `OPTIONS` preflight request prior to every `GET`/`POST`.
3. **Disallowed Origin on Render**: The production FastAPI backend on Render uses Starlette's `CORSMiddleware` (`backend/app/main.py:81-87`). On Render, the `CORS_ORIGINS` environment variable is strictly configured for the deployed production frontend (`https://soc-verison1.vercel.app`). It does **not** include `http://localhost:5173`.
4. **Starlette HTTP 400 Response**: When an origin is disallowed in preflight, Starlette's `CORSMiddleware` explicitly returns **HTTP 400 Bad Request** with body `"Disallowed CORS origin"`. Because the preflight receives HTTP 400, the browser blocks the actual `GET` request from firing.

---

## 2. Frontend Configuration & Request Destination Analysis

### A. Frontend API Client & Vite Configuration
In [`frontend/src/services/api.ts:34-39`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/frontend/src/services/api.ts#L34-L39):
```typescript
const API_BASE_URL = import.meta.env.VITE_API_URL ?? "/api";

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: { "Content-Type": "application/json" },
});
```
When `VITE_API_URL` is set to an absolute URL (`https://soc-verison1.onrender.com/api`):
- Axios resolves relative endpoints against that absolute URL.
- The built-in Vite dev proxy defined in [`frontend/vite.config.ts:8-10`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/frontend/vite.config.ts#L8-L10) (`proxy: { "/api": "http://localhost:8000" }`) is **completely bypassed** because Axios makes direct browser-to-Render network requests.

### B. Exact Destination URLs
| Component Request | Code Location | Exact Target Destination URL | Host Evaluated |
|---|---|---|---|
| Events Data | [`frontend/src/services/api.ts:71`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/frontend/src/services/api.ts#L71) | `https://soc-verison1.onrender.com/api/events?page=1&page_size=30` | **Production Render Backend** |
| Connector Status | [`frontend/src/services/api.ts:419`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/frontend/src/services/api.ts#L419) | `https://soc-verison1.onrender.com/api/telemetry/connector/status` | **Production Render Backend** |
| Auth Login | [`frontend/src/services/api.ts:61`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/frontend/src/services/api.ts#L61) | `https://soc-verison1.onrender.com/api/auth/login` | **Production Render Backend** |

---

## 3. Backend CORS Middleware & Preflight Investigation

### A. Backend Code Inspection
In [`backend/app/main.py:81-87`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/main.py#L81-L87):
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=[str(origin) for origin in settings.cors_origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```
In [`backend/app/config.py:15-26`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/backend/app/config.py#L15-L26):
```python
cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

@field_validator("cors_origins", mode="before")
@classmethod
def assemble_cors_origins(cls, v: Any) -> list[str]:
    if isinstance(v, str):
        if v.strip() == "*":
            return ["*"]
        return [i.strip() for i in v.split(",") if i.strip()]
    elif isinstance(v, (list, set, tuple)):
        return [str(i) for i in v]
    return ["http://localhost:5173", "http://127.0.0.1:5173"]
```
In local development with default config, `cors_origins` includes `localhost:5173`.  
However, on the production Render deployment, the service environment overrides `CORS_ORIGINS` to restrict access strictly to the production frontend (`https://soc-verison1.vercel.app`).

### B. Empirical Evidence: Preflight Probing

We transmitted controlled `OPTIONS` preflight requests directly to the production backend (`https://soc-verison1.onrender.com/api/events?page=1&page_size=30`) comparing both origins:

#### 1. Probe with `Origin: http://localhost:5173` (Local Frontend)
```http
OPTIONS /api/events?page=1&page_size=30 HTTP/1.1
Host: soc-verison1.onrender.com
Origin: http://localhost:5173
Access-Control-Request-Method: GET
Access-Control-Request-Headers: authorization,content-type
```
**Response Received**:
```http
HTTP/1.1 400 Bad Request
Date: Fri, 09 Oct 2026 12:28:12 GMT
Content-Type: text/plain; charset=utf-8
Server: cloudflare
Vary: Origin
x-render-origin-server: uvicorn

Disallowed CORS origin
```
*Observation*: Starlette `CORSMiddleware` rejects `http://localhost:5173`, emits `HTTP 400 Disallowed CORS origin`, and withholds `Access-Control-Allow-Origin`. The browser treats this as a CORS preflight failure and cancels the request.

#### 2. Probe with `Origin: https://soc-verison1.vercel.app` (Production Dashboard)
```http
OPTIONS /api/events?page=1&page_size=30 HTTP/1.1
Host: soc-verison1.onrender.com
Origin: https://soc-verison1.vercel.app
Access-Control-Request-Method: GET
Access-Control-Request-Headers: authorization,content-type
```
**Response Received**:
```http
HTTP/1.1 200 OK
Date: Fri, 09 Oct 2026 12:28:21 GMT
Content-Type: text/plain; charset=utf-8
access-control-allow-origin: https://soc-verison1.vercel.app
access-control-allow-credentials: true
access-control-allow-methods: DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT
access-control-allow-headers: authorization,content-type
access-control-max-age: 600
Server: cloudflare
```
*Observation*: Preflight succeeds with `HTTP 200 OK` and returns authorized CORS headers.

---

## 4. Failure Classification & Distinction

| Failure Category | Status | Empirical Evidence |
|---|---|---|
| **CORS Preflight Error** | **CONFIRMED ROOT CAUSE** | Starlette `CORSMiddleware` returns `HTTP 400 Disallowed CORS origin` for `Origin: http://localhost:5173`. The browser suppresses the outbound `GET` request. |
| **Authentication Failure (401/403)** | **RULED OUT** | The request never reaches FastAPI's `get_current_user` dependency. When authenticated directly via script, credentials and JWT tokens are valid and accepted by Render. |
| **Incorrect Route / 404** | **RULED OUT** | The endpoints `/api/events` and `/api/telemetry/connector/status` exist, return HTTP 200 for allowed origins, and match the backend OpenAPI schema. |
| **Server Crash / 500 / 502** | **RULED OUT** | Render backend is operational (`/health` returns `HTTP 200 {"status":"ok","service":"Mini SIEM Dashboard"}`). The HTTP 400 is an intended security rejection by Starlette middleware. |

---

## 5. Minimal Fix Recommendations

To enable local browser verification without compromising security or modifying production deployments, there are two distinct architectural options:

### Option A (Recommended — Frontend Vite Dev Proxy, Zero Production Changes)
Use Vite's built-in reverse proxy in [`frontend/vite.config.ts`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/frontend/vite.config.ts) to forward local requests to Render server-to-server:

1. **Update [`frontend/vite.config.ts`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/frontend/vite.config.ts)**:
   ```typescript
   export default defineConfig({
     plugins: [react()],
     server: {
       port: 5173,
       proxy: {
         "/api": {
           target: "https://soc-verison1.onrender.com",
           changeOrigin: true,
           secure: true,
         },
       },
     },
   });
   ```
2. **Update [`frontend/.env`](file:///c:/Users/User/OneDrive/Desktop/mini-siem-dashboard/frontend/.env)**:
   ```env
   VITE_API_URL=/api
   ```
3. **Why this is superior**:
   - The browser sends requests to `http://localhost:5173/api/...` (**same-origin**).
   - Because it is same-origin, the browser **does not send CORS preflight `OPTIONS` requests**.
   - Vite forwards the request over HTTPS to Render with `changeOrigin: true` (`Host: soc-verison1.onrender.com`), completely transparent to the backend.
   - **Zero changes** to production settings, backend code, or Render environment variables.

### Option B (Render Production Environment Variable Update)
Log into the Render Dashboard and append `http://localhost:5173` to the backend environment variable:
```env
CORS_ORIGINS=https://soc-verison1.vercel.app,http://localhost:5173
```
- **Trade-off**: Requires modifying the live production service environment on Render and exposes the production backend to local origins.

---

## 6. Safeguards & Preserved State

- **Backend & Victim Application**: Completely untouched.
- **RULE-008 & Detection Engine**: Untouched and unmodified.
- **Phase 0–9 Research Baseline**: Checkpoint `6a153ae17c676e92b7fc7208b374c2646e99b4f6` remains strictly frozen (`git diff 6a153ae17c676e92b7fc7208b374c2646e99b4f6..HEAD --stat research/` is empty).
- **Phase 10B Production Deployment**: Active on Vercel and unaffected.
- **No Unapproved Deployments**: Stopped and awaiting direction.
