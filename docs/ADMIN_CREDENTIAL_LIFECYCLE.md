# Administrator Credential Lifecycle & Recovery Policy

## Overview
This document specifies the operational lifecycle, self-service rotation, container restart behavior, and disaster recovery path for administrator credentials in the Detection-Quality-Aware SOC Framework.

---

## 1. Initial Bootstrap Phase
When deploying the SOC backend for the first time, the application database undergoes automatic schema synchronization and seed initialization (`ensure_users()`).

1. **Environment Configuration**:
   - Set `INITIAL_ADMIN_PASSWORD` in the environment (e.g., Render Environment Variables, Docker Compose `.env`, or Kubernetes Secret).
   - Minimum password length: **10 characters** (enforced by schema validators).
2. **Execution**:
   - On container startup, `ensure_users()` creates the `admin` account with the password hashed using Argon2.
   - If `INITIAL_ADMIN_PASSWORD` is omitted during local development, demo defaults are seeded for non-production evaluation only.

---

## 2. In-App Password Rotation (Self-Service)
Once the system is operational:
1. **Self-Service Rotation**:
   - An authenticated administrator changes their password via `POST /api/auth/change-password`.
   - The endpoint requires:
     - Authentication via JWT Bearer token (`HTTP 401` on absence/expiry).
     - Exact verification of `current_password` (`HTTP 400` on mismatch).
     - Pydantic validation of `new_password` (`HTTP 422` if shorter than 10 characters).
2. **Audit Trail**:
   - A secure audit record is committed to `audit_logs` with action `AUTH_PASSWORD_CHANGED`.
   - **Zero Secret Exposure**: The plaintext password is never recorded in `details_json`, console logs, or exception traces.

---

## 3. Predictable Restart Behavior
To guarantee predictable behavior across container redeployments and restarts:
- **Production Mode (Recommended)**:
  - After initial bootstrap, **unset `INITIAL_ADMIN_PASSWORD`** in the host environment settings.
  - When `INITIAL_ADMIN_PASSWORD` is unset (`None`), `ensure_users()` preserves the existing `admin` password hash across all container restarts.
  - Any password updated through `POST /api/auth/change-password` remains permanent.
- **Persistent Environment Variable Mode**:
  - If `INITIAL_ADMIN_PASSWORD` is left persistently configured in the container environment, `ensure_users()` evaluates it on every startup. This serves as an authoritative static configuration anchor.

---

## 4. Disaster Recovery Path
If the administrator password is lost, forgotten, or compromised:
1. Access the hosting provider control panel (e.g. Render Dashboard, AWS ECS, or Docker host).
2. Set or update `INITIAL_ADMIN_PASSWORD` with a new secure password.
3. Restart or redeploy the backend container.
4. On startup, `ensure_users()` detects `INITIAL_ADMIN_PASSWORD`, hashes it with Argon2, and updates the `admin` user record.
5. Log in with the newly configured password.
6. (Optional) Unset `INITIAL_ADMIN_PASSWORD` in the hosting environment to resume self-service lifecycle management.

---

## 5. Security Invariants
- **No Plaintext Logging**: Passwords and secrets are excluded from `AuditLog`, API error messages, and server tracebacks.
- **Fail-Closed RBAC**: Non-admin users cannot access administrative password reset endpoints (`POST /api/admin/users/{user_id}/reset-password` returns `HTTP 403 Forbidden`).
- **Fail-Closed Database**: In `ENVIRONMENT=production`, database unavailability raises `RuntimeError` and refuses fallback to SQLite.
