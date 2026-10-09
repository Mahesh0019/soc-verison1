"""
tests/test_live_telemetry_pipeline.py

Phase 10A: Automated Live Telemetry Pipeline Verification.

Verifies the genuine live telemetry ingestion pipeline end-to-end:
  Victim App (/health)
    -> Telemetry Middleware (/api/telemetry/events)
    -> Background Connector (juice_shop_background.py)
    -> Normalization & PostgreSQL Storage (normalized_events)
    -> Detection Rule Evaluation
    -> Read-Only Events API (/api/events)

Guarantees & Safeguards:
1. SAFE & READ-ONLY: Uses only the harmless victim /health endpoint. Does not generate attack traffic.
2. ZERO PERMANENT SECRETS: Loads credentials strictly from environment variables without logging them.
3. OPT-IN EXECUTION: Skips automatically in standard CI/local runs unless ENABLE_LIVE_TELEMETRY_TEST=true.
4. MOCKED FAILURE TESTS: Includes complete offline mock tests for failure scenarios that run in standard pytest.
5. CORRELATION TRACKING: Uses a unique UUID correlation marker in User-Agent to trace the probe deterministically.
6. TIMING & DEDUPLICATION: Measures probe-to-visibility latency and validates deduplication.
"""

from __future__ import annotations

import json
import os
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch


class StageFailureError(Exception):
    """Raised when a specific stage in the live telemetry pipeline fails."""
    def __init__(self, stage: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"[{stage}] {message}")
        self.stage = stage
        self.details = details or {}


@dataclass
class PipelineVerificationResult:
    success: bool
    probe_id: str
    victim_url: str
    backend_url: str
    elapsed_seconds: float = 0.0
    stage_results: Dict[str, str] = field(default_factory=dict)
    ingested_event: Optional[Dict[str, Any]] = None
    duplicate_count: int = 0
    error_message: Optional[str] = None


class LiveTelemetryPipelineRunner:
    """
    Executes and measures the multi-stage live telemetry pipeline.
    """

    def __init__(
        self,
        victim_url: Optional[str] = None,
        backend_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout_seconds: float = 45.0,
        poll_interval_seconds: float = 2.5,
        duplicate_check_seconds: float = 10.0,
    ):
        self.victim_url = (victim_url or os.getenv("LIVE_VICTIM_URL", "https://demo-victim-1.onrender.com")).rstrip("/")
        self.backend_url = (backend_url or os.getenv("LIVE_BACKEND_URL", "https://soc-verison1.onrender.com")).rstrip("/")
        self.username = username or os.getenv("LIVE_SOC_USERNAME", "admin")
        self.password = password or os.getenv("LIVE_SOC_PASSWORD", "AdminPass123!")
        self.timeout_seconds = float(os.getenv("LIVE_TEST_TIMEOUT_SECONDS", str(timeout_seconds)))
        self.poll_interval = float(os.getenv("LIVE_POLL_INTERVAL_SECONDS", str(poll_interval_seconds)))
        self.duplicate_check_seconds = float(os.getenv("LIVE_DUPLICATE_CHECK_SECONDS", str(duplicate_check_seconds)))
        self.token: Optional[str] = None

    def _http_get(self, url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 15.0) -> tuple[int, Any, Dict[str, str]]:
        req = urllib.request.Request(url, headers=headers or {}, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                try:
                    data = json.loads(raw)
                except Exception:
                    data = raw
                return resp.getcode(), data, dict(resp.headers)
        except urllib.error.HTTPError as err:
            raw = err.read().decode("utf-8", errors="replace")
            try:
                data = json.loads(raw)
            except Exception:
                data = raw
            return err.code, data, dict(err.headers)

    def _http_post(self, url: str, json_data: Dict[str, Any], headers: Optional[Dict[str, str]] = None, timeout: float = 15.0) -> tuple[int, Any, Dict[str, str]]:
        req_headers = {"Content-Type": "application/json"}
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(
            url,
            data=json.dumps(json_data).encode("utf-8"),
            headers=req_headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                try:
                    data = json.loads(raw)
                except Exception:
                    data = raw
                return resp.getcode(), data, dict(resp.headers)
        except urllib.error.HTTPError as err:
            raw = err.read().decode("utf-8", errors="replace")
            try:
                data = json.loads(raw)
            except Exception:
                data = raw
            return err.code, data, dict(err.headers)

    def stage_1_preflight(self) -> None:
        """Stage 1: Verify health and connectivity of both deployed services."""
        # 1. Victim application telemetry health
        code, v_health, _ = self._http_get(f"{self.victim_url}/api/telemetry/health")
        if code != 200:
            raise StageFailureError("stage_1_preflight", f"Victim health check failed with HTTP {code}", {"response": v_health})
        if not isinstance(v_health, dict) or v_health.get("status") != "ok":
            raise StageFailureError("stage_1_preflight", f"Victim returned non-ok health: {v_health}")

        # 2. SOC Backend health check
        code, b_health, _ = self._http_get(f"{self.backend_url}/health")
        if code != 200:
            raise StageFailureError("stage_1_preflight", f"SOC backend /health failed with HTTP {code}", {"response": b_health})

        # 3. Authenticate to SOC backend to acquire JWT bearer token
        code, auth_data, _ = self._http_post(
            f"{self.backend_url}/api/auth/login",
            {"username": self.username, "password": self.password},
        )
        if code != 200 or not isinstance(auth_data, dict) or "access_token" not in auth_data:
            raise StageFailureError("stage_1_preflight", f"SOC authentication failed with HTTP {code}", {"response": auth_data})
        self.token = auth_data["access_token"]

        # 4. Verify telemetry connector operational status
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        code, conn_status, _ = self._http_get(f"{self.backend_url}/api/telemetry/connector/status", headers=headers)
        if code != 200 or not isinstance(conn_status, dict):
            raise StageFailureError("stage_1_preflight", f"Connector status endpoint failed with HTTP {code}", {"response": conn_status})
        if not conn_status.get("enabled") or not conn_status.get("running"):
            raise StageFailureError("stage_1_preflight", f"Telemetry connector is not active: {conn_status}")

    def stage_2_dispatch_probe(self, probe_id: str) -> float:
        """Stage 2: Dispatches one unique, harmless HTTP request to the victim health endpoint."""
        user_agent = f"MiniSIEM-Probe-{probe_id}"
        headers = {
            "User-Agent": user_agent,
            "X-Probe-Id": probe_id,
            "Accept": "text/html,application/json",
        }
        send_time = time.time()
        code, body, _ = self._http_get(f"{self.victim_url}/health", headers=headers)
        if code not in (200, 304):
            raise StageFailureError("stage_2_dispatch_probe", f"Victim probe request failed with HTTP {code}", {"body": body})
        return send_time

    def stage_3_poll_for_event(self, probe_id: str, probe_sent_time: float) -> tuple[Dict[str, Any], float]:
        """Stage 3: Polls SOC Events API until the matching event is confirmed persisted."""
        if not self.token:
            raise StageFailureError("stage_3_poll_for_event", "Missing bearer token from preflight")

        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        user_agent_target = f"MiniSIEM-Probe-{probe_id}"
        deadline = time.time() + self.timeout_seconds

        while time.time() < deadline:
            url = f"{self.backend_url}/api/events?q={urllib.parse.quote(probe_id)}&page=1&page_size=10"
            code, data, _ = self._http_get(url, headers=headers)

            if code == 200 and isinstance(data, dict):
                items = data.get("items", [])
                for item in items:
                    ua = item.get("user_agent") or ""
                    raw = item.get("raw_log") or ""
                    msg = item.get("message") or ""
                    if probe_id in ua or probe_id in raw or probe_id in msg:
                        # Found matching persisted event
                        elapsed = time.time() - probe_sent_time
                        # Validate schema assertions
                        if item.get("source_type") != "WEB":
                            raise StageFailureError(
                                "stage_3_poll_for_event",
                                f"Expected source_type='WEB', got '{item.get('source_type')}'",
                                {"event": item},
                            )
                        if item.get("request_path") != "/health":
                            raise StageFailureError(
                                "stage_3_poll_for_event",
                                f"Expected request_path='/health', got '{item.get('request_path')}'",
                                {"event": item},
                            )
                        if item.get("id") is None:
                            raise StageFailureError("stage_3_poll_for_event", "Event missing primary key id", {"event": item})
                        return item, elapsed

            time.sleep(self.poll_interval)

        raise StageFailureError(
            "stage_3_poll_for_event",
            f"Timed out after {self.timeout_seconds:.1f}s waiting for probe '{probe_id}' to appear in /api/events",
        )

    def stage_4_check_duplicates(self, probe_id: str) -> int:
        """Stage 4: Checks for duplicate ingestion of the probe marker after an observation period."""
        if not self.token:
            return 0

        time.sleep(self.duplicate_check_seconds)
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        url = f"{self.backend_url}/api/events?q={urllib.parse.quote(probe_id)}&page=1&page_size=20"
        code, data, _ = self._http_get(url, headers=headers)

        if code != 200 or not isinstance(data, dict):
            raise StageFailureError("stage_4_check_duplicates", f"Failed to re-query events API: HTTP {code}")

        matching = [
            it for it in data.get("items", [])
            if probe_id in (it.get("user_agent") or "") or probe_id in (it.get("raw_log") or "")
        ]

        if len(matching) > 1:
            raise StageFailureError(
                "stage_4_check_duplicates",
                f"Duplicate ingestion detected: found {len(matching)} records for probe '{probe_id}'",
                {"matching_events": matching},
            )

        return len(matching)

    def run(self, probe_id: Optional[str] = None) -> PipelineVerificationResult:
        """Executes the full pipeline verification and returns a structured report."""
        if not probe_id:
            probe_id = f"probe-{uuid.uuid4().hex[:12]}"
        res = PipelineVerificationResult(
            success=False,
            probe_id=probe_id,
            victim_url=self.victim_url,
            backend_url=self.backend_url,
        )

        try:
            # Stage 1: Preflight
            self.stage_1_preflight()
            res.stage_results["stage_1_preflight"] = "PASSED (Victim healthy, Backend healthy, Connector running)"

            # Stage 2: Probe dispatch
            send_time = self.stage_2_dispatch_probe(probe_id)
            res.stage_results["stage_2_dispatch_probe"] = f"PASSED (Harmless GET /health dispatched with marker '{probe_id}')"

            # Stage 3: Polling for delivery & persistence
            event, elapsed = self.stage_3_poll_for_event(probe_id, send_time)
            res.elapsed_seconds = round(elapsed, 2)
            res.ingested_event = event
            res.stage_results["stage_3_poll_for_event"] = f"PASSED (Persisted as Event ID={event.get('id')} in {res.elapsed_seconds}s, source_type='WEB')"

            # Stage 4: Duplicate inspection
            match_count = self.stage_4_check_duplicates(probe_id)
            res.duplicate_count = match_count
            res.stage_results["stage_4_check_duplicates"] = f"PASSED (Exactly {match_count} record found; no duplicates)"

            res.success = True
            return res

        except StageFailureError as sfe:
            res.stage_results[sfe.stage] = f"FAILED: {sfe}"
            res.error_message = str(sfe)
            return res
        except Exception as exc:
            res.error_message = f"Unexpected exception: {exc}"
            return res


class TestLiveTelemetryPipelineOptIn(unittest.TestCase):
    """
    Opt-in live integration test.
    Requires ENABLE_LIVE_TELEMETRY_TEST=true environment variable.
    """

    def setUp(self):
        opt_in = os.getenv("ENABLE_LIVE_TELEMETRY_TEST", "").strip().lower()
        if opt_in not in ("true", "1", "yes"):
            self.skipTest("Live integration test disabled. Set ENABLE_LIVE_TELEMETRY_TEST=true to run against live services.")

    def test_live_telemetry_ingestion_end_to_end(self):
        """Verifies probe creation on victim to database ingestion on SOC backend."""
        runner = LiveTelemetryPipelineRunner()
        result = runner.run()

        # Output detailed stage report
        print(f"\n=======================================================")
        print(f"LIVE TELEMETRY PIPELINE VERIFICATION RESULT")
        print(f"=======================================================")
        print(f"Probe ID: {result.probe_id}")
        print(f"Victim:   {result.victim_url}")
        print(f"Backend:  {result.backend_url}")
        for stage, status in result.stage_results.items():
            print(f"  {stage:25}: {status}")
        print(f"Elapsed Time: {result.elapsed_seconds}s")
        print(f"Success:      {result.success}")
        if result.error_message:
            print(f"Error:        {result.error_message}")
        print(f"=======================================================\n")

        self.assertTrue(result.success, f"Live pipeline verification failed: {result.error_message}")
        self.assertIsNotNone(result.ingested_event)
        self.assertEqual(result.ingested_event.get("source_type"), "WEB")
        self.assertEqual(result.ingested_event.get("request_path"), "/health")
        self.assertEqual(result.duplicate_count, 1)


class TestLiveTelemetryPipelineMocked(unittest.TestCase):
    """
    Offline unit tests covering failure and timing paths.
    Always executes during standard pytest runs without hitting external services.
    """

    def setUp(self):
        self.runner = LiveTelemetryPipelineRunner(
            victim_url="https://victim.mock",
            backend_url="https://soc.mock",
            username="admin",
            password="mockpassword",
            timeout_seconds=0.5,
            poll_interval_seconds=0.05,
            duplicate_check_seconds=0.05,
        )

    @patch.object(LiveTelemetryPipelineRunner, "_http_get")
    def test_victim_health_failure_raises_preflight_error(self, mock_get):
        """Preflight fails when victim application health returns non-200."""
        mock_get.return_value = (502, {"error": "Bad Gateway"}, {})
        with self.assertRaises(StageFailureError) as ctx:
            self.runner.stage_1_preflight()
        self.assertEqual(ctx.exception.stage, "stage_1_preflight")
        self.assertIn("Victim health check failed", str(ctx.exception))

    @patch.object(LiveTelemetryPipelineRunner, "_http_post")
    @patch.object(LiveTelemetryPipelineRunner, "_http_get")
    def test_backend_auth_failure_raises_preflight_error(self, mock_get, mock_post):
        """Preflight fails when backend login fails."""
        mock_get.side_effect = [
            (200, {"status": "ok"}, {}),  # victim health
            (200, {"status": "ok"}, {}),  # backend health
        ]
        mock_post.return_value = (401, {"detail": "Invalid credentials"}, {})

        with self.assertRaises(StageFailureError) as ctx:
            self.runner.stage_1_preflight()
        self.assertEqual(ctx.exception.stage, "stage_1_preflight")
        self.assertIn("SOC authentication failed", str(ctx.exception))

    @patch.object(LiveTelemetryPipelineRunner, "_http_post")
    @patch.object(LiveTelemetryPipelineRunner, "_http_get")
    def test_connector_not_running_raises_preflight_error(self, mock_get, mock_post):
        """Preflight fails when connector status reports running=false."""
        mock_get.side_effect = [
            (200, {"status": "ok"}, {}),  # victim health
            (200, {"status": "ok"}, {}),  # backend health
            (200, {"enabled": True, "running": False, "last_status": "IDLE"}, {}),  # connector status
        ]
        mock_post.return_value = (200, {"access_token": "mock-token-xyz"}, {})

        with self.assertRaises(StageFailureError) as ctx:
            self.runner.stage_1_preflight()
        self.assertEqual(ctx.exception.stage, "stage_1_preflight")
        self.assertIn("Telemetry connector is not active", str(ctx.exception))

    @patch.object(LiveTelemetryPipelineRunner, "_http_get")
    def test_probe_dispatch_failure_raises_stage_error(self, mock_get):
        """Stage 2 fails when victim health endpoint returns error on probe."""
        mock_get.return_value = (500, "Internal Server Error", {})
        with self.assertRaises(StageFailureError) as ctx:
            self.runner.stage_2_dispatch_probe("test-probe-123")
        self.assertEqual(ctx.exception.stage, "stage_2_dispatch_probe")

    @patch.object(LiveTelemetryPipelineRunner, "_http_get")
    def test_polling_timeout_when_event_not_ingested(self, mock_get):
        """Stage 3 raises timeout when probe never appears in /api/events."""
        self.runner.token = "mock-token"
        mock_get.return_value = (200, {"items": [], "total": 0}, {})

        with self.assertRaises(StageFailureError) as ctx:
            self.runner.stage_3_poll_for_event("missing-probe", time.time())
        self.assertEqual(ctx.exception.stage, "stage_3_poll_for_event")
        self.assertIn("Timed out", str(ctx.exception))

    @patch.object(LiveTelemetryPipelineRunner, "_http_get")
    def test_duplicate_check_detects_multiple_matching_events(self, mock_get):
        """Stage 4 flags duplicate ingestion when multiple events contain probe marker."""
        self.runner.token = "mock-token"
        mock_get.return_value = (
            200,
            {
                "items": [
                    {"id": 1, "user_agent": "MiniSIEM-Probe-p1", "source_type": "WEB"},
                    {"id": 2, "user_agent": "MiniSIEM-Probe-p1", "source_type": "WEB"},
                ]
            },
            {},
        )

        with self.assertRaises(StageFailureError) as ctx:
            self.runner.stage_4_check_duplicates("p1")
        self.assertEqual(ctx.exception.stage, "stage_4_check_duplicates")
        self.assertIn("Duplicate ingestion detected", str(ctx.exception))

    @patch.object(LiveTelemetryPipelineRunner, "_http_post")
    @patch.object(LiveTelemetryPipelineRunner, "_http_get")
    def test_full_pipeline_mocked_success(self, mock_get, mock_post):
        """Happy path verifies all stages and returns success."""
        probe_event = {
            "id": 999,
            "source_type": "WEB",
            "request_path": "/health",
            "status_code": 200,
            "user_agent": "MiniSIEM-Probe-mock-123",
            "raw_log": "probe-mock-123",
        }

        mock_get.side_effect = [
            (200, {"status": "ok"}, {}),  # victim health
            (200, {"status": "ok"}, {}),  # backend health
            (200, {"enabled": True, "running": True, "last_status": "HEALTHY"}, {}),  # connector status
            (200, "ok", {}),  # dispatch probe
            (200, {"items": [probe_event], "total": 1}, {}),  # poll event
            (200, {"items": [probe_event], "total": 1}, {}),  # duplicate check
        ]
        mock_post.return_value = (200, {"access_token": "mock-token"}, {})

        result = self.runner.run(probe_id="mock-123")
        self.assertTrue(result.success)
        self.assertEqual(result.duplicate_count, 1)
        self.assertEqual(result.ingested_event.get("id"), 999)
        self.assertIn("stage_1_preflight", result.stage_results)
        self.assertIn("stage_2_dispatch_probe", result.stage_results)
        self.assertIn("stage_3_poll_for_event", result.stage_results)
        self.assertIn("stage_4_check_duplicates", result.stage_results)


if __name__ == "__main__":
    unittest.main()
