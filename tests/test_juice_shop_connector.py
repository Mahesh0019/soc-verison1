"""
Unit tests for OWASP Juice Shop Telemetry Connector.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from connector.juice_shop_connector import (
    ConnectorConfig,
    generate_message,
    load_checkpoint,
    poll_and_process,
    save_checkpoint,
    transform_event,
)


class TestJuiceShopConnector(unittest.TestCase):

    def setUp(self) -> None:
        self.sample_telemetry_event = {
            "event_id": "evt_98765",
            "timestamp": "2026-09-26T12:00:07.533Z",
            "source_ip": "49.43.203.178",
            "method": "GET",
            "path": "/api/Quantitys/",
            "status_code": 304,
            "response_time_ms": 405.03,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "user_identity": "anonymous",
            "request_body_snippet": "sensitive_data_to_ignore",
            "event_type": "HTTP_REQUEST",
        }

    def test_telemetry_to_siem_field_mapping(self) -> None:
        """Verify Juice Shop telemetry fields map correctly into Mini-SIEM NormalizedEvent schema."""
        transformed = transform_event(self.sample_telemetry_event)
        self.assertIsNotNone(transformed)
        self.assertEqual(transformed["timestamp"], "2026-09-26T12:00:07.533Z")
        self.assertEqual(transformed["source_ip"], "49.43.203.178")
        self.assertEqual(transformed["http_method"], "GET")
        self.assertEqual(transformed["request_path"], "/api/Quantitys/")
        self.assertEqual(transformed["status_code"], 304)
        self.assertEqual(transformed["user_agent"], "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        self.assertEqual(transformed["username"], "anonymous")
        self.assertEqual(transformed["event_type"], "web_request")
        self.assertEqual(transformed["event_category"], "web")
        self.assertEqual(transformed["severity"], "low")
        self.assertEqual(transformed["message"], "GET /api/Quantitys/ returned 304 (405.03ms)")
        # Ensure sensitive request body snippet is NOT in transformed dict or message
        self.assertNotIn("request_body_snippet", transformed)
        self.assertNotIn("sensitive_data_to_ignore", transformed["message"])

    def test_message_generation(self) -> None:
        """Verify SIEM message formatting."""
        msg = generate_message("POST", "/rest/user/login", 401, 120.5)
        self.assertEqual(msg, "POST /rest/user/login returned 401 (120.5ms)")

    def test_malformed_event_handling(self) -> None:
        """Verify malformed telemetry records do not crash the connector."""
        # Non-dict input
        self.assertIsNone(transform_event("not_a_dict"))
        self.assertIsNone(transform_event([]))

        # Missing timestamp
        event_missing_ts = {"source_ip": "1.1.1.1", "method": "GET"}
        self.assertIsNone(transform_event(event_missing_ts))

        # Non-integer status code and non-float response time fallback safely
        event_bad_types = {
            "timestamp": "2026-09-26T12:00:00Z",
            "status_code": "invalid",
            "response_time_ms": None,
        }
        res = transform_event(event_bad_types)
        self.assertIsNotNone(res)
        self.assertEqual(res["status_code"], 200)
        self.assertEqual(res["message"], "GET / returned 200 (0.0ms)")

    def test_checkpoint_behavior(self) -> None:
        """Verify load_checkpoint and save_checkpoint reading and writing to disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cp_path = Path(tmpdir) / ".checkpoint"
            # Initial state should be None
            self.assertIsNone(load_checkpoint(cp_path))

            # Save checkpoint
            save_checkpoint(cp_path, "evt_001")
            self.assertEqual(load_checkpoint(cp_path), "evt_001")

            # Overwrite checkpoint
            save_checkpoint(cp_path, "evt_002")
            self.assertEqual(load_checkpoint(cp_path), "evt_002")

    def test_duplicate_prevention(self) -> None:
        """Verify checkpoint filtering prevents duplicate event submission."""
        config = ConnectorConfig()
        with tempfile.TemporaryDirectory() as tmpdir:
            config.checkpoint_file = Path(tmpdir) / ".checkpoint"
            save_checkpoint(config.checkpoint_file, "evt_100")

            events_fetched = [
                {"event_id": "evt_100", "timestamp": "2026-09-26T12:00:00Z"},
                {"event_id": "evt_101", "timestamp": "2026-09-26T12:01:00Z"},
            ]

            with patch("connector.juice_shop_connector.fetch_telemetry", return_value=events_fetched):
                with patch("connector.juice_shop_connector.ingest_batch_to_siem") as mock_ingest:
                    count = poll_and_process(config)
                    self.assertEqual(count, 1)
                    # Verify only evt_101 was sent to SIEM
                    mock_ingest.assert_called_once()
                    sent_events = mock_ingest.call_args[1]["events"]
                    self.assertEqual(len(sent_events), 1)
                    self.assertEqual(load_checkpoint(config.checkpoint_file), "evt_101")


if __name__ == "__main__":
    unittest.main()
