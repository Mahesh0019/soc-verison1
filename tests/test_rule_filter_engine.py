"""
tests/test_rule_filter_engine.py

Unit tests for rule-filter engine enhancements in Phase 11 Stage 3:
1. Matching when path does not contain excluded substrings.
2. Exclusion when path contains excluded substrings.
3. Missing paths (None and empty string) handled correctly without false exclusion.
4. Empty exclusion lists ([]) matching all events.
5. Case-insensitive token evaluation in both Python and SQL.
6. Database query filtering equivalence (apply_filters with SQLite and NULL handling).
7. Threshold query batching optimization equivalence with baseline per-event evaluation.
"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AUTO_CREATE_TABLES"] = "true"
os.environ["ENABLE_JUICE_SHOP_CONNECTOR"] = "false"
os.environ["JWT_SECRET_KEY"] = "filter-test-secret-key-12345"

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.models import Alert, DetectionRule, NormalizedEvent
from app.rules.engine import (
    apply_filters,
    evaluate_rules_for_events,
    evaluate_threshold_rule,
    evaluate_threshold_rule_batched,
    event_matches_filters,
)


class TestRuleFilterEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        cls.SessionLocal = sessionmaker(
            bind=cls.engine, autoflush=False, autocommit=False, expire_on_commit=False
        )
        Base.metadata.create_all(bind=cls.engine)

    def _create_event(
        self,
        event_id: int,
        path: str | None,
        source_ip: str = "192.0.2.1",
        category: str = "web",
        status_code: int = 200,
        offset_seconds: int = 0,
    ) -> NormalizedEvent:
        now = datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC) + timedelta(seconds=offset_seconds)
        return NormalizedEvent(
            id=event_id,
            timestamp=now,
            source_type="test_connector",
            event_category=category,
            event_type="web_request",
            severity="low",
            source_ip=source_ip,
            request_path=path,
            status_code=status_code,
            message="Test event",
        )

    def test_01_matching_when_path_does_not_contain_excluded_tokens(self):
        """Path not containing any excluded tokens must return True (match)."""
        ev = self._create_event(1, "/rest/products/search?q=apple")
        filters = {
            "event_category": "web",
            "request_path_not_contains_any": ["/socket.io", "/assets/", "/media/"],
        }
        self.assertTrue(
            event_matches_filters(ev, filters),
            "Legitimate product search path should match filter",
        )

    def test_02_exclusion_when_path_contains_excluded_token(self):
        """Path containing an excluded token must return False (excluded)."""
        filters = {
            "event_category": "web",
            "request_path_not_contains_any": ["/socket.io", "/assets/", "/media/"],
        }
        # Exact match
        ev1 = self._create_event(1, "/socket.io/?EIO=4&transport=polling")
        self.assertFalse(
            event_matches_filters(ev1, filters),
            "/socket.io/ must be excluded",
        )
        # Nested prefix match
        ev2 = self._create_event(2, "/health/socket.io/?transport=polling")
        self.assertFalse(
            event_matches_filters(ev2, filters),
            "/health/socket.io/ must be excluded because /socket.io is in the path",
        )
        # Static asset match
        ev3 = self._create_event(3, "/assets/public/images/products/apple_press.jpg")
        self.assertFalse(
            event_matches_filters(ev3, filters),
            "/assets/ path must be excluded",
        )
        # Media match
        ev4 = self._create_event(4, "/media/videos/promo.mp4")
        self.assertFalse(
            event_matches_filters(ev4, filters),
            "/media/ path must be excluded",
        )

    def test_03_missing_paths_handled_without_false_exclusion(self):
        """Events with request_path=None or empty string must not be excluded."""
        filters = {
            "event_category": "web",
            "request_path_not_contains_any": ["/socket.io", "/assets/", "/media/"],
        }
        # None path
        ev_none = self._create_event(5, None)
        self.assertTrue(
            event_matches_filters(ev_none, filters),
            "Event with None request_path must not be falsely excluded by exclusion filter",
        )
        # Empty string path
        ev_empty = self._create_event(6, "")
        self.assertTrue(
            event_matches_filters(ev_empty, filters),
            "Event with empty request_path must not be falsely excluded",
        )

    def test_04_empty_exclusion_lists(self):
        """When request_path_not_contains_any is empty, no paths are excluded."""
        filters_empty = {
            "event_category": "web",
            "request_path_not_contains_any": [],
        }
        ev1 = self._create_event(7, "/socket.io/?EIO=4")
        ev2 = self._create_event(8, "/assets/bundle.js")
        ev3 = self._create_event(9, "/rest/products/1")
        self.assertTrue(event_matches_filters(ev1, filters_empty))
        self.assertTrue(event_matches_filters(ev2, filters_empty))
        self.assertTrue(event_matches_filters(ev3, filters_empty))

        # Also test with empty string inside list
        filters_blank_item = {
            "event_category": "web",
            "request_path_not_contains_any": [""],
        }
        self.assertTrue(event_matches_filters(ev3, filters_blank_item))

    def test_05_case_insensitivity(self):
        """Exclusion tokens must match case-insensitively."""
        filters = {
            "request_path_not_contains_any": ["/socket.io", "/ASSETS/"],
        }
        # Mixed casing in request path
        ev1 = self._create_event(10, "/HEALTH/SOCKET.IO/?transport=polling")
        self.assertFalse(event_matches_filters(ev1, filters))

        ev2 = self._create_event(11, "/assets/images/logo.png")
        self.assertFalse(event_matches_filters(ev2, filters))

    def test_06_database_apply_filters_sql_execution(self):
        """Verify apply_filters generates valid SQL and returns correct matching rows from SQLite."""
        db = self.SessionLocal()
        try:
            # Clean up prior test events
            db.query(Alert).delete()
            db.query(NormalizedEvent).delete()
            db.commit()

            events = [
                self._create_event(101, "/rest/products/1", "10.0.0.1"),
                self._create_event(102, "/health/socket.io/?t=1", "10.0.0.1"),
                self._create_event(103, "/assets/bundle.js", "10.0.0.1"),
                self._create_event(104, None, "10.0.0.1"),  # NULL request_path
                self._create_event(105, "/media/photo.jpg", "10.0.0.1"),
                self._create_event(106, "/rest/user/login", "10.0.0.1"),
            ]
            db.add_all(events)
            db.commit()

            filters = {
                "event_category": "web",
                "request_path_not_contains_any": ["/socket.io", "/assets/", "/media/"],
            }
            query = db.query(NormalizedEvent)
            query = apply_filters(query, filters)
            results = query.order_by(NormalizedEvent.id.asc()).all()

            matched_ids = [r.id for r in results]
            # 101 (/rest/products/1), 104 (None), 106 (/rest/user/login) should match
            # 102 (/socket.io), 103 (/assets/), 105 (/media/) must be excluded
            self.assertEqual(matched_ids, [101, 104, 106])

            # Also verify empty filter list in SQL returns all web events
            empty_query = db.query(NormalizedEvent)
            empty_query = apply_filters(empty_query, {"event_category": "web", "request_path_not_contains_any": []})
            self.assertEqual(len(empty_query.all()), 6)
        finally:
            db.close()

    def test_07_batched_threshold_evaluation_equivalence(self):
        """Verify evaluate_threshold_rule_batched produces identical results to evaluate_threshold_rule."""
        db = self.SessionLocal()
        try:
            db.query(Alert).delete()
            db.query(NormalizedEvent).delete()
            db.commit()

            rule = DetectionRule(
                id=801,
                name="Candidate Volume Burst",
                description="Test candidate rule",
                category="traffic_anomaly",
                severity="medium",
                version="1.0",
                status="ACTIVE",
                enabled=True,
                conditions_json={
                    "type": "threshold",
                    "filters": {
                        "event_category": "web",
                        "request_path_not_contains_any": ["/socket.io", "/assets/"],
                    },
                    "group_by": ["source_ip"],
                },
                time_window_minutes=5,
                threshold=10,
            )
            db.add(rule)
            db.commit()

            # Generate 15 events in 2 minutes: 12 API requests and 3 socket.io polls
            events: list[NormalizedEvent] = []
            for i in range(12):
                events.append(self._create_event(200 + i, f"/rest/products/{i}", "10.0.0.5", offset_seconds=i * 5))
            for i in range(3):
                events.append(self._create_event(250 + i, f"/health/socket.io/?t={i}", "10.0.0.5", offset_seconds=i * 5 + 2))
            events.sort(key=lambda e: e.timestamp)

            db.add_all(events)
            db.commit()

            # Run baseline evaluate_threshold_rule
            alert_ids_seq = evaluate_threshold_rule(db, rule, events)
            db.commit()
            self.assertEqual(len(alert_ids_seq), 1, "Baseline should trigger 1 alert for 12 API requests >= 10")

            # Clean alerts and run batched evaluate_threshold_rule_batched
            db.query(Alert).delete()
            db.commit()

            alert_ids_batch = evaluate_threshold_rule_batched(db, rule, events)
            db.commit()
            self.assertEqual(len(alert_ids_batch), 1, "Batched should trigger 1 alert")

            # Both should produce an alert with event_count >= 10
            alert = db.query(Alert).first()
            self.assertIsNotNone(alert)
            self.assertGreaterEqual(alert.event_count, 10)
        finally:
            db.close()

    def test_08_query_parameter_bypass_neutralization(self):
        """Query parameters containing excluded tokens must NEVER cause the path to be excluded."""
        filters = {
            "event_category": "web",
            "request_path_not_contains_any": ["/socket.io", "/assets/", "/media/"],
        }
        # Scraper attempting evasion via query parameter
        ev1 = self._create_event(301, "/rest/products/search?q=apple&bypass=/socket.io")
        self.assertTrue(
            event_matches_filters(ev1, filters),
            "URL with /socket.io only in query string must NOT be excluded",
        )

        ev2 = self._create_event(302, "/rest/products/1?ref=/assets/public/images/logo.png")
        self.assertTrue(
            event_matches_filters(ev2, filters),
            "URL with /assets/ only in query string must NOT be excluded",
        )

        ev3 = self._create_event(303, "/api/v1/auth?redirect=https://victim.com/socket.io/poll")
        self.assertTrue(
            event_matches_filters(ev3, filters),
            "URL with /socket.io in redirect query param must NOT be excluded",
        )

    def test_09_encoded_paths_handling(self):
        """Percent-encoded excluded paths must be decoded and properly excluded."""
        filters = {
            "event_category": "web",
            "request_path_not_contains_any": ["/socket.io", "/assets/", "/media/"],
        }
        # %73 = 's' -> /health/socket.io/
        ev1 = self._create_event(304, "/health/%73ocket.io/?transport=polling")
        self.assertFalse(
            event_matches_filters(ev1, filters),
            "Encoded /%73ocket.io/ path must be normalized and excluded",
        )

        # %61 = 'a' -> /assets/
        ev2 = self._create_event(305, "/%61ssets/public/app.js")
        self.assertFalse(
            event_matches_filters(ev2, filters),
            "Encoded /%61ssets/ path must be normalized and excluded",
        )

    def test_10_path_traversal_normalization(self):
        """Path traversal sequences (e.g. /assets/../rest/products) must normalize to true path."""
        filters = {
            "event_category": "web",
            "request_path_not_contains_any": ["/socket.io", "/assets/", "/media/"],
        }
        # Attacker pretends to access /assets/ but traverses out to /rest/products
        ev1 = self._create_event(306, "/assets/../rest/products/search")
        self.assertTrue(
            event_matches_filters(ev1, filters),
            "/assets/../rest/products normalizes to /rest/products and must NOT be excluded",
        )

        # Conversely, traversing INTO an excluded directory must be excluded
        ev2 = self._create_event(307, "/public/../assets/images/logo.png")
        self.assertFalse(
            event_matches_filters(ev2, filters),
            "/public/../assets/ normalizes to /assets/ and MUST be excluded",
        )

    def test_11_malformed_and_edge_case_urls(self):
        """Malformed and edge-case URLs must be parsed safely without crashing."""
        filters = {
            "event_category": "web",
            "request_path_not_contains_any": ["/socket.io", "/assets/", "/media/"],
        }
        # Multi-slash paths
        ev1 = self._create_event(308, "///socket.io///poll")
        self.assertFalse(event_matches_filters(ev1, filters))

        # Absolute URL with scheme and host
        ev2 = self._create_event(309, "https://victim.com/health/socket.io/?eio=4")
        self.assertFalse(event_matches_filters(ev2, filters))

        # Malformed percent encoding
        ev3 = self._create_event(310, "/rest/products/%zz/search?q=/socket.io")
        self.assertTrue(
            event_matches_filters(ev3, filters),
            "Malformed percent encoding must not crash and query param must not exclude",
        )

        # Whitespace-padded path
        ev4 = self._create_event(311, "   /rest/products/1   ")
        self.assertTrue(event_matches_filters(ev4, filters))

    def test_12_database_apply_filters_query_bypass_and_encoded_paths(self):
        """Verify database query apply_filters handles query-parameter bypasses in SQL."""
        db = self.SessionLocal()
        try:
            db.query(Alert).delete()
            db.query(NormalizedEvent).delete()
            db.commit()

            events = [
                self._create_event(401, "/rest/products/search?q=1&bypass=/socket.io", "10.0.0.1"),
                self._create_event(402, "/health/socket.io/?eio=4", "10.0.0.1"),
                self._create_event(403, "/assets/main.js", "10.0.0.1"),
                self._create_event(404, "/rest/products/2?ref=/assets/logo.png", "10.0.0.1"),
                self._create_event(405, None, "10.0.0.1"),
            ]
            db.add_all(events)
            db.commit()

            filters = {
                "event_category": "web",
                "request_path_not_contains_any": ["/socket.io", "/assets/"],
            }
            query = db.query(NormalizedEvent)
            query = apply_filters(query, filters)
            results = query.order_by(NormalizedEvent.id.asc()).all()

            matched_ids = [r.id for r in results]
            # 401 (/rest/products/search?bypass=...), 404 (/rest/products/2?ref=...), 405 (None) must be MATCHED
            # 402 (/health/socket.io/...), 403 (/assets/...) must be EXCLUDED
            self.assertEqual(matched_ids, [401, 404, 405])
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()

