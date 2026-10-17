"""
tests/test_rule_007_exclusion_regression.py

Regression test suite for RULE-007 (Repeated sensitive path access) exact-path exclusion:
- TC-01: Benign SPA metadata traffic (GET /rest/admin/application-version, application-configuration)
- TC-02: Genuine administrative probing (GET /admin/settings, /admin/users)
- TC-03: Sensitive file reconnaissance (GET /.env)
- TC-04: Mixed benign & genuine attack traffic (metadata + /admin/users)
- TC-05: Sub-threshold genuine attack traffic with benign padding (must NOT alert)
- TC-06: State-changing method abuse on metadata endpoint (POST /rest/admin/application-configuration)
- TC-07: Subpath traversal / smuggling attempt (GET /rest/admin/application-version/secrets)
- TC-08: Query parameter handling on metadata endpoint
- TC-09: Case-insensitivity & trailing slash normalization
- TC-10: Batched versus unbatched threshold evaluation equivalence
"""

from __future__ import annotations

import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.models import Alert, AlertEvent, DetectionRule, NormalizedEvent, RawLog
from app.rules.builtin import builtin_rules
from app.rules.engine import (
    apply_filters,
    evaluate_rules_for_events,
    evaluate_threshold_rule,
    evaluate_threshold_rule_batched,
    event_matches_filters,
    normalize_request_path,
)
from app.services.seed import ensure_builtin_rules


class TestRule007ExclusionRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        cls.SessionLocal = sessionmaker(bind=cls.engine, autoflush=False, autocommit=False)
        Base.metadata.create_all(bind=cls.engine)

    def setUp(self):
        self.db = self.SessionLocal()
        # Clean up database tables
        self.db.query(AlertEvent).delete()
        self.db.query(Alert).delete()
        self.db.query(NormalizedEvent).delete()
        self.db.query(RawLog).delete()
        self.db.query(DetectionRule).delete()
        self.db.commit()

        # Seed builtin rules
        ensure_builtin_rules(self.db)
        self.db.commit()

        # Retrieve RULE-007
        self.rule_007 = self.db.query(DetectionRule).filter(DetectionRule.rule_id == "RULE-007").first()
        self.assertIsNotNone(self.rule_007, "RULE-007 must exist in builtin rules")

    def tearDown(self):
        self.db.close()

    def _create_event(
        self,
        event_id: int,
        path: str | None,
        method: str = "GET",
        status_code: int = 200,
        source_ip: str = "192.0.2.10",
        offset_seconds: int = 0,
        base_time: datetime | None = None,
    ) -> NormalizedEvent:
        if base_time is None:
            base_time = datetime(2026, 10, 17, 12, 0, 0, tzinfo=UTC)
        ts = base_time + timedelta(seconds=offset_seconds)
        raw_log = RawLog(source_type="web", original_content=f"log_{event_id}")
        self.db.add(raw_log)
        self.db.flush()

        event = NormalizedEvent(
            id=event_id,
            raw_log_id=raw_log.id,
            timestamp=ts,
            source_type="WEB",
            event_category="web",
            event_type="web_request",
            severity="low",
            source_ip=source_ip,
            request_path=path,
            http_method=method,
            status_code=status_code,
            message=f"{method} {path} HTTP/{status_code}",
        )
        self.db.add(event)
        self.db.flush()
        return event

    def test_tc01_benign_spa_metadata_traffic(self):
        """TC-01: 4 requests to GET /rest/admin/application-version and /application-configuration must generate 0 alerts."""
        events = [
            self._create_event(1, "/rest/admin/application-version", method="GET", status_code=304, offset_seconds=0),
            self._create_event(2, "/rest/admin/application-configuration", method="GET", status_code=304, offset_seconds=10),
            self._create_event(3, "/rest/admin/application-version", method="GET", status_code=200, offset_seconds=20),
            self._create_event(4, "/rest/admin/application-configuration", method="GET", status_code=304, offset_seconds=30),
        ]
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, events, auto_correlate=False, use_batched_threshold=True, rules_override=[self.rule_007]
        )
        self.db.commit()

        self.assertEqual(alert_count, 0, "Benign SPA metadata requests must not trigger RULE-007")
        alerts = self.db.query(Alert).all()
        self.assertEqual(len(alerts), 0)

    def test_tc02_genuine_admin_probing(self):
        """TC-02: 4 requests to GET /admin/settings must trigger 1 alert with 4 events linked."""
        events = [
            self._create_event(10, "/admin/settings", method="GET", status_code=403, offset_seconds=0),
            self._create_event(11, "/admin/users", method="GET", status_code=401, offset_seconds=15),
            self._create_event(12, "/admin/roles", method="GET", status_code=403, offset_seconds=30),
            self._create_event(13, "/admin/audit", method="GET", status_code=403, offset_seconds=45),
        ]
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, events, auto_correlate=False, use_batched_threshold=True, rules_override=[self.rule_007]
        )
        self.db.commit()

        self.assertEqual(alert_count, 1, "Genuine /admin probing must trigger RULE-007")
        alert = self.db.query(Alert).filter(Alert.rule_id == self.rule_007.id).first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.event_count, 4)

        # Check linked events
        linked_event_ids = [link.event_id for link in self.db.query(AlertEvent).filter(AlertEvent.alert_id == alert.id).all()]
        self.assertEqual(sorted(linked_event_ids), [10, 11, 12, 13])

    def test_tc03_sensitive_file_reconnaissance(self):
        """TC-03: 4 requests to GET /.env must trigger 1 alert with 4 events linked."""
        events = [
            self._create_event(20, "/.env", method="GET", status_code=404, offset_seconds=0),
            self._create_event(21, "/.env", method="GET", status_code=404, offset_seconds=10),
            self._create_event(22, "/.env.local", method="GET", status_code=404, offset_seconds=20),
            self._create_event(23, "/.env.production", method="GET", status_code=404, offset_seconds=30),
        ]
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, events, auto_correlate=False, use_batched_threshold=True, rules_override=[self.rule_007]
        )
        self.db.commit()

        self.assertEqual(alert_count, 1, "Probing /.env must trigger RULE-007")
        alert = self.db.query(Alert).filter(Alert.rule_id == self.rule_007.id).first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.event_count, 4)

    def test_tc04_mixed_benign_and_attack_traffic(self):
        """TC-04: Mixed traffic (4 benign metadata + 4 /admin/users attack) must link ONLY the 4 attack events."""
        events = [
            # 4 Benign metadata events
            self._create_event(30, "/rest/admin/application-version", method="GET", status_code=304, offset_seconds=0),
            self._create_event(31, "/rest/admin/application-configuration", method="GET", status_code=304, offset_seconds=10),
            self._create_event(32, "/rest/admin/application-version", method="GET", status_code=304, offset_seconds=20),
            self._create_event(33, "/rest/admin/application-configuration", method="GET", status_code=304, offset_seconds=30),
            # 4 Genuine attack events
            self._create_event(34, "/admin/users", method="GET", status_code=403, offset_seconds=40),
            self._create_event(35, "/admin/users", method="GET", status_code=403, offset_seconds=50),
            self._create_event(36, "/admin/users", method="GET", status_code=403, offset_seconds=60),
            self._create_event(37, "/admin/users", method="GET", status_code=403, offset_seconds=70),
        ]
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, events, auto_correlate=False, use_batched_threshold=True, rules_override=[self.rule_007]
        )
        self.db.commit()

        self.assertEqual(alert_count, 1, "Attack events must trigger RULE-007")
        alert = self.db.query(Alert).filter(Alert.rule_id == self.rule_007.id).first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.event_count, 4, "Event count must only include matched attack events")

        linked_event_ids = [link.event_id for link in self.db.query(AlertEvent).filter(AlertEvent.alert_id == alert.id).all()]
        self.assertEqual(sorted(linked_event_ids), [34, 35, 36, 37], "Only attack event IDs must be linked")
        self.assertTrue(all(eid not in linked_event_ids for eid in [30, 31, 32, 33]))

    def test_tc05_subthreshold_attack_with_benign_padding(self):
        """TC-05: 6 benign metadata + 2 /admin/users (threshold=4) must NOT alert (benign traffic must not pad threshold)."""
        events = [
            # 6 Benign metadata events
            self._create_event(40, "/rest/admin/application-version", method="GET", status_code=304, offset_seconds=0),
            self._create_event(41, "/rest/admin/application-configuration", method="GET", status_code=304, offset_seconds=10),
            self._create_event(42, "/rest/admin/application-version", method="GET", status_code=304, offset_seconds=20),
            self._create_event(43, "/rest/admin/application-configuration", method="GET", status_code=304, offset_seconds=30),
            self._create_event(44, "/rest/admin/application-version", method="GET", status_code=304, offset_seconds=40),
            self._create_event(45, "/rest/admin/application-configuration", method="GET", status_code=304, offset_seconds=50),
            # 2 Genuine attack events (below threshold of 4)
            self._create_event(46, "/admin/users", method="GET", status_code=403, offset_seconds=60),
            self._create_event(47, "/admin/users", method="GET", status_code=403, offset_seconds=70),
        ]
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, events, auto_correlate=False, use_batched_threshold=True, rules_override=[self.rule_007]
        )
        self.db.commit()

        self.assertEqual(alert_count, 0, "Sub-threshold attack with benign padding must NOT trigger an alert")
        alerts = self.db.query(Alert).all()
        self.assertEqual(len(alerts), 0)

    def test_tc06_state_changing_method_abuse(self):
        """TC-06: 4 requests to POST /rest/admin/application-configuration must trigger 1 alert (non-GET not excluded)."""
        events = [
            self._create_event(50, "/rest/admin/application-configuration", method="POST", status_code=401, offset_seconds=0),
            self._create_event(51, "/rest/admin/application-configuration", method="POST", status_code=401, offset_seconds=10),
            self._create_event(52, "/rest/admin/application-configuration", method="POST", status_code=401, offset_seconds=20),
            self._create_event(53, "/rest/admin/application-configuration", method="POST", status_code=401, offset_seconds=30),
        ]
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, events, auto_correlate=False, use_batched_threshold=True, rules_override=[self.rule_007]
        )
        self.db.commit()

        self.assertEqual(alert_count, 1, "POST requests to admin configuration must trigger RULE-007")
        alert = self.db.query(Alert).filter(Alert.rule_id == self.rule_007.id).first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.event_count, 4)

        linked_event_ids = [link.event_id for link in self.db.query(AlertEvent).filter(AlertEvent.alert_id == alert.id).all()]
        self.assertEqual(sorted(linked_event_ids), [50, 51, 52, 53])

    def test_tc07_subpath_traversal_smuggling_attempt(self):
        """TC-07: 4 requests to GET /rest/admin/application-version/secrets must trigger 1 alert (subpaths not excluded)."""
        events = [
            self._create_event(60, "/rest/admin/application-version/secrets", method="GET", status_code=403, offset_seconds=0),
            self._create_event(61, "/rest/admin/application-version/secrets", method="GET", status_code=403, offset_seconds=10),
            self._create_event(62, "/rest/admin/application-version/secrets", method="GET", status_code=403, offset_seconds=20),
            self._create_event(63, "/rest/admin/application-version/secrets", method="GET", status_code=403, offset_seconds=30),
        ]
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, events, auto_correlate=False, use_batched_threshold=True, rules_override=[self.rule_007]
        )
        self.db.commit()

        self.assertEqual(alert_count, 1, "Subpath traversal attempts must trigger RULE-007")
        alert = self.db.query(Alert).filter(Alert.rule_id == self.rule_007.id).first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.event_count, 4)

    def test_tc08_query_param_and_fragment_handling(self):
        """TC-08: 4 requests to GET /rest/admin/application-version?debug=1#info must be excluded (0 alerts)."""
        events = [
            self._create_event(70, "/rest/admin/application-version?debug=1#info", method="GET", status_code=304, offset_seconds=0),
            self._create_event(71, "/rest/admin/application-version?_t=99999", method="GET", status_code=304, offset_seconds=10),
            self._create_event(72, "/rest/admin/application-configuration?v=2", method="GET", status_code=200, offset_seconds=20),
            self._create_event(73, "/rest/admin/application-configuration#top", method="GET", status_code=304, offset_seconds=30),
        ]
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, events, auto_correlate=False, use_batched_threshold=True, rules_override=[self.rule_007]
        )
        self.db.commit()

        self.assertEqual(alert_count, 0, "Metadata requests with query params or fragments must be excluded")

    def test_tc09_case_insensitivity_and_trailing_slash(self):
        """TC-09: 4 requests with uppercase or trailing slash on metadata paths must be excluded (0 alerts)."""
        events = [
            self._create_event(80, "/REST/ADMIN/APPLICATION-VERSION", method="GET", status_code=304, offset_seconds=0),
            self._create_event(81, "/rest/admin/application-version/", method="GET", status_code=304, offset_seconds=10),
            self._create_event(82, "/REST/ADMIN/APPLICATION-CONFIGURATION/", method="GET", status_code=304, offset_seconds=20),
            self._create_event(83, "/rest/admin/application-configuration/", method="GET", status_code=304, offset_seconds=30),
        ]
        self.db.commit()

        alert_count = evaluate_rules_for_events(
            self.db, events, auto_correlate=False, use_batched_threshold=True, rules_override=[self.rule_007]
        )
        self.db.commit()

        self.assertEqual(alert_count, 0, "Case-insensitive and trailing-slash metadata requests must be excluded")

    def test_tc10_batched_vs_unbatched_equivalence(self):
        """TC-10: Evaluate identical mixed payloads with unbatched and batched evaluators and assert 100% equivalence."""
        events = [
            # 3 Benign events
            self._create_event(90, "/rest/admin/application-version", method="GET", status_code=304, offset_seconds=0),
            self._create_event(91, "/rest/admin/application-configuration", method="GET", status_code=304, offset_seconds=10),
            self._create_event(92, "/rest/admin/application-version", method="GET", status_code=304, offset_seconds=20),
            # 5 Attack events
            self._create_event(93, "/admin/access", method="GET", status_code=403, offset_seconds=30),
            self._create_event(94, "/admin/access", method="GET", status_code=403, offset_seconds=40),
            self._create_event(95, "/admin/access", method="GET", status_code=403, offset_seconds=50),
            self._create_event(96, "/admin/access", method="GET", status_code=403, offset_seconds=60),
            self._create_event(97, "/admin/access", method="GET", status_code=403, offset_seconds=70),
        ]
        self.db.commit()

        # Run unbatched
        unbatched_alert_ids = evaluate_threshold_rule(self.db, self.rule_007, events)
        self.db.commit()
        self.assertEqual(len(unbatched_alert_ids), 1)

        unbatched_alert = self.db.query(Alert).filter(Alert.id.in_(unbatched_alert_ids)).first()
        unbatched_count = unbatched_alert.event_count
        unbatched_links = sorted([link.event_id for link in self.db.query(AlertEvent).filter(AlertEvent.alert_id == unbatched_alert.id).all()])

        # Clean alerts
        self.db.query(AlertEvent).delete()
        self.db.query(Alert).delete()
        self.db.commit()

        # Run batched
        batched_alert_ids = evaluate_threshold_rule_batched(self.db, self.rule_007, events)
        self.db.commit()
        self.assertEqual(len(batched_alert_ids), 1)

        batched_alert = self.db.query(Alert).filter(Alert.id.in_(batched_alert_ids)).first()
        batched_count = batched_alert.event_count
        batched_links = sorted([link.event_id for link in self.db.query(AlertEvent).filter(AlertEvent.alert_id == batched_alert.id).all()])

        self.assertEqual(unbatched_count, batched_count)
        self.assertEqual(unbatched_links, batched_links)
        self.assertEqual(unbatched_links, [93, 94, 95, 96, 97])


if __name__ == "__main__":
    unittest.main()
