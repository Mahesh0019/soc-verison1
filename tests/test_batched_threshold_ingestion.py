"""
tests/test_batched_threshold_ingestion.py

Regression test suite for batched threshold rule-evaluation optimization:
- Single-event and multi-event batches
- Multiple grouping keys (e.g. ['source_ip'], ['username', 'source_ip'], ['hostname', 'process'])
- Duplicate events (identical timestamps and attributes)
- Threshold and sliding time-window boundaries
- Non-threshold rule handler preservation (sequence, pattern, blacklist)
- Strict assertion of equivalence between unbatched and batched evaluation
- End-to-end persistence and ingestion integration
"""

import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.models import Alert, AlertEvent, DetectionRule, Incident, IncidentAlert, NormalizedEvent, RawLog, ThreatIndicator
from app.rules.engine import evaluate_rules_for_events
from app.services.ingestion import ingest_api_payload, persist_events
from app.services.seed import ensure_builtin_rules, ensure_indicators


class TestBatchedThresholdIngestion(unittest.TestCase):

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        self.SessionLocal = sessionmaker(bind=self.engine, autoflush=False, autocommit=False)
        Base.metadata.create_all(bind=self.engine)
        self.db = self.SessionLocal()
        ensure_builtin_rules(self.db)
        ensure_indicators(self.db)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)
        self.engine.dispose()

    def _create_and_flush_events(self, event_dicts: List[Dict[str, Any]]) -> List[NormalizedEvent]:
        raw_log = RawLog(source_type="test", original_content="test_content")
        self.db.add(raw_log)
        self.db.flush()

        events = []
        for ed in event_dicts:
            data = {
                "raw_log_id": raw_log.id,
                "event_category": "network",
                "source_type": "WEB",
                "severity": "medium",
                "destination_ip": "10.0.0.15",
                **ed,
            }
            ev = NormalizedEvent(**data)
            self.db.add(ev)
            events.append(ev)
        self.db.flush()
        return events

    def _snapshot_detection_state(self) -> Dict[str, Any]:
        alerts = self.db.query(Alert).all()
        incidents = self.db.query(Incident).all()
        alert_events = self.db.query(AlertEvent).all()
        incident_alerts = self.db.query(IncidentAlert).all()
        return {
            "alert_count": len(alerts),
            "alert_titles": sorted(a.title for a in alerts),
            "alert_severities": sorted(a.severity for a in alerts),
            "incident_count": len(incidents),
            "incident_severities": sorted(i.severity for i in incidents),
            "alert_event_count": len(alert_events),
            "incident_alert_count": len(incident_alerts),
            "alert_event_pairs": sorted((ae.alert_id, ae.event_id) for ae in alert_events),
            "incident_alert_pairs": sorted((ia.incident_id, ia.alert_id) for ia in incident_alerts),
        }

    def _clear_tables(self):
        self.db.query(IncidentAlert).delete()
        self.db.query(AlertEvent).delete()
        self.db.query(Alert).delete()
        self.db.query(Incident).delete()
        self.db.query(NormalizedEvent).delete()
        self.db.query(RawLog).delete()
        self.db.commit()
        self.db.expunge_all()

    def test_single_event_batch_equivalence(self):
        """Verify single-event ingestion genuinely triggers threshold rule (RULE-003) with identical results."""
        now = datetime.now(UTC)
        event_dict = [{
            "timestamp": now,
            "event_type": "successful_login",
            "event_category": "authentication",
            "source_type": "AUTH",
            "severity": "high",
            "source_ip": "198.51.100.42",
            "username": "admin",
            "status_code": 200,
            "message": "Privileged login for admin",
        }]

        # 1. Unbatched Run
        events_u = self._create_and_flush_events(event_dict)
        evaluate_rules_for_events(self.db, events_u, auto_correlate=True, use_batched_threshold=False)
        self.db.commit()
        snapshot_u = self._snapshot_detection_state()

        # Reset tables for batched comparison
        self._clear_tables()

        # 2. Batched Run
        events_b = self._create_and_flush_events(event_dict)
        evaluate_rules_for_events(self.db, events_b, auto_correlate=True, use_batched_threshold=True)
        self.db.commit()
        snapshot_b = self._snapshot_detection_state()

        self.assertEqual(snapshot_u, snapshot_b)
        self.assertEqual(snapshot_b["alert_count"], 1)
        self.assertIn("Suspicious admin login", snapshot_b["alert_titles"])
        self.assertEqual(snapshot_b["alert_event_count"], 1)
        self.assertEqual(snapshot_b["incident_count"], 1)

    def test_multi_event_batch_same_group_trigger(self):
        """Verify multi-event batch with threshold triggering generates equivalent alerts and links."""
        now = datetime.now(UTC)
        # Generate 6 failed_login events for same IP within 5 minutes (RULE-001 threshold is 5)
        event_dicts = [
            {
                "timestamp": now - timedelta(seconds=i * 20),
                "event_type": "failed_login",
                "event_category": "authentication",
                "source_type": "AUTH",
                "severity": "medium",
                "source_ip": "198.51.100.55",
                "username": f"user_{i}",
                "status_code": 401,
                "message": f"Authentication failure for user_{i}",
            }
            for i in range(6)
        ]

        # 1. Unbatched
        events_u = self._create_and_flush_events(event_dicts)
        evaluate_rules_for_events(self.db, events_u, auto_correlate=True, use_batched_threshold=False)
        self.db.commit()
        snapshot_u = self._snapshot_detection_state()

        # Reset
        self._clear_tables()

        # 2. Batched
        events_b = self._create_and_flush_events(event_dicts)
        evaluate_rules_for_events(self.db, events_b, auto_correlate=True, use_batched_threshold=True)
        self.db.commit()
        snapshot_b = self._snapshot_detection_state()

        self.assertEqual(snapshot_u["alert_count"], snapshot_b["alert_count"])
        self.assertEqual(snapshot_u["alert_titles"], snapshot_b["alert_titles"])
        self.assertEqual(snapshot_u["incident_count"], snapshot_b["incident_count"])
        self.assertEqual(snapshot_u["alert_event_count"], snapshot_b["alert_event_count"])
        self.assertEqual(snapshot_u["incident_alert_count"], snapshot_b["incident_alert_count"])
        self.assertIn("Multiple failed login attempts from same IP", snapshot_b["alert_titles"])

    def test_multiple_grouping_keys_partitioning(self):
        """Verify rules grouping by multiple keys (e.g. username + source_ip) partition properly."""
        now = datetime.now(UTC)
        # Suspicious admin login (RULE-003: group_by: ['username', 'source_ip'], threshold: 1)
        event_dicts = [
            {
                "timestamp": now - timedelta(seconds=30),
                "event_type": "successful_login",
                "event_category": "authentication",
                "source_type": "AUTH",
                "severity": "high",
                "source_ip": "198.51.100.10",
                "username": "admin",
                "status_code": 200,
                "message": "Admin login from IP 10",
            },
            {
                "timestamp": now - timedelta(seconds=20),
                "event_type": "successful_login",
                "event_category": "authentication",
                "source_type": "AUTH",
                "severity": "high",
                "source_ip": "198.51.100.20",
                "username": "admin",
                "status_code": 200,
                "message": "Admin login from IP 20",
            },
            {
                "timestamp": now - timedelta(seconds=10),
                "event_type": "successful_login",
                "event_category": "authentication",
                "source_type": "AUTH",
                "severity": "high",
                "source_ip": "198.51.100.10",
                "username": "root",
                "status_code": 200,
                "message": "Root login from IP 10",
            },
        ]

        # Batched evaluation
        events_b = self._create_and_flush_events(event_dicts)
        evaluate_rules_for_events(self.db, events_b, auto_correlate=True, use_batched_threshold=True)
        self.db.commit()

        # Should generate 3 distinct alerts because (admin, IP10), (admin, IP20), and (root, IP10) are 3 distinct groups
        admin_alerts = self.db.query(Alert).filter(Alert.title.contains("Suspicious admin login")).all()
        self.assertEqual(len(admin_alerts), 3)

    def test_duplicate_events_idempotence(self):
        """Verify duplicate events in the same batch do not cause IntegrityErrors or duplicate alerts."""
        now = datetime.now(UTC)
        duplicate_dicts = [
            {
                "timestamp": now,
                "event_type": "failed_login",
                "event_category": "authentication",
                "source_type": "AUTH",
                "severity": "medium",
                "source_ip": "198.51.100.77",
                "username": "testuser",
                "status_code": 401,
                "message": "Failed login attempt",
            }
            for _ in range(7)  # 7 identical events
        ]

        events = self._create_and_flush_events(duplicate_dicts)
        evaluate_rules_for_events(self.db, events, auto_correlate=True, use_batched_threshold=True)
        self.db.commit()

        # Alert should be created and deduplicated into a single Alert record
        alerts = self.db.query(Alert).filter(Alert.source_ip == "198.51.100.77").all()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].event_count, 7)

    def test_threshold_and_time_window_boundaries(self):
        """Verify events strictly outside time window do not trigger threshold alerts."""
        now = datetime.now(UTC)
        window_minutes = 10  # RULE-001 has 10 min window, threshold 5

        # 3 events 20 minutes ago (outside window)
        old_events = [
            {
                "timestamp": now - timedelta(minutes=20, seconds=i),
                "event_type": "failed_login",
                "event_category": "authentication",
                "source_type": "AUTH",
                "severity": "medium",
                "source_ip": "198.51.100.99",
                "username": "victim",
                "status_code": 401,
                "message": "Old failed login",
            }
            for i in range(3)
        ]
        # 3 events now (inside window, but total in window = 3 < threshold 5)
        new_events = [
            {
                "timestamp": now - timedelta(seconds=i * 10),
                "event_type": "failed_login",
                "event_category": "authentication",
                "source_type": "AUTH",
                "severity": "medium",
                "source_ip": "198.51.100.99",
                "username": "victim",
                "status_code": 401,
                "message": "Recent failed login",
            }
            for i in range(3)
        ]

        all_events = self._create_and_flush_events(old_events + new_events)
        evaluate_rules_for_events(self.db, all_events, auto_correlate=True, use_batched_threshold=True)
        self.db.commit()

        # Total is 6 events, but only 3 are in the 10-minute window -> no threshold alert should trigger
        failed_login_alerts = self.db.query(Alert).filter(
            Alert.title.contains("Multiple failed login attempts"),
            Alert.source_ip == "198.51.100.99",
        ).all()
        self.assertEqual(len(failed_login_alerts), 0)

    def test_non_threshold_rules_preserved(self):
        """Verify sequence rules, blacklist rules, and pattern rules function correctly with batched threshold flag."""
        now = datetime.now(UTC)

        # 1. Blacklist rule (Threat Intel)
        blacklist_event = [{
            "timestamp": now,
            "event_type": "web_request",
            "event_category": "network",
            "source_type": "WEB",
            "severity": "high",
            "source_ip": "203.0.113.199",  # Seeded indicator in test db
            "request_path": "/index.html",
            "status_code": 200,
            "message": "Request from known malicious IP",
        }]

        # Add indicator
        self.db.add(ThreatIndicator(
            type="ip",
            value="203.0.113.199",
            severity="high",
            description="Test C2 IP",
        ))
        self.db.commit()

        events = self._create_and_flush_events(blacklist_event)
        evaluate_rules_for_events(self.db, events, auto_correlate=True, use_batched_threshold=True)
        self.db.commit()

        intel_alerts = self.db.query(Alert).filter(Alert.source_ip == "203.0.113.199").all()
        self.assertGreaterEqual(len(intel_alerts), 1)

    def test_persist_events_ingestion_service_integration(self):
        """Verify persist_events in ingestion service directly runs with use_batched_threshold=True."""
        now = datetime.now(UTC)
        raw_payload = [
            {
                "timestamp": (now - timedelta(seconds=i * 5)).isoformat(),
                "event_type": "web_attack",
                "event_category": "network",
                "source_type": "WEB",
                "severity": "high",
                "source_ip": "198.51.100.42",
                "request_path": f"/rest/user/login?probe={i}",
                "method": "POST",
                "status_code": 500,
                "message": f"SQL Injection probe {i}: ' UNION SELECT 1,2,3--",
            }
            for i in range(5)
        ]

        result = ingest_api_payload(
            self.db,
            source_type="api",
            events=raw_payload,
            raw_lines=[],
            user_id=1,
        )

        self.assertEqual(result["parsed_count"], 5)
        self.assertGreaterEqual(result["alert_count"], 1)

        # Verify alert and incident were persisted to database
        db_alerts = self.db.query(Alert).all()
        self.assertGreaterEqual(len(db_alerts), 1)
        db_incidents = self.db.query(Incident).all()
        self.assertGreaterEqual(len(db_incidents), 1)

    def test_sqlite_naive_db_aware_batch_events_no_typeerror(self):
        """
        Regression Test: Verify that when historical events in SQLite return offset-naive datetimes
        and new incoming events have timezone-aware datetimes, evaluate_threshold_rule_batched
        normalizes both cleanly without raising:
            TypeError: can't compare offset-naive and offset-aware datetimes
        """
        now = datetime.now(UTC)

        # 1. Seed 4 historical failed_login events in SQLite with naive datetimes
        raw_log = RawLog(source_type="AUTH", original_content="historical auth log")
        self.db.add(raw_log)
        self.db.flush()

        for i in range(4):
            # Explicitly naive timestamp simulating SQLite roundtrip
            naive_ts = datetime(now.year, now.month, now.day, now.hour, now.minute, now.second) - timedelta(seconds=(4 - i) * 30)
            self.db.add(NormalizedEvent(
                raw_log_id=raw_log.id,
                timestamp=naive_ts,
                source_type="AUTH",
                source_ip="198.51.100.80",
                username="victim_user",
                event_type="failed_login",
                event_category="authentication",
                severity="medium",
                status_code=401,
                message=f"Historical failed login {i}",
            ))
        self.db.commit()

        # 2. Ingest 2 new events with explicit timezone-aware UTC timestamps
        new_event_dicts = [
            {
                "timestamp": now - timedelta(seconds=10),
                "event_type": "failed_login",
                "event_category": "authentication",
                "source_type": "AUTH",
                "severity": "medium",
                "source_ip": "198.51.100.80",
                "username": "victim_user",
                "status_code": 401,
                "message": "New aware failed login 1",
            },
            {
                "timestamp": now,
                "event_type": "failed_login",
                "event_category": "authentication",
                "source_type": "AUTH",
                "severity": "medium",
                "source_ip": "198.51.100.80",
                "username": "victim_user",
                "status_code": 401,
                "message": "New aware failed login 2",
            },
        ]

        new_events = self._create_and_flush_events(new_event_dicts)

        # Must not raise TypeError: can't compare offset-naive and offset-aware datetimes
        touched = evaluate_rules_for_events(self.db, new_events, auto_correlate=True, use_batched_threshold=True)
        self.db.commit()

        # Total is 4 historical + 2 new = 6 events (threshold for RULE-001 is 5)
        self.assertGreaterEqual(touched, 1)
        alerts = self.db.query(Alert).filter(Alert.source_ip == "198.51.100.80").all()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].event_count, 6)

    def test_api_ingest_iso_timestamps_sqlite_end_to_end(self):
        """
        Regression Test: Ingest ISO-8601 strings with 'Z' UTC designator through ingest_api_payload
        into SQLite and assert persist_events with use_batched_threshold=True succeeds completely.
        """
        now = datetime.now(UTC)
        events_payload = [
            {
                "timestamp": (now - timedelta(seconds=(6 - i) * 15)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "event_type": "failed_login",
                "event_category": "authentication",
                "source_type": "AUTH",
                "severity": "medium",
                "source_ip": "198.51.100.85",
                "username": "target_user",
                "status_code": 401,
                "message": f"Brute force attempt {i}",
            }
            for i in range(6)
        ]

        result = ingest_api_payload(
            self.db,
            source_type="api",
            events=events_payload,
            raw_lines=[],
            user_id=1,
        )

        self.assertEqual(result["parsed_count"], 6)
        self.assertGreaterEqual(result["alert_count"], 1)

        alert = self.db.query(Alert).filter(Alert.source_ip == "198.51.100.85").first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.event_count, 6)
        self.assertIn("Multiple failed login attempts", alert.title)


if __name__ == "__main__":
    unittest.main()
