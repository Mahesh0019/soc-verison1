"""
tests/test_threat_hunting.py

Phase 9: Comprehensive Tests for Threat Hunting & Closed-Loop Detection Engineering.
Verifies:
- Hunt creation & listing
- Bounded parameterized execution & classification
- Detection gap creation & duplicate detection
- Candidate rule generation in status DRAFT
- Quality Gate validation (positive, negative, mutation, missing fields)
- Regression evaluation across historical benchmarks
- Lifecycle state transitions & validation prerequisites
- Immutable rule versioning
- RBAC authorization enforcement
- Cross-incident isolation
- Query bounds & malicious input sanitization
"""

import os
import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.base import Base
from app.models import (
    Alert,
    AlertEvent,
    CandidateRule,
    DetectionGap,
    DetectionRule,
    Incident,
    IncidentAlert,
    NormalizedEvent,
    RegressionEvaluationRecord,
    RuleVersionHistory,
    ThreatHunt,
)
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users
from app.services.threat_hunting_service import (
    build_detection_coverage_matrix,
    compute_hunt_quality_metrics,
    ensure_builtin_hunts,
    evaluate_regression_impact,
    execute_hunt_query,
    generate_candidate_rule,
    identify_detection_gap,
    sanitize_input,
    transition_rule_lifecycle,
    validate_candidate_rule,
)


class TestThreatHuntingLifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine("sqlite:///:memory:", echo=False)
        Base.metadata.create_all(bind=cls.engine)
        cls.Session = sessionmaker(bind=cls.engine)

    def setUp(self):
        self.db = self.Session()
        ensure_users(self.db)
        ensure_builtin_rules(self.db)
        ensure_indicators(self.db)
        ensure_builtin_hunts(self.db)

    def tearDown(self):
        self.db.rollback()
        # Clean transient data
        self.db.query(RegressionEvaluationRecord).delete()
        self.db.query(RuleVersionHistory).delete()
        self.db.query(DetectionGap).delete()
        self.db.query(ThreatHunt).delete()
        self.db.query(CandidateRule).delete()
        self.db.query(AlertEvent).delete()
        self.db.query(IncidentAlert).delete()
        self.db.query(Alert).delete()
        self.db.query(Incident).delete()
        self.db.query(NormalizedEvent).delete()
        self.db.commit()
        self.db.close()

    def test_01_hunt_creation_and_defaults(self):
        """Verifies ThreatHunt creation with required attributes and defaults."""
        hunt = ThreatHunt(
            hunt_id="HUNT-TEST-001",
            title="Suspicious Scheduled Task Creation",
            hypothesis="Adversaries establish persistence via scheduled tasks in unusual paths.",
            analyst="analyst_alice",
            data_sources_json=["SYSMON"],
            query_filter_json={"process": "schtasks.exe"},
            expected_behavior="Creation of scheduled tasks with administrative privileges.",
            result="INCONCLUSIVE",
            confidence=0.50,
            classification="FALSE_LEAD",
            status="OPEN",
        )
        self.db.add(hunt)
        self.db.commit()

        fetched = self.db.query(ThreatHunt).filter(ThreatHunt.hunt_id == "HUNT-TEST-001").first()
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.analyst, "analyst_alice")
        self.assertEqual(fetched.result, "INCONCLUSIVE")
        self.assertEqual(fetched.data_sources_json, ["SYSMON"])

    def test_02_hunt_execution_and_classification(self):
        """Tests query execution and classification: DETECTION_GAP vs FALSE_LEAD vs INSUFFICIENT_DATA."""
        hunt = self.db.query(ThreatHunt).filter(ThreatHunt.hunt_id == "HUNT-006").first()
        self.assertIsNotNone(hunt)

        # Add event matching temporary directory execution
        now = datetime.now(UTC)
        ev = NormalizedEvent(
            timestamp=now - timedelta(minutes=10),
            source_type="SYSMON",
            event_type="sysmon_process_create",
            event_category="endpoint",
            severity="high",
            hostname="PC-01",
            username="victim",
            process="evil.exe",
            command_line="C:\\Users\\victim\\AppData\\Local\\Temp\\evil.exe",
            message="Process created in temp",
        )
        self.db.add(ev)
        self.db.commit()

        res = execute_hunt_query(self.db, hunt, analyst_role="analyst")
        self.assertEqual(res["result"], "CONFIRMED")
        self.assertEqual(res["classification"], "DETECTION_GAP")
        self.assertGreaterEqual(res["matched_events_count"], 1)

    def test_03_detection_gap_creation(self):
        """Verifies formal DetectionGap creation and relationship mapping."""
        hunt = self.db.query(ThreatHunt).filter(ThreatHunt.hunt_id == "HUNT-006").first()
        self.assertIsNotNone(hunt)

        gap = identify_detection_gap(self.db, hunt, analyst_role="analyst")
        self.assertEqual(gap.gap_id, "GAP-HUNT-006")
        self.assertEqual(gap.affected_source, "SYSMON")
        self.assertEqual(gap.status, "IDENTIFIED")
        self.assertEqual(gap.hunt_id, hunt.id)

    def test_04_duplicate_candidate_and_gap_prevention(self):
        """Ensures calling identify_detection_gap and generate_candidate_rule twice does not produce duplicates."""
        hunt = self.db.query(ThreatHunt).filter(ThreatHunt.hunt_id == "HUNT-001").first()
        self.assertIsNotNone(hunt)

        gap1 = identify_detection_gap(self.db, hunt, analyst_role="analyst")
        gap2 = identify_detection_gap(self.db, hunt, analyst_role="analyst")
        self.assertEqual(gap1.id, gap2.id)

        cand1 = generate_candidate_rule(self.db, gap1, author="analyst_hunter")
        cand2 = generate_candidate_rule(self.db, gap1, author="analyst_hunter")
        self.assertEqual(cand1.id, cand2.id)
        self.assertEqual(self.db.query(CandidateRule).count(), 1)

    def test_05_candidate_rule_draft_status(self):
        """Verifies that generated candidate rules strictly start in status DRAFT."""
        gap = DetectionGap(
            gap_id="GAP-TEST-01",
            description="Test gap",
            affected_source="SYSMON",
            affected_behavior="Test behavior",
            severity="HIGH",
            missing_detection_capability="Missing rule",
            status="IDENTIFIED",
        )
        self.db.add(gap)
        self.db.commit()

        cand = generate_candidate_rule(self.db, gap, author="analyst_hunter")
        self.assertEqual(cand.status, "DRAFT")
        # Ensure active_rule_id is None while in DRAFT
        self.assertIsNone(cand.active_rule_id)

    def test_06_rule_quality_gate(self):
        """Verifies Quality Gate assertions on candidate rule."""
        gap = DetectionGap(
            gap_id="GAP-HUNT-006",
            description="Process in temp",
            affected_source="SYSMON",
            affected_behavior="Process execution in temp",
            missing_detection_capability="Inspects temp dirs",
            status="IDENTIFIED",
        )
        self.db.add(gap)
        self.db.commit()

        cand = generate_candidate_rule(self.db, gap, author="analyst_hunter")
        res = validate_candidate_rule(cand, self.db)

        self.assertTrue(res["passed"])
        self.assertGreaterEqual(res["precision"], 0.90)
        self.assertGreaterEqual(res["recall"], 0.90)
        self.assertLessEqual(res["fpr"], 0.05)
        self.assertTrue(res["quality_gate_checks"]["positive_attack_cases_pass"])
        self.assertTrue(res["quality_gate_checks"]["negative_benign_cases_pass"])
        self.assertTrue(res["quality_gate_checks"]["missing_field_graceful_pass"])

    def test_07_regression_evaluation(self):
        """Verifies historical benchmark regression evaluation before activation."""
        gap = DetectionGap(
            gap_id="GAP-HUNT-006",
            description="Temp exec",
            affected_source="SYSMON",
            affected_behavior="Process in temp",
            missing_detection_capability="Inspects temp dirs",
            status="IDENTIFIED",
        )
        self.db.add(gap)
        self.db.commit()

        cand = generate_candidate_rule(self.db, gap, author="analyst_hunter")
        validate_candidate_rule(cand, self.db)

        rec = evaluate_regression_impact(cand, self.db)
        self.assertEqual(rec.status, "PASSED")
        self.assertLessEqual(rec.fp_delta, 1)
        self.assertGreaterEqual(rec.f1_delta, 0.0)
        self.assertIn("Dataset V2", rec.target_datasets_json)
        self.assertIn("Sysmon V1", rec.target_datasets_json)

    def test_08_lifecycle_state_machine_and_promotion(self):
        """Tests full lifecycle promotion DRAFT -> TESTING -> VALIDATING -> ACTIVE and deprecation."""
        gap = DetectionGap(
            gap_id="GAP-HUNT-006",
            description="Temp exec",
            affected_source="SYSMON",
            affected_behavior="Process in temp",
            missing_detection_capability="Inspects temp dirs",
            status="IDENTIFIED",
        )
        self.db.add(gap)
        self.db.commit()

        cand = generate_candidate_rule(self.db, gap, author="analyst_hunter")

        # Invalid jump DRAFT -> ACTIVE must fail
        with self.assertRaises(ValueError):
            transition_rule_lifecycle(self.db, cand, "ACTIVE", "Illegal jump", author="analyst_lead")

        # Valid transitions
        cand = transition_rule_lifecycle(self.db, cand, "TESTING", "Promoting to testing", author="analyst_lead")
        self.assertEqual(cand.status, "TESTING")

        cand = transition_rule_lifecycle(self.db, cand, "VALIDATING", "Beginning automated validation", author="analyst_lead")
        self.assertEqual(cand.status, "VALIDATING")

        # Validation gate
        validate_candidate_rule(cand, self.db)
        evaluate_regression_impact(cand, self.db)

        # Promotion to ACTIVE
        cand = transition_rule_lifecycle(self.db, cand, "ACTIVE", "Passed quality gates and regression checks", author="analyst_lead")
        self.assertEqual(cand.status, "ACTIVE")
        self.assertIsNotNone(cand.active_rule_id)

        # Verify active rule in production engine
        active_prod_rule = self.db.query(DetectionRule).filter(DetectionRule.id == cand.active_rule_id).first()
        self.assertIsNotNone(active_prod_rule)
        self.assertTrue(active_prod_rule.enabled)
        self.assertEqual(active_prod_rule.status, "ACTIVE")

        # Deprecation
        cand = transition_rule_lifecycle(self.db, cand, "DEPRECATED", "Superseded by v2", author="analyst_lead")
        self.assertEqual(cand.status, "DEPRECATED")
        self.assertFalse(active_prod_rule.enabled)

    def test_09_rule_version_history_audit(self):
        """Verifies immutable version auditing."""
        gap = DetectionGap(
            gap_id="GAP-HUNT-006",
            description="Temp exec",
            affected_source="SYSMON",
            affected_behavior="Process in temp",
            missing_detection_capability="Inspects temp dirs",
            status="IDENTIFIED",
        )
        self.db.add(gap)
        self.db.commit()

        cand = generate_candidate_rule(self.db, gap, author="analyst_hunter")
        transition_rule_lifecycle(self.db, cand, "TESTING", "Test phase", author="lead_1")
        transition_rule_lifecycle(self.db, cand, "VALIDATING", "Validation phase", author="lead_2")

        histories = self.db.query(RuleVersionHistory).filter(RuleVersionHistory.candidate_rule_id == cand.id).all()
        # DRAFT, TESTING, VALIDATING = 3 history entries
        self.assertEqual(len(histories), 3)
        self.assertEqual(histories[0].status, "DRAFT")
        self.assertEqual(histories[1].status, "TESTING")
        self.assertEqual(histories[2].status, "VALIDATING")

    def test_10_rbac_authorization(self):
        """Verifies non-authorized roles are rejected from executing hunts or creating gaps."""
        hunt = ThreatHunt(
            hunt_id="HUNT-RBAC-01",
            title="RBAC Hunt",
            hypothesis="Testing RBAC",
            analyst="viewer",
            expected_behavior="Expected",
        )
        self.db.add(hunt)
        self.db.commit()

        with self.assertRaises(PermissionError):
            execute_hunt_query(self.db, hunt, analyst_role="guest")

        with self.assertRaises(PermissionError):
            identify_detection_gap(self.db, hunt, analyst_role="viewer")

    def test_11_cross_incident_isolation(self):
        """Verifies cross-incident query filtering prevents data leakage."""
        now = datetime.now(UTC)
        ev1 = NormalizedEvent(
            timestamp=now - timedelta(minutes=5),
            source_type="SYSMON",
            event_type="sysmon_process_create",
            event_category="endpoint",
            severity="medium",
            process="test1.exe",
            message="Event 1 for Incident A",
        )
        ev2 = NormalizedEvent(
            timestamp=now - timedelta(minutes=4),
            source_type="SYSMON",
            event_type="sysmon_process_create",
            event_category="endpoint",
            severity="medium",
            process="test2.exe",
            message="Event 2 for Incident B",
        )
        self.db.add_all([ev1, ev2])
        self.db.flush()

        # Alert and Incident for ev1
        al1 = Alert(
            title="Alert 1",
            description="Alert 1 description",
            severity="high",
            status="open",
            event_count=1,
            first_seen=now,
            last_seen=now,
        )
        self.db.add(al1)
        self.db.flush()
        self.db.add(AlertEvent(alert_id=al1.id, event_id=ev1.id))

        inc1 = Incident(
            incident_number="INC-001",
            title="Incident 1",
            description="Inc 1",
            first_seen=now,
            last_seen=now,
        )
        self.db.add(inc1)
        self.db.flush()
        self.db.add(IncidentAlert(incident_id=inc1.id, alert_id=al1.id))
        self.db.commit()

        hunt = ThreatHunt(
            hunt_id="HUNT-ISO-01",
            title="Isolated Hunt",
            hypothesis="Testing incident isolation",
            analyst="analyst_hunter",
            expected_behavior="Expected",
        )
        self.db.add(hunt)
        self.db.commit()

        # Query restricted to incident 1
        res = execute_hunt_query(
            self.db,
            hunt,
            override_filters={"incident_id": inc1.id},
            analyst_role="analyst",
        )
        self.assertEqual(res["matched_events_count"], 1)
        self.assertIn(ev1.id, res["matched_event_ids"])
        self.assertNotIn(ev2.id, res["matched_event_ids"])

    def test_12_query_bounds_and_sanitization(self):
        """Verifies row limits are capped and input sanitization strips dangerous characters."""
        self.assertEqual(sanitize_input("admin' OR 1=1;--"), "admin' OR 1=1")
        self.assertEqual(sanitize_input("proc.exe/*comment*/"), "proc.exe")

        # Test bounding
        now = datetime.now(UTC)
        events = [
            NormalizedEvent(
                timestamp=now - timedelta(seconds=i),
                source_type="SYSMON",
                event_type="sysmon_process_create",
                event_category="endpoint",
                severity="low",
                process="batch.exe",
                message=f"Event {i}",
            )
            for i in range(250)
        ]
        self.db.add_all(events)
        self.db.commit()

        hunt = ThreatHunt(
            hunt_id="HUNT-BOUNDS-01",
            title="Bounds Hunt",
            hypothesis="Testing row limits",
            analyst="analyst_hunter",
            query_filter_json={"limit": 500},  # Requested 500, but max is 200
            expected_behavior="Expected",
        )
        self.db.add(hunt)
        self.db.commit()

        res = execute_hunt_query(self.db, hunt, analyst_role="analyst")
        # Should be capped at MAX_QUERY_LIMIT = 200
        self.assertEqual(res["matched_events_count"], 200)

    def test_13_coverage_matrix_and_hunt_metrics(self):
        """Verifies coverage matrix computation and lifecycle quality metrics calculation."""
        cov = build_detection_coverage_matrix(self.db)
        self.assertGreater(cov["total_behaviors_evaluated"], 0)
        self.assertGreater(cov["full_coverage_count"], 0)

        met = compute_hunt_quality_metrics(self.db)
        self.assertIn("hunt_precision", met)
        self.assertIn("detection_gap_yield", met)
        self.assertIn("candidate_acceptance_rate", met)
        self.assertIn("candidate_regression_failure_rate", met)
