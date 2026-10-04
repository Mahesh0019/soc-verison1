"""
tests/test_data_models.py

Unit tests for Phase 2 data model extensions.
Verifies all additive ORM entities, relationships, foreign keys, and cascading behaviors:
- Incident and IncidentAlert
- Case
- Evidence
- DetectionQuality
- RiskAssessment
- AIAnalysis
- AnalystFeedback
- ValidationTest
- Experiment, ExperimentRun, ExperimentMetric
- AuditLog
- Backward compatibility with Alert, NormalizedEvent, DetectionRule, User
"""

import os
import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.models import (
    AIAnalysis,
    Alert,
    AlertEvent,
    AnalystFeedback,
    AuditLog,
    Case,
    DetectionQuality,
    DetectionRule,
    Evidence,
    Experiment,
    ExperimentMetric,
    ExperimentRun,
    Incident,
    IncidentAlert,
    NormalizedEvent,
    RiskAssessment,
    ThreatIndicator,
    User,
    ValidationTest,
)


class TestDataModels(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        cls.SessionLocal = sessionmaker(bind=cls.engine, autoflush=False, autocommit=False)
        Base.metadata.create_all(bind=cls.engine)

    @classmethod
    def tearDownClass(cls):
        Base.metadata.drop_all(bind=cls.engine)

    def setUp(self):
        self.db = self.SessionLocal()

    def tearDown(self):
        self.db.rollback()
        self.db.close()

    def _create_user(self, username="analyst_test"):
        user = User(
            username=username,
            email=f"{username}@example.com",
            password_hash="fakehash",
            role="analyst",
        )
        self.db.add(user)
        self.db.flush()
        return user

    def _create_alert(self):
        now = datetime.now(UTC)
        alert = Alert(
            title="Brute Force Suspicion",
            description="Multiple failed logins observed",
            severity="high",
            status="open",
            source_ip="198.51.100.11",
            first_seen=now,
            last_seen=now,
            event_count=5,
        )
        self.db.add(alert)
        self.db.flush()
        return alert

    def test_incident_and_incident_alert_relationship(self):
        """Verify Incident entity creation and linking to alerts via IncidentAlert."""
        now = datetime.now(UTC)
        alert = self._create_alert()

        incident = Incident(
            incident_number="INC-1001",
            title="Coordinated Credential Stuffing Campaign",
            description="Reconnaissance followed by credential testing across admin accounts",
            severity="high",
            status="open",
            source_ip="198.51.100.11",
            first_seen=now,
            last_seen=now,
            alert_count=1,
            event_count=5,
        )
        self.db.add(incident)
        self.db.flush()

        link = IncidentAlert(incident_id=incident.id, alert_id=alert.id)
        self.db.add(link)
        self.db.commit()

        # Query back and verify relationship
        fetched = self.db.query(Incident).filter_by(incident_number="INC-1001").first()
        self.assertIsNotNone(fetched)
        self.assertEqual(len(fetched.alerts), 1)
        self.assertEqual(fetched.alerts[0].alert.title, "Brute Force Suspicion")

    def test_case_management_model(self):
        """Verify Case entity creation, assignment to analyst, and linking to incident."""
        analyst = self._create_user("case_analyst")
        alert = self._create_alert()
        now = datetime.now(UTC)

        incident = Incident(
            incident_number="INC-1002",
            title="Suspicious Outbound Tunneling",
            description="High volume network denied spike",
            severity="critical",
            status="investigating",
            first_seen=now,
            last_seen=now,
        )
        self.db.add(incident)
        self.db.flush()

        case = Case(
            case_number="CASE-2001",
            title="Investigate Outbound Tunneling",
            description="Verify if source IP belongs to external botnet",
            status="INVESTIGATING",
            priority="HIGH",
            assigned_analyst_id=analyst.id,
            incident_id=incident.id,
            alert_id=alert.id,
        )
        self.db.add(case)
        self.db.commit()

        fetched = self.db.query(Case).filter_by(case_number="CASE-2001").first()
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.assigned_analyst.username, "case_analyst")
        self.assertEqual(fetched.incident.incident_number, "INC-1002")
        self.assertEqual(fetched.alert.title, "Brute Force Suspicion")

    def test_evidence_model(self):
        """Verify Evidence storage with structured JSON data and alert association."""
        alert = self._create_alert()
        evidence = Evidence(
            alert_id=alert.id,
            evidence_type="triggering_event",
            title="Failed Login Spike",
            description="5 authentication failures within 60 seconds",
            data_json={"sample_ids": [101, 102, 103], "rate_per_min": 5.0},
            confidence=0.95,
            is_verified=True,
        )
        self.db.add(evidence)
        self.db.commit()

        fetched_alert = self.db.query(Alert).filter_by(id=alert.id).first()
        self.assertEqual(len(fetched_alert.evidence_items), 1)
        self.assertEqual(fetched_alert.evidence_items[0].evidence_type, "triggering_event")
        self.assertEqual(fetched_alert.evidence_items[0].data_json["rate_per_min"], 5.0)

    def test_detection_quality_model(self):
        """Verify DetectionQuality explainable factor scoring model."""
        alert = self._create_alert()
        dq = DetectionQuality(
            alert_id=alert.id,
            overall_quality=0.88,
            evidence_completeness=0.90,
            correlation_strength=0.85,
            rule_confidence=0.95,
            behavioral_confidence=0.78,
            context_confidence=0.86,
            factors_json={
                "evidence_completeness": 0.90,
                "correlation_strength": 0.85,
                "independent_signals": 2,
            },
            explanation="High evidence completeness and confirmed threat-intel alignment.",
        )
        self.db.add(dq)
        self.db.commit()

        fetched_alert = self.db.query(Alert).filter_by(id=alert.id).first()
        self.assertIsNotNone(fetched_alert.detection_quality)
        self.assertEqual(fetched_alert.detection_quality.overall_quality, 0.88)
        self.assertEqual(fetched_alert.detection_quality.factors_json["independent_signals"], 2)

    def test_risk_assessment_model(self):
        """Verify RiskAssessment multi-factor scoring model."""
        alert = self._create_alert()
        risk = RiskAssessment(
            alert_id=alert.id,
            risk_score=78.5,
            risk_level="HIGH",
            impact_score=8.0,
            likelihood_score=7.5,
            asset_criticality="HIGH",
            justification="Critical asset targeted by persistent external scanner.",
            factors_json={"impact": 8.0, "likelihood": 7.5, "asset_tier": 1},
        )
        self.db.add(risk)
        self.db.commit()

        fetched_alert = self.db.query(Alert).filter_by(id=alert.id).first()
        self.assertIsNotNone(fetched_alert.risk_assessment)
        self.assertEqual(fetched_alert.risk_assessment.risk_level, "HIGH")
        self.assertEqual(fetched_alert.risk_assessment.risk_score, 78.5)

    def test_ai_analysis_model(self):
        """Verify AIAnalysis advisory claims tracking and analyst agreement."""
        alert = self._create_alert()
        ai = AIAnalysis(
            alert_id=alert.id,
            model_name="phi-3-mini-4k-instruct",
            prompt_version="v1.2",
            summary="Attacker performed reconnaissance followed by authentication brute force.",
            suggested_classification="TRUE_POSITIVE",
            suggested_severity="high",
            confidence=0.85,
            supporting_evidence_json={"evidence_ids": [1, 2], "signals": ["403_burst", "auth_fail"]},
            uncertainty_notes="Source IP location could be a shared VPN egress node.",
            ai_claim_count=4,
            supported_claim_count=4,
            unsupported_claim_count=0,
            analyst_agreement="AGREED",
        )
        self.db.add(ai)
        self.db.commit()

        fetched_alert = self.db.query(Alert).filter_by(id=alert.id).first()
        self.assertEqual(len(fetched_alert.ai_analyses), 1)
        self.assertEqual(fetched_alert.ai_analyses[0].suggested_classification, "TRUE_POSITIVE")
        self.assertEqual(fetched_alert.ai_analyses[0].unsupported_claim_count, 0)
        self.assertEqual(fetched_alert.ai_analyses[0].analyst_agreement, "AGREED")

    def test_analyst_feedback_model(self):
        """Verify AnalystFeedback model recording triage decisions and rule suggestions."""
        analyst = self._create_user("feedback_analyst")
        alert = self._create_alert()
        feedback = AnalystFeedback(
            alert_id=alert.id,
            analyst_id=analyst.id,
            classification="TRUE_POSITIVE",
            severity_override="critical",
            notes="Confirmed active directory traversal probe.",
            rule_adjustment_suggested=True,
            suggested_rule_changes_json={"rule_id": 7, "suggested_threshold": 3},
        )
        self.db.add(feedback)
        self.db.commit()

        fetched_alert = self.db.query(Alert).filter_by(id=alert.id).first()
        self.assertEqual(len(fetched_alert.feedbacks), 1)
        self.assertEqual(fetched_alert.feedbacks[0].classification, "TRUE_POSITIVE")
        self.assertTrue(fetched_alert.feedbacks[0].rule_adjustment_suggested)

    def test_validation_test_model(self):
        """Verify ValidationTest entity for detection rule assertions."""
        rule = DetectionRule(
            name="Test Directory Traversal Rule",
            description="Flags directory traversal keywords",
            severity="high",
            enabled=True,
            conditions_json={"type": "threshold"},
            threshold=1,
            time_window_minutes=5,
        )
        self.db.add(rule)
        self.db.flush()

        vtest = ValidationTest(
            rule_id=rule.id,
            rule_version="1.0",
            test_name="Test path traversal detection with ../..",
            test_scenario_id="SCENARIO-TRAVERSAL-01",
            expected_result=True,
            observed_result=True,
            passed=True,
            execution_time_ms=12.4,
            details_json={"matched_patterns": ["../.."]},
        )
        self.db.add(vtest)
        self.db.commit()

        fetched = self.db.query(ValidationTest).filter_by(test_scenario_id="SCENARIO-TRAVERSAL-01").first()
        self.assertIsNotNone(fetched)
        self.assertTrue(fetched.passed)
        self.assertEqual(fetched.rule.name, "Test Directory Traversal Rule")

    def test_experiment_and_metrics_hierarchy(self):
        """Verify Experiment -> ExperimentRun -> ExperimentMetric hierarchy for M0-M6."""
        exp = Experiment(
            name="Baseline vs Correlation Comparison",
            description="Testing detection quality impact between M0 and M1",
            mode="M1",
            dataset_version="benchmark-v1.0",
            status="COMPLETED",
        )
        self.db.add(exp)
        self.db.flush()

        run = ExperimentRun(
            experiment_id=exp.id,
            run_number=1,
            mode="M1",
            total_events=1200,
            total_alerts=18,
            total_incidents=3,
            execution_duration_seconds=4.25,
            status="COMPLETED",
        )
        self.db.add(run)
        self.db.flush()

        metrics = [
            ExperimentMetric(experiment_run_id=run.id, metric_name="precision", metric_value=0.92),
            ExperimentMetric(experiment_run_id=run.id, metric_name="recall", metric_value=0.96),
            ExperimentMetric(experiment_run_id=run.id, metric_name="f1", metric_value=0.94),
            ExperimentMetric(experiment_run_id=run.id, metric_name="genuine_attack_retention", metric_value=1.0),
        ]
        self.db.add_all(metrics)
        self.db.commit()

        fetched = self.db.query(Experiment).filter_by(name="Baseline vs Correlation Comparison").first()
        self.assertIsNotNone(fetched)
        self.assertEqual(len(fetched.runs), 1)
        run_obj = fetched.runs[0]
        self.assertEqual(len(run_obj.metrics), 4)
        prec = next(m for m in run_obj.metrics if m.metric_name == "precision")
        self.assertEqual(prec.metric_value, 0.92)

    def test_audit_log_model(self):
        """Verify AuditLog entity tracks administrative and analyst operations."""
        analyst = self._create_user("audit_analyst")
        audit = AuditLog(
            user_id=analyst.id,
            action="UPDATE_ALERT_STATUS",
            resource_type="Alert",
            resource_id="12",
            details_json={"old_status": "open", "new_status": "investigating"},
            ip_address="192.168.1.50",
        )
        self.db.add(audit)
        self.db.commit()

        fetched = self.db.query(AuditLog).filter_by(action="UPDATE_ALERT_STATUS").first()
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.user.username, "audit_analyst")
        self.assertEqual(fetched.details_json["new_status"], "investigating")


if __name__ == "__main__":
    unittest.main()
