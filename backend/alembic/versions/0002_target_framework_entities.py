"""target framework entities

Revision ID: 0002_target_framework_entities
Revises: 0001_initial
Create Date: 2026-10-04
"""

from alembic import op
import sqlalchemy as sa


revision = "0002_target_framework_entities"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Incidents
    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_number", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False, server_default="medium"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("affected_user", sa.String(length=128), nullable=True),
        sa.Column("correlation_key", sa.String(length=128), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("alert_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    for col in ["incident_number", "title", "severity", "status", "source_ip", "affected_user", "correlation_key", "first_seen", "last_seen"]:
        op.create_index(f"ix_incidents_{col}", "incidents", [col], unique=(col == "incident_number"))

    # 2. Incident Alerts join table
    op.create_table(
        "incident_alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False),
        sa.UniqueConstraint("incident_id", "alert_id", name="uq_incident_alert"),
    )
    op.create_index("ix_incident_alerts_incident_id", "incident_alerts", ["incident_id"])
    op.create_index("ix_incident_alerts_alert_id", "incident_alerts", ["alert_id"])

    # 3. Cases
    op.create_table(
        "cases",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("case_number", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="OPEN"),
        sa.Column("priority", sa.String(length=32), nullable=False, server_default="MEDIUM"),
        sa.Column("assigned_analyst_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("resolution_summary", sa.Text(), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    for col in ["case_number", "title", "status", "priority", "assigned_analyst_id", "incident_id", "alert_id"]:
        op.create_index(f"ix_cases_{col}", "cases", [col], unique=(col == "case_number"))

    # 4. Evidence
    op.create_table(
        "evidence",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True),
        sa.Column("evidence_type", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("data_json", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_evidence_alert_id", "evidence", ["alert_id"])
    op.create_index("ix_evidence_incident_id", "evidence", ["incident_id"])
    op.create_index("ix_evidence_evidence_type", "evidence", ["evidence_type"])

    # 5. Detection Quality
    op.create_table(
        "detection_quality",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True),
        sa.Column("overall_quality", sa.Float(), nullable=False),
        sa.Column("evidence_completeness", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("correlation_strength", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("rule_confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("behavioral_confidence", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("context_confidence", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("factors_json", sa.JSON(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_detection_quality_alert_id", "detection_quality", ["alert_id"])
    op.create_index("ix_detection_quality_incident_id", "detection_quality", ["incident_id"])
    op.create_index("ix_detection_quality_overall_quality", "detection_quality", ["overall_quality"])

    # 6. Risk Assessments
    op.create_table(
        "risk_assessments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("risk_level", sa.String(length=32), nullable=False, server_default="MEDIUM"),
        sa.Column("impact_score", sa.Float(), nullable=False, server_default="5.0"),
        sa.Column("likelihood_score", sa.Float(), nullable=False, server_default="5.0"),
        sa.Column("asset_criticality", sa.String(length=32), nullable=False, server_default="MEDIUM"),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("factors_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_risk_assessments_alert_id", "risk_assessments", ["alert_id"])
    op.create_index("ix_risk_assessments_incident_id", "risk_assessments", ["incident_id"])
    op.create_index("ix_risk_assessments_risk_score", "risk_assessments", ["risk_score"])
    op.create_index("ix_risk_assessments_risk_level", "risk_assessments", ["risk_level"])

    # 7. AI Analyses
    op.create_table(
        "ai_analyses",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True),
        sa.Column("model_name", sa.String(length=80), nullable=False),
        sa.Column("prompt_version", sa.String(length=32), nullable=False, server_default="v1.0"),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("suggested_classification", sa.String(length=32), nullable=False),
        sa.Column("suggested_severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.8"),
        sa.Column("supporting_evidence_json", sa.JSON(), nullable=False),
        sa.Column("uncertainty_notes", sa.Text(), nullable=True),
        sa.Column("ai_claim_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("supported_claim_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unsupported_claim_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("analyst_agreement", sa.String(length=32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_ai_analyses_alert_id", "ai_analyses", ["alert_id"])
    op.create_index("ix_ai_analyses_incident_id", "ai_analyses", ["incident_id"])
    op.create_index("ix_ai_analyses_analyst_agreement", "ai_analyses", ["analyst_agreement"])

    # 8. Analyst Feedback
    op.create_table(
        "analyst_feedback",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True),
        sa.Column("analyst_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("classification", sa.String(length=32), nullable=False),
        sa.Column("severity_override", sa.String(length=32), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("feedback_type", sa.String(length=64), nullable=False, server_default="triage"),
        sa.Column("rule_adjustment_suggested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("suggested_rule_changes_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_analyst_feedback_alert_id", "analyst_feedback", ["alert_id"])
    op.create_index("ix_analyst_feedback_incident_id", "analyst_feedback", ["incident_id"])
    op.create_index("ix_analyst_feedback_analyst_id", "analyst_feedback", ["analyst_id"])
    op.create_index("ix_analyst_feedback_classification", "analyst_feedback", ["classification"])

    # 9. Validation Tests
    op.create_table(
        "validation_tests",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("rule_id", sa.Integer(), sa.ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rule_version", sa.String(length=32), nullable=False, server_default="1.0"),
        sa.Column("test_name", sa.String(length=160), nullable=False),
        sa.Column("test_scenario_id", sa.String(length=80), nullable=False),
        sa.Column("expected_result", sa.Boolean(), nullable=False),
        sa.Column("observed_result", sa.Boolean(), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=False),
        sa.Column("execution_time_ms", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("details_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_validation_tests_rule_id", "validation_tests", ["rule_id"])
    op.create_index("ix_validation_tests_test_scenario_id", "validation_tests", ["test_scenario_id"])
    op.create_index("ix_validation_tests_passed", "validation_tests", ["passed"])

    # 10. Experiments
    op.create_table(
        "experiments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("mode", sa.String(length=32), nullable=False),
        sa.Column("dataset_version", sa.String(length=64), nullable=False, server_default="v1.0"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_experiments_name", "experiments", ["name"])
    op.create_index("ix_experiments_mode", "experiments", ["mode"])
    op.create_index("ix_experiments_status", "experiments", ["status"])

    # 11. Experiment Runs
    op.create_table(
        "experiment_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("experiment_id", sa.Integer(), sa.ForeignKey("experiments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("run_number", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("mode", sa.String(length=32), nullable=False),
        sa.Column("total_events", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_alerts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_incidents", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("execution_duration_seconds", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="COMPLETED"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_experiment_runs_experiment_id", "experiment_runs", ["experiment_id"])
    op.create_index("ix_experiment_runs_mode", "experiment_runs", ["mode"])
    op.create_index("ix_experiment_runs_status", "experiment_runs", ["status"])

    # 12. Experiment Metrics
    op.create_table(
        "experiment_metrics",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("experiment_run_id", sa.Integer(), sa.ForeignKey("experiment_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("metric_name", sa.String(length=80), nullable=False),
        sa.Column("metric_value", sa.Float(), nullable=False),
        sa.Column("details_json", sa.JSON(), nullable=True),
    )
    op.create_index("ix_experiment_metrics_experiment_run_id", "experiment_metrics", ["experiment_run_id"])
    op.create_index("ix_experiment_metrics_metric_name", "experiment_metrics", ["metric_name"])

    # 13. Audit Logs
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action", sa.String(length=80), nullable=False),
        sa.Column("resource_type", sa.String(length=80), nullable=False),
        sa.Column("resource_id", sa.String(length=80), nullable=True),
        sa.Column("details_json", sa.JSON(), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_resource_type", "audit_logs", ["resource_type"])
    op.create_index("ix_audit_logs_resource_id", "audit_logs", ["resource_id"])
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("experiment_metrics")
    op.drop_table("experiment_runs")
    op.drop_table("experiments")
    op.drop_table("validation_tests")
    op.drop_table("analyst_feedback")
    op.drop_table("ai_analyses")
    op.drop_table("risk_assessments")
    op.drop_table("detection_quality")
    op.drop_table("evidence")
    op.drop_table("cases")
    op.drop_table("incident_alerts")
    op.drop_table("incidents")
