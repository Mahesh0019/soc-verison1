"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-05-02
"""

from alembic import op
import sqlalchemy as sa


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(length=80), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_role", "users", ["role"], unique=False)

    op.create_table(
        "raw_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_type", sa.String(length=80), nullable=False),
        sa.Column("original_content", sa.Text(), nullable=False),
        sa.Column("file_name", sa.String(length=255), nullable=True),
        sa.Column("uploaded_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_raw_logs_source_type", "raw_logs", ["source_type"])

    op.create_table(
        "detection_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("conditions_json", sa.JSON(), nullable=False),
        sa.Column("time_window_minutes", sa.Integer(), nullable=False),
        sa.Column("threshold", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_detection_rules_name", "detection_rules", ["name"], unique=True)
    op.create_index("ix_detection_rules_enabled", "detection_rules", ["enabled"])

    op.create_table(
        "threat_indicators",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("type", "value", name="uq_indicator_type_value"),
    )
    op.create_index("ix_threat_indicators_type", "threat_indicators", ["type"])
    op.create_index("ix_threat_indicators_value", "threat_indicators", ["value"])

    op.create_table(
        "normalized_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("raw_log_id", sa.Integer(), sa.ForeignKey("raw_logs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("destination_ip", sa.String(length=64), nullable=True),
        sa.Column("username", sa.String(length=128), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("event_category", sa.String(length=80), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("request_path", sa.String(length=2048), nullable=True),
        sa.Column("http_method", sa.String(length=16), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("geo_country", sa.String(length=80), nullable=True),
        sa.Column("raw_log", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    for column in ["timestamp", "source_ip", "destination_ip", "username", "hostname", "event_type", "event_category", "severity", "status_code", "geo_country"]:
        op.create_index(f"ix_normalized_events_{column}", "normalized_events", [column])

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("rule_id", sa.Integer(), sa.ForeignKey("detection_rules.id", ondelete="SET NULL"), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("affected_user", sa.String(length=128), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    for column in ["rule_id", "severity", "status", "source_ip", "affected_user", "first_seen", "last_seen"]:
        op.create_index(f"ix_alerts_{column}", "alerts", [column])

    op.create_table(
        "alert_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_id", sa.Integer(), sa.ForeignKey("normalized_events.id", ondelete="CASCADE"), nullable=False),
        sa.UniqueConstraint("alert_id", "event_id", name="uq_alert_event"),
    )
    op.create_index("ix_alert_events_alert_id", "alert_events", ["alert_id"])
    op.create_index("ix_alert_events_event_id", "alert_events", ["event_id"])

    op.create_table(
        "alert_notes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_alert_notes_alert_id", "alert_notes", ["alert_id"])
    op.create_index("ix_alert_notes_user_id", "alert_notes", ["user_id"])


def downgrade() -> None:
    op.drop_table("alert_notes")
    op.drop_table("alert_events")
    op.drop_table("alerts")
    op.drop_table("normalized_events")
    op.drop_table("threat_indicators")
    op.drop_table("detection_rules")
    op.drop_table("raw_logs")
    op.drop_table("users")

