"""
backend/app/database/schema_sync.py

Self-healing schema synchronizer:
Ensures all tables and missing columns from SQLAlchemy models
are automatically synchronized with the target database on startup.
Guarantees compatibility across database migrations without downtime or crash loops.
"""

from __future__ import annotations

import logging
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

from app.database.base import Base

logger = logging.getLogger("uvicorn.error")


def sync_db_schema(engine: Engine) -> None:
    """
    1. Runs Base.metadata.create_all(bind=engine) to create any missing tables.
    2. Inspects existing tables and adds any missing columns defined in the models.
       Uses autocommit isolation and per-statement execution so Postgres never
       enters an aborted transaction state.
    """
    # 1. Create missing tables
    Base.metadata.create_all(bind=engine)

    # 2. Add missing columns to existing tables
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    is_postgres = "postgres" in engine.dialect.name.lower()

    # Fast-path for critical detection_rules columns in PostgreSQL
    if is_postgres:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            critical_ddls = [
                "ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS rule_id VARCHAR(32)",
                "ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS category VARCHAR(64) DEFAULT 'web_attack'",
                "ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS version VARCHAR(32) DEFAULT '1.0'",
                "ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS status VARCHAR(32) DEFAULT 'ACTIVE'",
                "ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS source VARCHAR(64) DEFAULT 'builtin'",
                "ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS owner VARCHAR(64) DEFAULT 'secops-team'",
                "ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(32) DEFAULT 'NOT_MAPPED'",
                "ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS confidence FLOAT DEFAULT 0.80",
                "ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS false_positive_notes TEXT",
                "ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS expected_data_source VARCHAR(64) DEFAULT 'web_telemetry'",
                "ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS test_cases_json JSON",
            ]
            for ddl in critical_ddls:
                try:
                    conn.execute(text(ddl))
                except Exception:
                    pass

    # Use AUTOCOMMIT so each DDL statement executes immediately without a shared transaction block
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        for table_name, table in Base.metadata.tables.items():
            if table_name not in existing_tables:
                continue

            try:
                current_cols = {c["name"] for c in inspect(conn).get_columns(table_name)}
            except Exception as e:
                logger.warning("Could not inspect columns for table %s: %s", table_name, e)
                continue

            for col in table.columns:
                if col.name not in current_cols:
                    try:
                        col_type = col.type.compile(engine.dialect)
                        if is_postgres:
                            ddl = f"ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS {col.name} {col_type}"
                        else:
                            ddl = f"ALTER TABLE {table_name} ADD COLUMN {col.name} {col_type}"

                        conn.execute(text(ddl))
                        logger.info("Schema sync: added column '%s' to '%s'", col.name, table_name)
                    except Exception as e:
                        logger.warning("Note on column '%s' for '%s': %s", col.name, table_name, e)

        # Controlled semantic backfill for legacy rows that have NULL in newly added columns
        backfill_statements = [
            "UPDATE normalized_events SET source_type = 'WEB' WHERE source_type IS NULL AND (request_path IS NOT NULL OR http_method IS NOT NULL OR user_agent IS NOT NULL)",
            "UPDATE normalized_events SET source_type = 'AUTH' WHERE source_type IS NULL AND event_category = 'authentication'",
            "UPDATE normalized_events SET source_type = 'FIREWALL' WHERE source_type IS NULL AND event_category = 'firewall'",
            "UPDATE normalized_events SET source_type = 'ZEEK' WHERE source_type IS NULL AND (dns_query IS NOT NULL OR connection_state IS NOT NULL OR protocol IS NOT NULL)",
            "UPDATE normalized_events SET source_type = 'SYSMON' WHERE source_type IS NULL AND (process IS NOT NULL OR image_path IS NOT NULL OR command_line IS NOT NULL)",
            "UPDATE normalized_events SET source_type = 'OTHER' WHERE source_type IS NULL",
            "UPDATE detection_rules SET source = 'BUILTIN' WHERE source IS NULL",
            "UPDATE detection_rules SET category = 'web_attack' WHERE category IS NULL",
            "UPDATE detection_rules SET status = 'ACTIVE' WHERE status IS NULL",
            "UPDATE detection_rules SET owner = 'secops-team' WHERE owner IS NULL",
            "UPDATE detection_rules SET mitre_technique = 'NOT_MAPPED' WHERE mitre_technique IS NULL",
            "UPDATE detection_rules SET expected_data_source = 'web_telemetry' WHERE expected_data_source IS NULL",
        ]
        for stmt in backfill_statements:
            try:
                conn.execute(text(stmt))
            except Exception as e:
                logger.debug("Backfill statement note: %s", e)
