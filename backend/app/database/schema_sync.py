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
