from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings


settings = get_settings()
db_url = settings.database_url
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+psycopg://", 1)
elif db_url.startswith("postgresql://") and not db_url.startswith("postgresql+"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

import logging
import time

logger = logging.getLogger("uvicorn.error")

connect_args = {}
if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    engine = create_engine(db_url, connect_args=connect_args)
else:
    connected = False
    last_err: Exception | None = None
    for attempt in range(1, 4):
        try:
            candidate_engine = create_engine(db_url, pool_pre_ping=True)
            with candidate_engine.connect() as conn:
                pass
            engine = candidate_engine
            connected = True
            logger.info("Connected successfully to PostgreSQL database.")
            break
        except Exception as exc:
            last_err = exc
            if attempt < 3:
                time.sleep(1.0)

    if not connected:
        if settings.environment.lower() == "production":
            logger.critical(
                "CRITICAL: PostgreSQL connection failed after 3 attempts in production (%s). Aborting fallback to ephemeral SQLite to prevent silent data loss.",
                last_err,
            )
            raise RuntimeError(f"Database connection failed in production: {last_err}") from last_err

        logger.warning(
            "PostgreSQL connection failed after 3 attempts (%s). Falling back to SQLite for non-production environment.",
            last_err,
        )
        db_url = "sqlite:///./mini_siem.db"
        connect_args = {"check_same_thread": False}
        engine = create_engine(db_url, connect_args=connect_args)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


