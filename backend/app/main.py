import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.api import api_router
from app.config import get_settings
from app.database.base import Base
from app.database.session import engine
from app.models import *  # noqa: F403
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users


settings = get_settings()


logger = logging.getLogger("uvicorn.error")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    # ── Startup ──────────────────────────────────────────────────────────────
    try:
        logger.info("Initializing and synchronizing database schema...")
        from app.database.schema_sync import sync_db_schema

        sync_db_schema(engine)
        logger.info("Database schema synchronized successfully.")
    except Exception as exc:
        logger.exception("Error synchronizing database schema on startup: %s", exc)

    try:
        from app.database.session import SessionLocal

        db = SessionLocal()
        try:
            logger.info("Ensuring builtin users, rules, and indicators...")
            ensure_users(db)
            ensure_builtin_rules(db)
            ensure_indicators(db)
            logger.info("Database initial seeding complete.")
        finally:
            db.close()
    except Exception as exc:
        logger.exception("Warning during database seed initialization: %s", exc)

    # Start the Juice Shop connector background task only when explicitly enabled.
    # Default is False so existing local/CI behaviour is unchanged.
    if settings.enable_juice_shop_connector:
        try:
            from app.services.juice_shop_background import start_background_collector

            start_background_collector()
            logger.info("Juice Shop connector background task started.")
        except Exception as exc:
            logger.exception("Warning starting Juice Shop background collector: %s", exc)

    # ── Hand control to FastAPI ───────────────────────────────────────────────
    yield

    # ── Shutdown ─────────────────────────────────────────────────────────────
    if settings.enable_juice_shop_connector:
        try:
            from app.services.juice_shop_background import stop_background_collector

            stop_background_collector()
        except Exception as exc:
            logger.exception("Warning stopping Juice Shop background collector: %s", exc)


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.cors_origins],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def add_security_headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        return response

    app.include_router(api_router)

    @app.api_route("/", methods=["GET", "HEAD"])
    def root() -> dict:
        return {
            "status": "online",
            "service": settings.app_name,
            "version": "1.0.0",
            "docs": "/api/docs",
            "health": "/health",
            "readiness": "/health/ready",
        }

    @app.api_route("/health", methods=["GET", "HEAD"])
    def health(ready: bool = False) -> dict:
        if ready:
            return readiness_check()
        return {"status": "ok", "service": settings.app_name}

    @app.api_route("/health/ready", methods=["GET", "HEAD"])
    @app.api_route("/ready", methods=["GET", "HEAD"])
    def readiness_check() -> dict:
        from app.database.session import SessionLocal

        try:
            db = SessionLocal()
            try:
                db.execute(text("SELECT 1"))
            finally:
                db.close()
            return {
                "status": "ready",
                "database": "connected",
                "service": settings.app_name,
            }
        except Exception as exc:
            logger.error("Database readiness check failed: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database persistence unavailable",
            ) from exc

    return app


app = create_app()
