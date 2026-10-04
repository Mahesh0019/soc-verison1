from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import api_router
from app.config import get_settings
from app.database.base import Base
from app.database.session import engine
from app.models import *  # noqa: F403
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users


settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    # ── Startup ──────────────────────────────────────────────────────────────
    if settings.auto_create_tables:
        Base.metadata.create_all(bind=engine)

    from app.database.session import SessionLocal

    db = SessionLocal()
    try:
        ensure_users(db)
        ensure_builtin_rules(db)
        ensure_indicators(db)
    finally:
        db.close()

    # Start the Juice Shop connector background task only when explicitly enabled.
    # Default is False so existing local/CI behaviour is unchanged.
    if settings.enable_juice_shop_connector:
        from app.services.juice_shop_background import start_background_collector

        start_background_collector()

    # ── Hand control to FastAPI ───────────────────────────────────────────────
    yield

    # ── Shutdown ─────────────────────────────────────────────────────────────
    if settings.enable_juice_shop_connector:
        from app.services.juice_shop_background import stop_background_collector

        stop_background_collector()


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

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "service": settings.app_name}

    return app


app = create_app()
