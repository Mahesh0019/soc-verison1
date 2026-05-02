from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import api_router
from app.config import get_settings
from app.database.base import Base
from app.database.session import engine
from app.models import *  # noqa: F403
from app.services.seed import ensure_builtin_rules, ensure_indicators, ensure_users


settings = get_settings()


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_name, version="1.0.0", docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.cors_origins],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(api_router)

    @app.on_event("startup")
    def on_startup() -> None:
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

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "service": settings.app_name}

    return app


app = create_app()

