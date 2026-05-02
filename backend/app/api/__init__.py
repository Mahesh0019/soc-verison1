from fastapi import APIRouter

from app.api import admin, alerts, auth, dashboard, demo, events, logs, rules, threat_intel


api_router = APIRouter(prefix="/api")
api_router.include_router(auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(logs.router)
api_router.include_router(events.router)
api_router.include_router(alerts.router)
api_router.include_router(rules.router)
api_router.include_router(threat_intel.router)
api_router.include_router(admin.router)
api_router.include_router(demo.router)

