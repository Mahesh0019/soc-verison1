from fastapi import APIRouter

from app.api import (
    admin,
    alerts,
    auth,
    cases,
    dashboard,
    demo,
    detection_quality,
    events,
    evidence,
    incidents,
    logs,
    risk,
    rules,
    threat_intel,
)


api_router = APIRouter(prefix="/api")
api_router.include_router(auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(logs.router)
api_router.include_router(events.router)
api_router.include_router(alerts.router)
api_router.include_router(incidents.router)
api_router.include_router(cases.router)
api_router.include_router(risk.router)
api_router.include_router(rules.router)
api_router.include_router(threat_intel.router)
api_router.include_router(evidence.router)
api_router.include_router(detection_quality.router)
api_router.include_router(admin.router)
api_router.include_router(demo.router)
