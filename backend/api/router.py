from fastapi import APIRouter

from .routes import alerts, flows, health, hosts, ingest, stats

api_router = APIRouter(prefix="/api")
api_router.include_router(health.router)
api_router.include_router(flows.router)
api_router.include_router(hosts.router)
api_router.include_router(alerts.router)
api_router.include_router(ingest.router)
api_router.include_router(stats.router)
