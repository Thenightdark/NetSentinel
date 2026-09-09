from fastapi import APIRouter, Depends

from backend.api.dependencies import require_dashboard_user
from .routes import alerts, auth, dns, flows, health, hosts, ingest, stats

api_router = APIRouter(prefix="/api")
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(ingest.router)

protected_router = APIRouter(dependencies=[Depends(require_dashboard_user)])
protected_router.include_router(flows.router)
protected_router.include_router(hosts.router)
protected_router.include_router(alerts.router)
protected_router.include_router(dns.router)
protected_router.include_router(stats.router)
api_router.include_router(protected_router)
