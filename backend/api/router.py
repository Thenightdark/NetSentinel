from fastapi import APIRouter, Depends

from backend.api.dependencies import require_dashboard_user
from .routes import agents, alerts, auth, dns, flows, health, hosts, ingest, network_map, settings, stats

api_router = APIRouter(prefix="/api")
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(agents.router)
api_router.include_router(ingest.router)

protected_router = APIRouter(dependencies=[Depends(require_dashboard_user)])
protected_router.include_router(flows.router)
protected_router.include_router(hosts.router)
protected_router.include_router(alerts.router)
protected_router.include_router(dns.router)
protected_router.include_router(stats.router)
protected_router.include_router(network_map.router)
protected_router.include_router(settings.router)
api_router.include_router(protected_router)
