from fastapi import APIRouter, BackgroundTasks, Depends, status
from sqlalchemy.orm import Session

from backend.api.dependencies import require_collector_agent
from backend.models import CollectorAgent
from backend.database.session import get_db
from backend.schemas import (
    DNSIngestRequest,
    DNSIngestResponse,
    FlowIngestRequest,
    FlowIngestResponse,
)
from backend.services.detection import run_detection, run_dns_detection
from backend.services.dns import ingest_dns_batch
from backend.services.ingestion import ingest_flow_batch
from backend.services.live import build_live_update
from backend.services.notifications import get_notification_manager
from backend.websocket.manager import live_manager

router = APIRouter(prefix="/ingest", tags=["ingestion"])


@router.post(
    "/flows",
    response_model=FlowIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_flows(
    request: FlowIngestRequest,
    background_tasks: BackgroundTasks,
    database: Session = Depends(get_db),
    agent: CollectorAgent = Depends(require_collector_agent),
) -> FlowIngestResponse:
    accepted, duplicate, completed_flows, new_host_ips = ingest_flow_batch(
        database, request, agent.agent_id
    )
    if not duplicate:
        alerts = run_detection(database, completed_flows, new_host_ips, agent.agent_id)
        if alerts:
            background_tasks.add_task(get_notification_manager().notify_alerts, alerts)
        live_manager.queue(build_live_update(database, completed_flows))
    return FlowIngestResponse(accepted=accepted, duplicate=duplicate)


@router.post(
    "/dns",
    response_model=DNSIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def ingest_dns(
    request: DNSIngestRequest,
    background_tasks: BackgroundTasks,
    database: Session = Depends(get_db),
    agent: CollectorAgent = Depends(require_collector_agent),
) -> DNSIngestResponse:
    accepted, duplicate, observations = ingest_dns_batch(database, request, agent.agent_id)
    if not duplicate:
        alerts = run_dns_detection(database, observations, agent.agent_id)
        if alerts:
            background_tasks.add_task(get_notification_manager().notify_alerts, alerts)
    return DNSIngestResponse(accepted=accepted, duplicate=duplicate)
