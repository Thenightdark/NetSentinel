from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from backend.api.dependencies import require_ingest_api_key
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
from backend.websocket.manager import live_manager

router = APIRouter(prefix="/ingest", tags=["ingestion"])


@router.post(
    "/flows",
    response_model=FlowIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_ingest_api_key)],
)
async def ingest_flows(
    request: FlowIngestRequest,
    database: Session = Depends(get_db),
) -> FlowIngestResponse:
    accepted, duplicate, completed_flows, new_host_ips = ingest_flow_batch(
        database, request
    )
    if not duplicate:
        run_detection(database, completed_flows, new_host_ips)
        live_manager.queue(build_live_update(database, completed_flows))
    return FlowIngestResponse(accepted=accepted, duplicate=duplicate)


@router.post(
    "/dns",
    response_model=DNSIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_ingest_api_key)],
)
def ingest_dns(
    request: DNSIngestRequest,
    database: Session = Depends(get_db),
) -> DNSIngestResponse:
    accepted, duplicate, observations = ingest_dns_batch(database, request)
    if not duplicate:
        run_dns_detection(database, observations)
    return DNSIngestResponse(accepted=accepted, duplicate=duplicate)
