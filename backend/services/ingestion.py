from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.models import Host, IngestBatch, NetworkFlow
from backend.schemas import FlowIngestRequest
from backend.services.hosts import track_local_hosts_for_flow


def ingest_flow_batch(
    database: Session, request: FlowIngestRequest
) -> tuple[int, bool, list[NetworkFlow], set[str]]:
    batch_id = str(request.batch_id)
    existing_batch = database.get(IngestBatch, batch_id)
    if existing_batch is not None:
        return existing_batch.flow_count, True, [], set()

    host_cache: dict[str, Host] = {}
    stored_flows: list[NetworkFlow] = []
    new_host_ips: set[str] = set()
    for item in request.flows:
        flow = NetworkFlow(
            source_ip=str(item.source_ip),
            destination_ip=str(item.destination_ip),
            source_port=item.source_port,
            destination_port=item.destination_port,
            protocol=item.protocol,
            bytes=item.bytes,
            packet_count=item.packet_count,
            first_seen=item.first_seen,
            last_seen=item.last_seen,
        )
        database.add(flow)
        stored_flows.append(flow)
        new_host_ips.update(track_local_hosts_for_flow(database, item, host_cache))

    database.add(IngestBatch(batch_id=batch_id, flow_count=len(request.flows)))
    try:
        database.commit()
    except IntegrityError:
        database.rollback()
        existing_batch = database.get(IngestBatch, batch_id)
        if existing_batch is None:
            raise
        return existing_batch.flow_count, True, [], set()
    return len(request.flows), False, stored_flows, new_host_ips
