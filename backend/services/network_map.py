"""Bounded, aggregated topology data for the dashboard network map."""

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.models import CollectorAgent, Host, NetworkFlow
from backend.schemas import NetworkMapEdge, NetworkMapNode, NetworkMapResponse
from backend.services.hosts import is_local_network_address


def build_network_map(
    database: Session,
    *,
    window_minutes: int,
    agent_id: str | None,
    max_external_nodes: int,
    max_lan_nodes: int,
) -> NetworkMapResponse:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    filters = [NetworkFlow.last_seen >= cutoff]
    if agent_id:
        filters.append(NetworkFlow.agent_id == agent_id)
    rows = database.execute(
        select(
            NetworkFlow.agent_id,
            NetworkFlow.source_ip,
            NetworkFlow.destination_ip,
            NetworkFlow.protocol,
            func.sum(NetworkFlow.bytes),
            func.count(NetworkFlow.id),
        )
        .where(*filters)
        .group_by(
            NetworkFlow.agent_id,
            NetworkFlow.source_ip,
            NetworkFlow.destination_ip,
            NetworkFlow.protocol,
        )
        .order_by(func.sum(NetworkFlow.bytes).desc())
        .limit(2_000)
    ).all()

    endpoint_volume: dict[tuple[str | None, str], int] = defaultdict(int)
    external_endpoints: set[tuple[str | None, str]] = set()
    local_endpoints: set[tuple[str | None, str]] = set()
    for row_agent, source, destination, _protocol, total_bytes, _connections in rows:
        volume = int(total_bytes or 0)
        for address in (source, destination):
            key = (row_agent, address)
            endpoint_volume[key] += volume
            (local_endpoints if is_local_network_address(address) else external_endpoints).add(key)

    kept_external = set(
        sorted(external_endpoints, key=lambda key: endpoint_volume[key], reverse=True)[
            :max_external_nodes
        ]
    )
    kept_local = set(
        sorted(local_endpoints, key=lambda key: endpoint_volume[key], reverse=True)[
            :max_lan_nodes
        ]
    )

    endpoint_addresses = {address for _row_agent, address in endpoint_volume}
    host_query = select(Host).where(Host.ip_address.in_(endpoint_addresses))
    if agent_id:
        host_query = host_query.where(Host.agent_id == agent_id)
    host_rows = database.scalars(host_query).all()
    hosts = {(host.agent_id, host.ip_address): host for host in host_rows}
    agent_query = select(CollectorAgent)
    if agent_id:
        agent_query = agent_query.where(CollectorAgent.agent_id == agent_id)
    agent_rows = database.scalars(agent_query).all()
    collector_ips = {(agent.agent_id, agent.ip_address) for agent in agent_rows}

    node_totals: dict[str, dict[str, object]] = {}
    edge_totals: dict[tuple[str, str], dict[str, object]] = {}
    grouped_external: dict[str | None, set[str]] = defaultdict(set)
    grouped_local: dict[str | None, set[str]] = defaultdict(set)

    def node_id(row_agent: str | None, address: str) -> str:
        prefix = row_agent or "legacy"
        key = (row_agent, address)
        if is_local_network_address(address):
            if key not in kept_local:
                grouped_local[row_agent].add(address)
                return f"lan-group:{prefix}"
            return f"lan:{prefix}:{address}"
        if key not in kept_external:
            grouped_external[row_agent].add(address)
            return f"external-group:{prefix}"
        return f"external:{prefix}:{address}"

    for row_agent, source, destination, protocol, total_bytes, connections in rows:
        source_id = node_id(row_agent, source)
        target_id = node_id(row_agent, destination)
        if source_id == target_id:
            continue
        volume = int(total_bytes or 0)
        count = int(connections or 0)
        edge = edge_totals.setdefault(
            (source_id, target_id),
            {"bytes": 0, "connections": 0, "protocols": set()},
        )
        edge["bytes"] = int(edge["bytes"]) + volume
        edge["connections"] = int(edge["connections"]) + count
        protocols = edge["protocols"]
        if isinstance(protocols, set):
            protocols.add(protocol)
        for identifier, address in ((source_id, source), (target_id, destination)):
            node = node_totals.setdefault(
                identifier,
                {"agent_id": row_agent, "address": address, "bytes": 0, "connections": 0},
            )
            node["bytes"] = int(node["bytes"]) + volume
            node["connections"] = int(node["connections"]) + count

    nodes = []
    for identifier, values in node_totals.items():
        row_agent = values["agent_id"] if isinstance(values["agent_id"], str) else None
        address = str(values["address"])
        key = (row_agent, address)
        host = hosts.get(key)
        if identifier.startswith("external-group:"):
            grouped_count = len(grouped_external[row_agent])
            label, kind, ip_address, host_id = (
                f"Other external destinations ({grouped_count})",
                "external_group",
                None,
                None,
            )
        elif identifier.startswith("lan-group:"):
            grouped_count = len(grouped_local[row_agent])
            label, kind, ip_address, host_id = (
                f"Other LAN hosts ({grouped_count})",
                "lan_group",
                None,
                None,
            )
        else:
            grouped_count = 0
            ip_address = address
            host_id = host.id if host else None
            label = host.hostname if host and host.hostname else address
            if key in collector_ips:
                kind = "collector"
            else:
                kind = "lan" if is_local_network_address(address) else "external"
        nodes.append(
            NetworkMapNode(
                id=identifier,
                label=label,
                ip_address=ip_address,
                kind=kind,
                agent_id=row_agent,
                host_id=host_id,
                connections=int(values["connections"]),
                bytes=int(values["bytes"]),
                grouped_destinations=grouped_count,
            )
        )

    nodes.sort(key=lambda item: (item.kind.endswith("group"), -item.bytes, item.label))
    edges = [
        NetworkMapEdge(
            id=f"edge:{index}",
            source=source,
            target=target,
            connections=int(values["connections"]),
            bytes=int(values["bytes"]),
            protocols=sorted(values["protocols"]),
        )
        for index, ((source, target), values) in enumerate(
            sorted(edge_totals.items(), key=lambda item: int(item[1]["bytes"]), reverse=True)
        )
    ]
    return NetworkMapResponse(
        window_minutes=window_minutes,
        nodes=nodes,
        edges=edges,
        aggregated_flow_groups=len(rows),
    )
