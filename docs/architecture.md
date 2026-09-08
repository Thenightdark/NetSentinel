# Architecture

NetSentinel starts as three intentionally separate components:

1. The **collector** reads passive IPv4/IPv6 metadata from the authorized host, normalizes it, and aggregates directional five-tuple flows in memory. A periodic finalizer removes inactive flows after a configurable timeout. Finalized flows enter a bounded delivery queue and are sent to the backend in authenticated, retry-safe batches. It uses Scapy with packet retention disabled.
2. The **backend** owns Host, NetworkFlow, and SecurityAlert persistence and exposes filtered, paginated HTTP queries plus a WebSocket event stream. Host records are derived passively from local-network endpoints in accepted flow batches, with cumulative traffic totals and on-demand peer/protocol statistics. SQLite keeps local setup small; SQLAlchemy isolates the database layer so PostgreSQL can replace it later.
3. The **dashboard** renders operational status and is ready to consume live events from the WebSocket endpoint.

This separation keeps privileged collection concerns away from the public-facing application. The ingestion contract authenticates collectors, validates flow batches, and records batch IDs so ambiguous HTTP retries do not duplicate flows. Packet payloads are never part of the contract.
