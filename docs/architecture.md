# Architecture

NetSentinel starts as three intentionally separate components:

1. The **collector** reads passive IPv4/IPv6 metadata from the authorized host, normalizes it, and aggregates directional five-tuple flows in memory. For DNS packets it extracts only first-question metadata and response codes. When explicitly enabled, a cached `psutil` connection-table snapshot can attach a local PID, process name, and executable basename to a matching endpoint. A periodic finalizer removes inactive flows after a configurable timeout. Finalized flows and DNS observations enter separate bounded delivery queues and are sent to the backend in authenticated, retry-safe batches. It uses Scapy with packet retention disabled.
2. The **backend** owns Host, NetworkFlow, DNSObservation, and SecurityAlert persistence and exposes filtered, paginated HTTP queries plus a WebSocket event stream. Host records are derived passively from local-network endpoints in accepted flow batches. Flow and DNS metadata feed cautious, configurable detection rules. SQLite keeps local setup small; SQLAlchemy isolates the database layer so PostgreSQL can replace it later.
3. The **dashboard** renders operational status, live flow events, DNS activity trends, top requested domains, and active DNS clients.

This separation keeps privileged collection concerns away from the public-facing application. The ingestion contract authenticates collectors, validates flow batches, and records batch IDs so ambiguous HTTP retries do not duplicate flows. Packet payloads are never part of the contract.

Process correlation is disabled by default and is only an observation of connection metadata already exposed by the local operating system. It does not inspect memory, inject into processes, manipulate privileges, or expose full executable paths. Missing permissions or short-lived connections simply result in flows with no process fields.
