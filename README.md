# NetSentinel

NetSentinel is a defensive, passive network traffic and security analyzer. This repository is intentionally an initial foundation: it provides a runnable API, a real-time dashboard shell, a safe collector skeleton, tests, and container definitions without implementing a complete detection platform.

## Project layout

- `collector/` — passive host and network metadata collection. It does not inject packets, intercept credentials, perform MITM activity, or attack other systems.
- `backend/` — FastAPI application, SQLAlchemy database setup, security-event model, and WebSocket endpoint for live dashboard messages.
- `dashboard/` — Next.js, TypeScript, Tailwind CSS, and Recharts frontend.
- `tests/` — pytest coverage for the initial API and WebSocket contract.
- `docs/` — architecture, safety boundaries, and development notes.

## Quick start

### Backend

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r backend/requirements.txt -r collector/requirements.txt
uvicorn backend.main:app --reload --port 8000
```

The API is available at `http://localhost:8000`, with interactive Swagger documentation at `http://localhost:8000/docs` and its OpenAPI schema at `http://localhost:8000/openapi.json`.

Initial read-only endpoints:

- `GET /api/health`
- `GET /api/flows` — filter by protocol or endpoint IP; paginate with `limit` and `offset`.
- `GET /api/flows/recent` — filter by recent minutes and protocol.
- `GET /api/hosts` — search IP addresses and hostnames or filter by active state.
- `GET /api/hosts/{id}` — host totals, top destinations, and most-used protocols.
- `GET /api/alerts` — filter by severity, status, or alert type.
- `GET /api/stats/summary`
- `WS /ws/live` — throttled aggregate statistics and completed-flow events for dashboards.

The collector submits finalized flow batches to `POST /api/ingest/flows`. This endpoint requires an API key in the `X-API-Key` header. Generate a secret locally, copy `.env.example` to `.env`, and set the same value for the backend and collector:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Never commit the populated `.env` file. If `NETSENTINEL_API_KEY` is absent, the backend returns `503` for ingestion and the collector continues running with ingestion disabled.

Host records are created only for addresses observed in accepted flows that belong to RFC1918 IPv4, loopback/link-local ranges, or IPv6 ULA/link-local ranges. NetSentinel never probes these hosts. For a newly observed address, it may ask the local operating-system resolver for an existing hostname. Host activity is calculated from `last_seen`; configure its window with `NETSENTINEL_HOST_ACTIVE_TIMEOUT_SECONDS` (300 seconds by default).

Accepted flows are also evaluated by defensive, metadata-only rules for possible port scans, connection spikes, configured unusual destination ports, large inbound or outbound transfers, and newly observed LAN hosts. Alerts use cautious language and include structured evidence such as counts, windows, thresholds, ports, and byte totals. All rule thresholds and the alert cooldown are configurable through the `NETSENTINEL_*` values documented in `.env.example`; set `NETSENTINEL_DETECTION_ENABLED=false` to disable the engine.

### Dashboard

```bash
cd dashboard
pnpm install
pnpm dev
```

Open `http://localhost:3000`. The dashboard connects to the backend WebSocket when the API is running.

Dashboard routes:

- `/` — live overview metrics, transfer estimates, protocol distribution, recent flows, and recent alerts.
- `/traffic` — filterable completed-flow inventory.
- `/hosts` — searchable observed-host inventory with activity filtering.
- `/alerts` — security-alert queue with severity and status filters.

The overview loads its initial state from the API, then updates throughput, active connections, recent flows, and protocol statistics over `/ws/live` without refreshing. The browser reconnects automatically with exponential backoff and shows the stream status. The backend coalesces ingestion bursts into compact updates rather than forwarding packets or emitting one message per packet. Periodic API refresh remains as a recovery path, and the dashboard does not substitute sample telemetry when the backend is available.

### Collector

The collector records only packet metadata. Scapy receives packets transiently, `store=False` prevents packet retention, and the normalized model has no payload field. Only monitor machines and networks you own or are explicitly authorized to observe.

List interfaces and choose one of the identifiers shown:

```bash
python -m collector.main --list-interfaces
python -m collector.main --interface "INTERFACE_NAME"
```

Press `Ctrl+C` to stop capture cleanly. Use `--debug` for readable per-packet summaries, `--count 25` for a bounded capture, or `--demo` to process synthetic packet metadata without opening a capture socket. If live capture cannot start, demo mode is used automatically; pass `--no-demo-fallback` to return an error instead.

Packets are aggregated into directional flows using source/destination IP, source/destination port, and protocol. Only the active aggregate is kept in memory; individual packets are not retained. Inactive flows are finalized after 60 seconds by default:

```bash
python -m collector.main --interface eth0 --flow-timeout 30
```

Set the same value with `NETSENTINEL_FLOW_TIMEOUT_SECONDS`. Remaining active flows are finalized when the collector exits.

When `NETSENTINEL_API_KEY` is configured, completed flows are placed on a bounded background queue and delivered to `NETSENTINEL_BACKEND_URL`. Delivery batches are retried for network errors, rate limits, and temporary server failures. Packet capture continues while delivery is unavailable.

Useful delivery settings are documented in `.env.example`, including batch size, flush interval, request timeout, retry count, and maximum queue size.

#### Windows

1. Install [Npcap](https://npcap.com/). Current Scapy guidance recommends leaving WinPcap compatibility mode disabled.
2. Open PowerShell as Administrator when your Npcap configuration requires elevated capture access.
3. Activate the virtual environment and run the interface-list and collector commands above.

```powershell
.venv\Scripts\Activate.ps1
python -m collector.main --list-interfaces
python -m collector.main --interface "Ethernet"
```

Interface labels vary by host, so use an exact value returned by `--list-interfaces`.

#### Linux

Packet capture normally requires root or Linux capabilities. Prefer granting a dedicated virtual-environment interpreter only the capture capabilities it needs instead of running the entire application as root. Be aware that every script executed by that interpreter receives those capabilities; remove them when they are no longer needed.

```bash
source .venv/bin/activate
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(which python)")"
python -m collector.main --list-interfaces
python -m collector.main --interface eth0
sudo setcap -r "$(readlink -f "$(which python)")"
```

If you do not want to grant capture permissions, use `python -m collector.main --demo`.

### Tests

From the repository root, with the Python environment active:

```bash
pytest
```

### Docker Compose

```bash
docker compose up --build
```

This starts the API on port `8000` and dashboard on port `3000`, using SQLite for early development. PostgreSQL can be introduced later by changing `DATABASE_URL` and adding a compatible SQLAlchemy driver.

## Current scope

The current foundation exposes health and inventory APIs plus a throttled live WebSocket stream. The collector supports local, passive IPv4/IPv6 packet-metadata capture, aggregates packets into completed flows, and delivers bounded batches to the authenticated backend ingestion API. Detection rules, user authentication, PostgreSQL migrations, and production deployment remain future work.

See [docs/architecture.md](docs/architecture.md) and [docs/safety.md](docs/safety.md) before extending collection capabilities.
