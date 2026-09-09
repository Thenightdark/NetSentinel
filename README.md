# NetSentinel

NetSentinel is a defensive, passive network traffic and security analyzer. This repository is intentionally an initial foundation: it provides a runnable API, a real-time dashboard shell, a safe collector skeleton, tests, and container definitions without implementing a complete detection platform.

## Project layout

- `collector/` — passive host and network metadata collection. It does not inject packets, intercept credentials, perform MITM activity, or attack other systems.
- `backend/` — FastAPI application, SQLAlchemy models, Alembic migrations, services, and the live WebSocket endpoint.
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
cp .env.example .env
alembic upgrade head
uvicorn backend.main:app --reload --port 8000
```

On Windows PowerShell, use `Copy-Item .env.example .env` instead of `cp`. Set a new PostgreSQL password and API key in `.env` before starting. A PostgreSQL server matching `DATABASE_URL` must be available; Docker Compose below is the simplest complete setup.

The API is available at `http://localhost:8000`, with interactive Swagger documentation at `http://localhost:8000/docs` and its OpenAPI schema at `http://localhost:8000/openapi.json`.

Authentication endpoints:

- `POST /api/auth/login` — verifies a dashboard user and starts a revocable session.
- `POST /api/auth/logout` — revokes the current session and clears its cookie.
- `GET /api/auth/me` — returns the authenticated dashboard user.

The following data endpoints require a dashboard session:

- `GET /api/health`
- `GET /api/flows` — filter by protocol or endpoint IP; paginate with `limit` and `offset`.
- `GET /api/flows/recent` — filter by recent minutes and protocol.
- `GET /api/hosts` — search IP addresses and hostnames or filter by active state.
- `GET /api/hosts/{id}` — host totals, top destinations, and most-used protocols.
- `GET /api/alerts` — filter by severity, status, or alert type.
- `GET /api/stats/summary`
- `GET /api/stats/history` — indexed rollups for `5m`, `1h`, `24h`, or `7d` graph ranges.
- `GET /api/dns` — filter and paginate passive DNS query/response metadata.
- `GET /api/dns/top-domains` — aggregate requested domains over a selected window.
- `WS /ws/live` — throttled aggregate statistics and completed-flow events for dashboards.

The collector submits finalized flow batches to `POST /api/ingest/flows`. This endpoint requires an API key in the `X-API-Key` header. Generate a secret locally, copy `.env.example` to `.env`, and set the same value for the backend and collector:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Never commit the populated `.env` file. If `NETSENTINEL_API_KEY` is absent, the backend returns `503` for ingestion and the collector continues running with ingestion disabled.

Dashboard access requires a separate user login. Configure a unique `NETSENTINEL_AUTH_SECRET`, initial administrator username, and initial administrator password in `.env`. The password is stored as an Argon2 hash; login creates a revocable, expiring HTTP-only session cookie. Data APIs, alert updates, dashboard pages, and live WebSockets require that session, while health checks and collector ingestion remain separate. See [`docs/authentication.md`](docs/authentication.md) for the security model and deployment settings.

Host records are created only for addresses observed in accepted flows that belong to RFC1918 IPv4, loopback/link-local ranges, or IPv6 ULA/link-local ranges. NetSentinel never probes these hosts. For a newly observed address, it may ask the local operating-system resolver for an existing hostname. Host activity is calculated from `last_seen`; configure its window with `NETSENTINEL_HOST_ACTIVE_TIMEOUT_SECONDS` (300 seconds by default).

Accepted flow and DNS metadata is evaluated by defensive rules for possible port scans, connection spikes, configured unusual destination ports, large inbound or outbound transfers, newly observed LAN hosts, high DNS query rates, unusually long domain names, and repeated failed lookups. Alerts use cautious language and include structured evidence such as counts, windows, thresholds, ports, and byte totals. All rule thresholds and the alert cooldown are configurable through the `NETSENTINEL_*` values documented in `.env.example`; set `NETSENTINEL_DETECTION_ENABLED=false` to disable the engine.

Each alert receives an explainable 0–100 risk score and a derived `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` severity. Alerts move through `NEW`, `ACKNOWLEDGED`, and `RESOLVED` states using `PATCH /api/alerts/{id}/status`. The complete formula and legacy-data mapping are documented in [`docs/risk-scoring.md`](docs/risk-scoring.md).

### Dashboard

```bash
cd dashboard
pnpm install
pnpm dev
```

Open `http://localhost:3000`. The dashboard connects to the backend WebSocket when the API is running.

Dashboard routes:

- `/` — live overview metrics, transfer estimates, protocol distribution, recent flows, and recent alerts.
- `/traffic` — filterable completed-flow inventory with optional local process context.
- `/hosts` — searchable observed-host inventory with activity filtering.
- `/hosts/{id}` — detailed host activity, risk, protocol, destination, flow, and alert view.
- `/alerts` — security-alert queue with severity and status filters.

The overview loads its initial state from the API, then updates throughput, active connections, recent flows, and protocol statistics over `/ws/live` without refreshing. The browser reconnects automatically with exponential backoff and shows the stream status. The backend coalesces ingestion bursts into compact updates rather than forwarding packets or emitting one message per packet. Periodic API refresh remains as a recovery path, and the dashboard does not substitute sample telemetry when the backend is available.

Historical dashboard graphs read bounded 1-minute, 5-minute, 1-hour, or 6-hour database rollups rather than repeatedly scanning raw flows and alerts. The rollups track uploaded and downloaded bytes, completed flows, distinct active hosts, and newly created alerts. See [`docs/historical-statistics.md`](docs/historical-statistics.md) for retention and metric semantics.

### Collector

The collector records only packet metadata. For DNS traffic it additionally extracts the requesting host, first queried name, query type, timestamp, and response code when observing a response. It does not retain DNS answers, unrelated record contents, or any other packet payload. Scapy receives packets transiently and `store=False` prevents packet retention. Only monitor machines and networks you own or are explicitly authorized to observe.

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

Optional local process correlation uses `psutil` to match observed TCP/UDP endpoints against the operating system's connection table. Enable it with `--process-correlation` or `NETSENTINEL_PROCESS_CORRELATION_ENABLED=true`. When permitted by the OS, flows include the PID, process name, and executable basename shown on the Traffic dashboard:

```bash
python -m collector.main --interface eth0 --process-correlation
```

This feature is disabled by default. Results are best-effort because short-lived connections can close between snapshots and some operating systems restrict process ownership details. Access failures do not stop capture or ingestion. NetSentinel does not read process memory, inject code, manipulate privileges, or store full executable paths. Adjust the snapshot cache interval with `NETSENTINEL_PROCESS_REFRESH_SECONDS` (2 seconds by default).

When `NETSENTINEL_API_KEY` is configured, completed flows and normalized DNS observations use separate bounded background queues and authenticated ingestion endpoints. Delivery batches are retried for network errors, rate limits, and temporary server failures. Packet capture continues while delivery is unavailable.

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
cp .env.example .env
docker compose up --build
```

On Windows PowerShell, use `Copy-Item .env.example .env` for the first command. Replace the development-only database password, administrator password, authentication secret, and collector API-key placeholders in `.env`, then Compose starts PostgreSQL, waits for it to become healthy, applies all Alembic migrations, starts the API on port `8000`, and starts the dashboard on port `3000`. PostgreSQL data is retained in the named `postgres-data` volume.

For local schema work, run `alembic upgrade head` before FastAPI. Application startup intentionally does not call `create_all`; schema history remains explicit and repeatable. See [`docs/postgresql.md`](docs/postgresql.md) for migration commands and guidance about existing SQLite development data.

## Current scope

The current foundation exposes inventory, history, DNS, alert, and health APIs plus a throttled live WebSocket stream. The collector supports local, passive IPv4/IPv6 packet-metadata capture, aggregates packets into completed flows, and delivers bounded batches to the authenticated backend ingestion API. PostgreSQL is managed through Alembic migrations. End-user authentication and production hardening remain future work.

See [docs/architecture.md](docs/architecture.md) and [docs/safety.md](docs/safety.md) before extending collection capabilities.
