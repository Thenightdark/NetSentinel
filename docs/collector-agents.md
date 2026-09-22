# Collector agents

NetSentinel treats every collector installation as a separate agent. On its first successful start, a collector sends its hostname, operating system, safe locally resolved IP address, and collector version to `POST /api/agents/register`. Registration uses the shared enrollment secret only once.

The backend returns a random, unique agent API key. The collector stores the agent ID and key in `~/.netsentinel/agent.json` by default and never logs the key. Keep this file private and do not commit it. Override the path with `NETSENTINEL_AGENT_STATE_PATH` when needed.

Subsequent heartbeats and metadata batches include both `X-Agent-ID` and `X-API-Key`. The backend stores only a SHA-256 digest of the high-entropy generated key and uses constant-time comparison during authentication. Dashboard users continue to authenticate with their session cookie; collector credentials cannot open dashboard APIs.

## Status

Collectors send a heartbeat every 30 seconds by default. An agent is shown as offline when its latest authenticated request is older than 90 seconds. Configure these windows with:

- `NETSENTINEL_AGENT_HEARTBEAT_SECONDS` on the collector
- `NETSENTINEL_AGENT_ONLINE_TIMEOUT_SECONDS` on the backend

Failed heartbeats and ingestion requests are logged without terminating packet capture. Agent traffic, hosts, and alerts remain attributed by `agent_id` and can be filtered independently in the API and dashboard.

## Adding another machine

1. Configure the same backend URL and enrollment secret on the new machine.
2. Start the collector once. It creates a distinct local identity and receives its own key.
3. Confirm the machine appears on the dashboard **Agents** page.

If an identity file is lost, remove or revoke the old agent record before re-enrolling that installation. Never copy one machine's `agent.json` to another machine.
