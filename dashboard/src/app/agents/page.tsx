"use client";

import { EmptyState, ErrorState, LoadingState } from "@/components/page-states";
import { SectionHeader } from "@/components/section-header";
import { useApiData } from "@/hooks/use-api-data";
import { AgentPageResponse } from "@/lib/api";
import { formatRelativeTime } from "@/lib/format";

export default function AgentsPage() {
  const { data, loading, error, reload } = useApiData<AgentPageResponse>("/api/agents");
  const online = data?.items.filter((agent) => agent.status === "ONLINE").length ?? 0;
  return <>
    <SectionHeader eyebrow="COLLECTORS / FLEET" title="Agents" description="Collector installations authorized to submit passive network metadata." />
    {loading && !data ? <LoadingState rows={5} /> : error && !data ? <ErrorState onRetry={reload} /> : data && <>
      <div className="agent-summary" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 14rem), 1fr))" }}>
        <article><span>Total agents</span><strong>{data.total}</strong><small>Registered identities</small></article>
        <article><span>Online now</span><strong className="agent-online-number">{online}</strong><small>Recently checked in</small></article>
        <article><span>Offline</span><strong>{Math.max(0, data.total - online)}</strong><small>Outside heartbeat window</small></article>
      </div>
      <section className="panel data-panel">
        <div className="panel-header"><div><p className="kicker">AGENT FLEET</p><h2>Collector status</h2></div><span className="panel-meta">{online} online</span></div>
        {error && <div className="inline-warning">Refresh failed. Showing the last successful response.</div>}
        {data.items.length === 0 ? <EmptyState title="No collector agents" message="Start a collector with the enrollment key to register its identity." /> : <div className="agent-grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 18rem), 1fr))" }}>
          {data.items.map((agent) => <article className="agent-card" key={agent.agent_id}>
            <div className="agent-card-head"><span className={`agent-status agent-status--${agent.status.toLowerCase()}`}><i />{agent.status === "ONLINE" ? "Online" : "Offline"}</span><small>v{agent.version}</small></div>
            <h2>{agent.hostname}</h2><p>{agent.operating_system}</p>
            <dl><div><dt>IP address</dt><dd className="mono">{agent.ip_address}</dd></div><div><dt>Last seen</dt><dd>{formatRelativeTime(agent.last_seen)}</dd></div><div><dt>Agent ID</dt><dd className="mono agent-id">{agent.agent_id}</dd></div></dl>
          </article>)}
        </div>}
      </section>
    </>}
  </>;
}
