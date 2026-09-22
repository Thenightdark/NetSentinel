"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import { AgentFilter } from "@/components/agent-filter";
import { EmptyState, ErrorState, LoadingState } from "@/components/page-states";
import { SectionHeader } from "@/components/section-header";
import { useApiData } from "@/hooks/use-api-data";
import { Host, PageResponse } from "@/lib/api";
import { formatBytes, formatNumber, formatRelativeTime } from "@/lib/format";

export default function HostsPage() {
  const [activity, setActivity] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [agentId, setAgentId] = useState("");
  const params = new URLSearchParams({ limit: "100" });
  if (activity) params.set("active", activity);
  if (search) params.set("search", search);
  if (agentId) params.set("agent_id", agentId);
  const { data, loading, error, reload } = useApiData<PageResponse<Host>>(`/api/hosts?${params}`);

  function applyFilters(event: FormEvent) { event.preventDefault(); setSearch(searchInput.trim()); }

  return <>
    <SectionHeader eyebrow="ASSETS / OBSERVED" title="Hosts" description="Local-network addresses discovered from passive traffic metadata." />
    <form className="filter-bar" onSubmit={applyFilters}>
      <AgentFilter value={agentId} onChange={setAgentId} />
      <label><span>Activity</span><select value={activity} onChange={(event) => setActivity(event.target.value)}><option value="">All hosts</option><option value="true">Active</option><option value="false">Inactive</option></select></label>
      <label className="filter-grow"><span>IP or hostname</span><input value={searchInput} onChange={(event) => setSearchInput(event.target.value)} placeholder="Search observed hosts" /></label>
      <button className="button" type="submit">Apply filters</button>
    </form>
    {loading && !data ? <LoadingState rows={6} /> : error && !data ? <ErrorState onRetry={reload} /> : data && <section className="panel data-panel">
      <div className="panel-header"><div><p className="kicker">HOST INVENTORY</p><h2>{formatNumber(data.total)} observed hosts</h2></div><span className="panel-meta">Showing {data.items.length}</span></div>
      {error && <div className="inline-warning">Refresh failed. Showing the last successful response.</div>}
      {data.items.length === 0 ? <EmptyState title="No matching hosts" message="Hosts appear after local addresses are observed in completed flows." /> : <div className="host-grid">{data.items.map((host) => <Link className="host-card" href={`/hosts/${host.id}`} key={host.id}>
        <div className="host-card-top"><span className={host.is_active ? "activity-dot is-online" : "activity-dot"} /><span>{host.is_active ? "Active" : "Inactive"}</span><small>#{host.id} · View details →</small></div>
        <h2 className="mono">{host.ip_address}</h2><p>{host.hostname ?? "Hostname unresolved"}</p>
        <dl><div><dt>Traffic</dt><dd>{formatBytes(host.total_bytes)}</dd></div><div><dt>Connections</dt><dd>{formatNumber(host.total_connections)}</dd></div><div><dt>Last seen</dt><dd>{formatRelativeTime(host.last_seen)}</dd></div></dl>
      </Link>)}</div>}
    </section>}
  </>;
}
