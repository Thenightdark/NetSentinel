"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { LiveStatus } from "@/components/live-status";
import { MetricCard } from "@/components/metric-card";
import { EmptyState, ErrorState, LoadingState } from "@/components/page-states";
import { ProtocolChart } from "@/components/protocol-chart";
import { DNSRequestsChart } from "@/components/dns-requests-chart";
import { HistoricalActivityChart, HistoricalTrafficChart } from "@/components/historical-stats-charts";
import { useApiData } from "@/hooks/use-api-data";
import { DNSObservation, fetchApi, HistoricalStats, HistoryRange, Host, NetworkFlow, PageResponse, SecurityAlert, StatsSummary, TopDomain } from "@/lib/api";
import { endpoint, formatBitsPerSecond, formatBytes, formatNumber, formatRelativeTime, formatTime, isLocalAddress } from "@/lib/format";
import { useLiveFlowUpdates } from "@/hooks/use-live-flow-updates";

type OverviewData = { stats: StatsSummary; minuteFlows: PageResponse<NetworkFlow>; recentFlows: PageResponse<NetworkFlow>; activeHosts: PageResponse<Host>; alerts: PageResponse<SecurityAlert>; dns: PageResponse<DNSObservation>; topDomains: TopDomain[] };
const historyRanges: { value: HistoryRange; label: string }[] = [
  { value: "5m", label: "Last 5 minutes" },
  { value: "1h", label: "Last hour" },
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
];

export default function OverviewPage() {
  const [data, setData] = useState<OverviewData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const [liveThroughput, setLiveThroughput] = useState<number | null>(null);
  const [activeConnections, setActiveConnections] = useState(0);
  const [historyRange, setHistoryRange] = useState<HistoryRange>("1h");
  const history = useApiData<HistoricalStats>(`/api/stats/history?range=${historyRange}`);

  const liveState = useLiveFlowUpdates((update) => {
    setLiveThroughput(update.summary.throughput_bps);
    setActiveConnections(update.summary.active_connections);
    setData((current) => current ? {
      ...current,
      stats: {
        ...current.stats,
        flows: update.summary.total_flows,
        total_bytes: update.summary.total_bytes,
        total_packets: update.summary.total_packets,
        protocols: update.summary.protocols,
      },
      recentFlows: {
        ...current.recentFlows,
        items: update.recent_flows.slice(0, current.recentFlows.limit),
        total: update.summary.active_connections,
      },
    } : current);
  });

  const load = useCallback(async (signal?: AbortSignal) => {
    setError(false);
    try {
      const [stats, minuteFlows, recentFlows, activeHosts, alerts, dns, topDomains] = await Promise.all([
        fetchApi<StatsSummary>("/api/stats/summary", signal),
        fetchApi<PageResponse<NetworkFlow>>("/api/flows/recent?minutes=1&limit=200", signal),
        fetchApi<PageResponse<NetworkFlow>>("/api/flows/recent?minutes=60&limit=8", signal),
        fetchApi<PageResponse<Host>>("/api/hosts?active=true&limit=1", signal),
        fetchApi<PageResponse<SecurityAlert>>("/api/alerts?limit=6", signal),
        fetchApi<PageResponse<DNSObservation>>("/api/dns?minutes=60&limit=500", signal),
        fetchApi<TopDomain[]>("/api/dns/top-domains?minutes=60&limit=6", signal),
      ]);
      setData({ stats, minuteFlows, recentFlows, activeHosts, alerts, dns, topDomains });
    } catch (requestError) {
      if ((requestError as Error).name !== "AbortError") setError(true);
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    const initialLoad = window.setTimeout(() => load(controller.signal), 0);
    const interval = window.setInterval(() => load(), 15_000);
    return () => { controller.abort(); window.clearTimeout(initialLoad); window.clearInterval(interval); };
  }, [load, refreshKey]);

  const transfer = useMemo(() => {
    const flows = data?.minuteFlows.items ?? [];
    let upload = 0;
    let download = 0;
    for (const flow of flows) {
      const sourceLocal = isLocalAddress(flow.source_ip);
      const destinationLocal = isLocalAddress(flow.destination_ip);
      if (sourceLocal && !destinationLocal) upload += flow.bytes;
      if (!sourceLocal && destinationLocal) download += flow.bytes;
    }
    const total = flows.reduce((sum, flow) => sum + flow.bytes, 0);
    return { upload, download, throughput: (total * 8) / 60 };
  }, [data]);

  const dnsInsights = useMemo(() => {
    const queries = (data?.dns.items ?? []).filter((item) => !item.is_response);
    const bucketMilliseconds = 5 * 60 * 1000;
    const latestTimestamp = Math.max(
      0,
      ...queries.map((query) => new Date(query.timestamp).getTime()),
    );
    const end = Math.ceil(latestTimestamp / bucketMilliseconds) * bucketMilliseconds;
    const start = end - 12 * bucketMilliseconds;
    const timeline = Array.from({ length: 12 }, (_, index) => {
      const time = new Date(start + index * bucketMilliseconds);
      return { time: time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }), requests: 0 };
    });
    const clients = new Map<string, number>();
    for (const query of queries) {
      const index = Math.floor((new Date(query.timestamp).getTime() - start) / bucketMilliseconds);
      if (index >= 0 && index < timeline.length) timeline[index].requests += 1;
      clients.set(query.requesting_host, (clients.get(query.requesting_host) ?? 0) + 1);
    }
    const activeClients = [...clients.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
    return { timeline, activeClients };
  }, [data]);

  if (loading && !data) return <LoadingState rows={6} />;
  if (error && !data) return <ErrorState onRetry={() => { setLoading(true); setRefreshKey((key) => key + 1); }} />;
  if (!data) return null;

  return <>
    <header className="page-header"><div><p className="kicker">SECURITY OPERATIONS / OVERVIEW</p><h1>Network overview</h1><p>Passive visibility across observed flows, hosts, and alerts.</p></div><div className="desktop-status"><LiveStatus state={liveState} /><button className="icon-button" onClick={() => setRefreshKey((key) => key + 1)} aria-label="Refresh dashboard">↻</button></div></header>
    {error && <div className="inline-warning">Some data could not be refreshed. Showing the last successful response.</div>}
    <section className="metric-grid" aria-label="Network metrics">
      <MetricCard label="Current throughput" value={formatBitsPerSecond(liveThroughput ?? transfer.throughput)} detail="Completed flows · last minute" tone="cyan" />
      <MetricCard label="Total flows" value={formatNumber(data.stats.flows)} detail={`${formatNumber(activeConnections || data.minuteFlows.total)} active connections`} tone="blue" />
      <MetricCard label="Active hosts" value={formatNumber(data.activeHosts.total)} detail="Seen within activity window" tone="lime" />
      <MetricCard label="Security alerts" value={formatNumber(data.stats.alerts)} detail={`${formatNumber(data.stats.open_alerts)} currently open`} tone="amber" />
    </section>
    <section className="transfer-strip"><div><span className="transfer-arrow upload">↑</span><span><small>Upload · last minute</small><strong>{formatBytes(transfer.upload)}</strong></span></div><div><span className="transfer-arrow download">↓</span><span><small>Download · last minute</small><strong>{formatBytes(transfer.download)}</strong></span></div><div className="transfer-total"><small>Total observed</small><strong>{formatBytes(data.stats.total_bytes)}</strong></div></section>
    <section className="history-section" aria-label="Historical network statistics">
      <div className="history-heading"><div><p className="kicker">HISTORICAL TELEMETRY</p><h2>Network activity over time</h2></div><div className="range-selector" role="group" aria-label="History range">{historyRanges.map((option) => <button key={option.value} type="button" aria-pressed={historyRange === option.value} className={historyRange === option.value ? "is-selected" : ""} onClick={() => setHistoryRange(option.value)}>{option.label}</button>)}</div></div>
      {history.loading && !history.data ? <LoadingState rows={3} /> : history.error && !history.data ? <div className="history-error" role="alert"><span>Historical statistics are unavailable.</span><button className="button" onClick={history.reload}>Retry</button></div> : history.data && <div className="history-grid"><article className="panel history-panel"><div className="panel-header"><div><p className="kicker">TRANSFER VOLUME</p><h2>Uploaded and downloaded bytes</h2></div><span className="panel-meta">{history.data.items.length} aggregated buckets</span></div><HistoricalTrafficChart data={history.data} /></article><article className="panel history-panel"><div className="panel-header"><div><p className="kicker">NETWORK EVENTS</p><h2>Flows, active hosts, and alerts</h2></div><span className="panel-meta">No raw-row scan</span></div><HistoricalActivityChart data={history.data} /></article></div>}
    </section>
    <div className="overview-grid">
      <section className="panel protocol-panel"><div className="panel-header"><div><p className="kicker">TRAFFIC COMPOSITION</p><h2>Protocol distribution</h2></div><span className="panel-meta">All completed flows</span></div><ProtocolChart data={data.stats.protocols} /></section>
      <section className="panel"><div className="panel-header"><div><p className="kicker">LATEST ACTIVITY</p><h2>Recent alerts</h2></div><Link className="text-link" href="/alerts">View all</Link></div>{data.alerts.items.length === 0 ? <EmptyState title="No security alerts" message="Alerts will appear here when defensive rules create them." /> : <ul className="alert-list">{data.alerts.items.map((alert) => <li key={alert.id}><span className={`severity severity--${alert.severity.toLowerCase()}`}>{alert.severity}</span><div><strong>{alert.alert_type.replaceAll("_", " ")}</strong><small>{alert.description}</small></div><time>{formatRelativeTime(alert.timestamp)}</time></li>)}</ul>}</section>
    </div>
    <section className="dns-section" aria-label="DNS metadata insights">
      <div className="panel dns-widget"><div className="panel-header"><div><p className="kicker">DNS VISIBILITY</p><h2>Top requested domains</h2></div><span className="panel-meta">Last hour</span></div>{data.topDomains.length === 0 ? <EmptyState title="No domain activity" message="Requested domains will appear after DNS metadata is observed." /> : <ol className="dns-list">{data.topDomains.map((domain) => <li key={domain.domain}><span className="mono">{domain.domain}</span><strong>{formatNumber(domain.query_count)}</strong><small>{domain.unique_clients} client{domain.unique_clients === 1 ? "" : "s"}</small></li>)}</ol>}</div>
      <div className="panel dns-widget dns-timeline"><div className="panel-header"><div><p className="kicker">QUERY VOLUME</p><h2>DNS requests over time</h2></div><span className="panel-meta">5-minute intervals</span></div><DNSRequestsChart data={dnsInsights.timeline} /></div>
      <div className="panel dns-widget"><div className="panel-header"><div><p className="kicker">CLIENT ACTIVITY</p><h2>Most active DNS clients</h2></div><span className="panel-meta">Last hour</span></div>{dnsInsights.activeClients.length === 0 ? <EmptyState title="No DNS clients" message="Requesting hosts will appear when DNS queries are observed." /> : <ol className="dns-list dns-clients">{dnsInsights.activeClients.map(([client, count]) => <li key={client}><span className="mono">{client}</span><strong>{formatNumber(count)}</strong><small>queries</small></li>)}</ol>}</div>
    </section>
    <section className="panel table-panel"><div className="panel-header"><div><p className="kicker">FLOW TELEMETRY</p><h2>Recent connections</h2></div><Link className="text-link" href="/traffic">Explore traffic</Link></div>{data.recentFlows.items.length === 0 ? <EmptyState title="No recent connections" message="Completed flows from the last hour will appear here." /> : <div className="table-scroll"><table><thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Volume</th></tr></thead><tbody>{data.recentFlows.items.map((flow) => <tr key={flow.id}><td>{formatTime(flow.last_seen)}</td><td className="mono">{endpoint(flow.source_ip, flow.source_port)}</td><td className="mono">{endpoint(flow.destination_ip, flow.destination_port)}</td><td><span className="protocol-pill">{flow.protocol}</span></td><td>{formatNumber(flow.packet_count)}</td><td>{formatBytes(flow.bytes)}</td></tr>)}</tbody></table></div>}</section>
  </>;
}
