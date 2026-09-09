"use client";

import Link from "next/link";
import { HostConnectionsChart, HostTrafficChart } from "@/components/host-activity-charts";
import { EmptyState, ErrorState, LoadingState } from "@/components/page-states";
import { ProtocolChart } from "@/components/protocol-chart";
import { useApiData } from "@/hooks/use-api-data";
import { HostDetail } from "@/lib/api";
import {
  endpoint,
  formatBytes,
  formatDateTime,
  formatNumber,
  formatRelativeTime,
} from "@/lib/format";

function riskLabel(score: number) {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 40) return "Medium";
  if (score >= 20) return "Low";
  return "Informational";
}

export function HostDetailClient({ hostId }: { hostId: string }) {
  const validId = /^\d+$/.test(hostId);
  const { data, loading, error, reload } = useApiData<HostDetail>(
    validId ? `/api/hosts/${hostId}` : "/api/hosts/invalid",
  );

  if (!validId) {
    return <div className="state-panel state-message"><span className="state-glyph">!</span><h2>Invalid host</h2><p>This host identifier is not valid.</p><Link className="button" href="/hosts">Return to hosts</Link></div>;
  }
  if (loading && !data) return <LoadingState rows={8} />;
  if (error && !data) return <ErrorState onRetry={reload} />;
  if (!data) return null;

  const protocolData = data.most_used_protocols.map((item) => ({
    protocol: item.protocol,
    flow_count: item.connections,
  }));

  return (
    <>
      <div className="host-breadcrumb"><Link href="/hosts">← Hosts</Link><span>/</span><span className="mono">{data.ip_address}</span></div>
      <header className="host-detail-hero">
        <div>
          <div className="host-state"><span className={data.is_active ? "activity-dot is-online" : "activity-dot"} />{data.is_active ? "Active now" : "Inactive"}</div>
          <h1 className="mono">{data.ip_address}</h1>
          <p>{data.hostname ?? "Hostname unresolved"}</p>
        </div>
        <div className={`host-risk host-risk--${riskLabel(data.risk_score).toLowerCase()}`}>
          <span>Current risk</span><strong>{data.risk_score}</strong><small>/ 100 · {riskLabel(data.risk_score)}</small>
        </div>
      </header>
      {error && <div className="inline-warning">Refresh failed. Showing the last successful response.</div>}

      <section className="host-facts" aria-label="Host summary">
        <article><span>Total transferred</span><strong>{formatBytes(data.total_bytes)}</strong></article>
        <article><span>Total connections</span><strong>{formatNumber(data.total_connections)}</strong></article>
        <article><span>First seen</span><strong>{formatDateTime(data.first_seen)}</strong><small>{formatRelativeTime(data.first_seen)}</small></article>
        <article><span>Last seen</span><strong>{formatDateTime(data.last_seen)}</strong><small>{formatRelativeTime(data.last_seen)}</small></article>
      </section>

      <section className="host-chart-grid">
        <article className="panel host-chart-panel host-chart-wide"><div className="panel-header"><div><p className="kicker">VOLUME</p><h2>Traffic over time</h2></div><span className="panel-meta">Last 24 hours</span></div><HostTrafficChart data={data.activity_over_time} /></article>
        <article className="panel host-chart-panel"><div className="panel-header"><div><p className="kicker">MIX</p><h2>Protocol distribution</h2></div><span className="panel-meta">All observed</span></div><ProtocolChart data={protocolData} /></article>
        <article className="panel host-chart-panel host-chart-full"><div className="panel-header"><div><p className="kicker">ACTIVITY</p><h2>Connections over time</h2></div><span className="panel-meta">Last 24 hours</span></div><HostConnectionsChart data={data.activity_over_time} /></article>
      </section>

      <section className="host-rankings">
        <article className="panel host-table-panel"><div className="panel-header"><div><p className="kicker">OUTBOUND</p><h2>Top destination IPs</h2></div></div>{data.top_destinations.length === 0 ? <EmptyState title="No destinations" message="Outbound destinations will appear after completed flows arrive." /> : <div className="table-scroll"><table><thead><tr><th>Destination</th><th>Connections</th><th>Traffic</th></tr></thead><tbody>{data.top_destinations.map((item) => <tr key={item.ip_address}><td className="mono">{item.ip_address}</td><td>{formatNumber(item.connections)}</td><td>{formatBytes(item.bytes)}</td></tr>)}</tbody></table></div>}</article>
        <article className="panel host-table-panel"><div className="panel-header"><div><p className="kicker">SERVICES</p><h2>Top destination ports</h2></div></div>{data.top_destination_ports.length === 0 ? <EmptyState title="No destination ports" message="Observed outbound service ports will appear here." /> : <div className="table-scroll"><table><thead><tr><th>Port</th><th>Connections</th><th>Traffic</th></tr></thead><tbody>{data.top_destination_ports.map((item) => <tr key={item.port}><td className="mono">{item.port}</td><td>{formatNumber(item.connections)}</td><td>{formatBytes(item.bytes)}</td></tr>)}</tbody></table></div>}</article>
      </section>

      <section className="panel host-detail-table"><div className="panel-header"><div><p className="kicker">LATEST ACTIVITY</p><h2>Recent network flows</h2></div><span className="panel-meta">Up to 10 flows</span></div>{data.recent_flows.length === 0 ? <EmptyState title="No recent flows" message="Traffic involving this host will appear here." /> : <div className="table-scroll"><table><thead><tr><th>Last seen</th><th>Direction</th><th>Remote endpoint</th><th>Protocol</th><th>Process</th><th>Packets</th><th>Traffic</th></tr></thead><tbody>{data.recent_flows.map((flow) => { const outbound = flow.source_ip === data.ip_address; return <tr key={flow.id}><td>{formatRelativeTime(flow.last_seen)}</td><td><span className={outbound ? "direction direction--out" : "direction direction--in"}>{outbound ? "Outbound" : "Inbound"}</span></td><td className="mono">{outbound ? endpoint(flow.destination_ip, flow.destination_port) : endpoint(flow.source_ip, flow.source_port)}</td><td><span className="protocol-pill">{flow.protocol}</span></td><td>{flow.process_name ?? flow.executable_name ?? (flow.process_id !== null ? `PID ${flow.process_id}` : "Unavailable")}</td><td>{formatNumber(flow.packet_count)}</td><td>{formatBytes(flow.bytes)}</td></tr>; })}</tbody></table></div>}</section>

      <section className="panel host-detail-table"><div className="panel-header"><div><p className="kicker">SECURITY CONTEXT</p><h2>Alerts involving this host</h2></div><span className="panel-meta">Current risk uses unresolved alerts</span></div>{data.recent_alerts.length === 0 ? <EmptyState title="No host alerts" message="No security signals currently involve this host." /> : <div className="table-scroll"><table><thead><tr><th>Time</th><th>Severity</th><th>Risk</th><th>Detection</th><th>Status</th><th>Explanation</th></tr></thead><tbody>{data.recent_alerts.map((alert) => <tr key={alert.id}><td>{formatRelativeTime(alert.timestamp)}</td><td><span className={`severity severity--${alert.severity.toLowerCase()}`}>{alert.severity}</span></td><td><strong>{alert.risk_score}</strong> / 100</td><td>{alert.alert_type.replaceAll("_", " ")}</td><td>{alert.status}</td><td className="host-alert-description">{alert.description}</td></tr>)}</tbody></table></div>}</section>
    </>
  );
}
