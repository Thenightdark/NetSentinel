"use client";

import Link from "next/link";
import { FormEvent, useState } from "react";
import { EmptyState, ErrorState, LoadingState } from "@/components/page-states";
import { SectionHeader } from "@/components/section-header";
import { useApiData } from "@/hooks/use-api-data";
import { PageResponse, SecurityAlert, SecurityEventDetail } from "@/lib/api";
import { endpoint, formatBytes, formatDateTime, formatNumber, formatRelativeTime } from "@/lib/format";
import styles from "./events.module.css";

const detectionTypes = [
  "possible_port_scan", "connection_spike", "unusual_destination_port",
  "bandwidth_spike", "new_host", "high_dns_query_rate",
  "unusually_long_domain", "repeated_failed_dns_lookups",
];

function toIso(value: string): string {
  return value ? new Date(value).toISOString() : "";
}

function title(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function Evidence({ evidence }: { evidence: Record<string, unknown> }) {
  const entries = Object.entries(evidence);
  if (entries.length === 0) return <p className={styles.muted}>No structured evidence was recorded for this event.</p>;
  return <dl className={styles.evidence}>{entries.map(([key, value]) => <div key={key}>
    <dt>{title(key)}</dt>
    <dd>{typeof value === "object" ? <pre>{JSON.stringify(value, null, 2)}</pre> : String(value)}</dd>
  </div>)}</dl>;
}

function EventDetail({ eventId }: { eventId: number }) {
  const { data, loading, error, reload } = useApiData<SecurityEventDetail>(`/api/alerts/${eventId}`, 60_000);
  if (loading && !data) return <LoadingState rows={6} />;
  if (error && !data) return <ErrorState onRetry={reload} />;
  if (!data) return null;
  return <article className={styles.detail}>
    <header className={styles.detailHeader}>
      <div><span className={`severity severity--${data.severity.toLowerCase()}`}>{data.severity}</span><span className={styles.status}>{data.status.replaceAll("_", " ")}</span><h2>{title(data.alert_type)}</h2><time>{formatDateTime(data.timestamp)}</time></div>
      <div className={`${styles.risk} risk-score--${data.severity.toLowerCase()}`}><strong>{data.risk_score}</strong><span>Risk score / 100</span></div>
    </header>
    <section className={styles.explanation}><h3>What happened</h3><p>{data.description}</p><div className={styles.caution}>This event is an analytical signal, not confirmation that an attack occurred.</div></section>
    <section><h3>Why NetSentinel flagged it</h3><p>{data.why_flagged}</p></section>
    <section><h3>Evidence</h3><Evidence evidence={data.evidence} /></section>
    <section><h3>Host information</h3>{data.host ? <div className={styles.hostContext}>
      <div><span className={data.host.is_active ? styles.online : styles.offline} /> <strong className="mono">{data.host.ip_address}</strong><small>{data.host.hostname ?? "Hostname unresolved"}</small></div>
      <dl><div><dt>Connections</dt><dd>{formatNumber(data.host.total_connections)}</dd></div><div><dt>Observed traffic</dt><dd>{formatBytes(data.host.total_bytes)}</dd></div><div><dt>Last seen</dt><dd>{formatRelativeTime(data.host.last_seen)}</dd></div></dl>
      <Link href={`/hosts/${data.host.id}`}>Open host investigation →</Link>
    </div> : <p className={styles.muted}>No local host record is associated with this signal.</p>}</section>
    <section><h3>Related flows</h3>{data.related_flows.length === 0 ? <p className={styles.muted}>No flows were found within the event correlation window.</p> : <div className={styles.flowTable}><table><thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Volume</th></tr></thead><tbody>{data.related_flows.map((flow) => <tr key={flow.id}><td>{formatRelativeTime(flow.last_seen)}</td><td className="mono">{endpoint(flow.source_ip, flow.source_port)}</td><td className="mono">{endpoint(flow.destination_ip, flow.destination_port)}</td><td>{flow.protocol}</td><td>{formatBytes(flow.bytes)}</td></tr>)}</tbody></table></div>}</section>
    <section><h3>Recommended investigation steps</h3><ol className={styles.steps}>{data.recommended_investigation_steps.map((step) => <li key={step}>{step}</li>)}</ol></section>
  </article>;
}

export default function SecurityEventsPage() {
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [detectionType, setDetectionType] = useState("");
  const [hostInput, setHostInput] = useState("");
  const [host, setHost] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const params = new URLSearchParams({ limit: "100" });
  if (severity) params.set("severity", severity);
  if (status) params.set("status", status);
  if (detectionType) params.set("alert_type", detectionType);
  if (host) params.set("host", host);
  if (dateFrom) params.set("date_from", toIso(dateFrom));
  if (dateTo) params.set("date_to", toIso(dateTo));
  const { data, loading, error, reload } = useApiData<PageResponse<SecurityAlert>>(`/api/alerts?${params}`);

  const activeSelectedId = data?.items.some((event) => event.id === selectedId)
    ? selectedId
    : data?.items[0]?.id ?? null;

  function applyFilters(event: FormEvent) { event.preventDefault(); setHost(hostInput.trim()); }

  return <>
    <SectionHeader eyebrow="DETECTION / INVESTIGATION" title="Security events" description="Chronological defensive signals with evidence and investigation context. Events indicate patterns worth review, not confirmed attacks." />
    <form className={`${styles.filters} filter-bar`} onSubmit={applyFilters}>
      <label><span>Severity</span><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">All severities</option>{["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((item) => <option key={item}>{item}</option>)}</select></label>
      <label><span>Host</span><input value={hostInput} onChange={(event) => setHostInput(event.target.value)} placeholder="IP or hostname" /></label>
      <label><span>Detection type</span><select value={detectionType} onChange={(event) => setDetectionType(event.target.value)}><option value="">All detections</option>{detectionTypes.map((item) => <option key={item} value={item}>{title(item)}</option>)}</select></label>
      <label><span>Status</span><select value={status} onChange={(event) => setStatus(event.target.value)}><option value="">All statuses</option>{["NEW", "ACKNOWLEDGED", "RESOLVED"].map((item) => <option key={item}>{item}</option>)}</select></label>
      <label><span>From</span><input type="datetime-local" value={dateFrom} onChange={(event) => setDateFrom(event.target.value)} /></label>
      <label><span>To</span><input type="datetime-local" value={dateTo} onChange={(event) => setDateTo(event.target.value)} /></label>
      <button className="button" type="submit">Apply</button>
    </form>
    {loading && !data ? <LoadingState rows={7} /> : error && !data ? <ErrorState onRetry={reload} /> : data && (data.items.length === 0 ? <section className="panel"><EmptyState title="No matching security events" message="Adjust the filters or wait for new defensive signals." /></section> : <div className={styles.layout}>
      <section className={styles.timelinePanel}><div className={styles.timelineHeading}><div><p className="kicker">EVENT TIMELINE</p><h2>{formatNumber(data.total)} events</h2></div><span>Newest first</span></div>{error && <div className="inline-warning">Refresh failed. Showing cached events.</div>}<div className={styles.timeline}>{data.items.map((item) => <button type="button" key={item.id} className={`${styles.event} ${activeSelectedId === item.id ? styles.selected : ""}`} onClick={() => setSelectedId(item.id)}><i className={styles.dot} /><time>{formatDateTime(item.timestamp)}<small>{formatRelativeTime(item.timestamp)}</small></time><div><span className={`severity severity--${item.severity.toLowerCase()}`}>{item.severity}</span><strong>{title(item.alert_type)}</strong><p>{item.description}</p><small className="mono">{item.source_ip ?? "Unknown source"} → {item.destination_ip ?? "Not applicable"}</small></div><b>{item.risk_score}</b></button>)}</div></section>
      <aside className={styles.detailPanel}>{activeSelectedId !== null && <EventDetail eventId={activeSelectedId} />}</aside>
    </div>)}
  </>;
}
