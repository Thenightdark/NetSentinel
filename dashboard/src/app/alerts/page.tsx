"use client";

import { useState } from "react";
import { EmptyState, ErrorState, LoadingState } from "@/components/page-states";
import { SectionHeader } from "@/components/section-header";
import { useApiData } from "@/hooks/use-api-data";
import { PageResponse, SecurityAlert } from "@/lib/api";
import { formatNumber, formatRelativeTime } from "@/lib/format";

export default function AlertsPage() {
  const [severity, setSeverity] = useState(""); const [status, setStatus] = useState("");
  const params = new URLSearchParams({ limit: "100" }); if (severity) params.set("severity", severity); if (status) params.set("status", status);
  const { data, loading, error, reload } = useApiData<PageResponse<SecurityAlert>>(`/api/alerts?${params}`);
  return <><SectionHeader eyebrow="DETECTION / ALERTS" title="Security alerts" description="Defensive findings generated from observed network behavior." /><div className="filter-bar"><label><span>Severity</span><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label><label><span>Status</span><select value={status} onChange={(event) => setStatus(event.target.value)}><option value="">All statuses</option><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option></select></label></div>{loading && !data ? <LoadingState rows={6} /> : error && !data ? <ErrorState onRetry={reload} /> : data && <section className="panel data-panel"><div className="panel-header"><div><p className="kicker">ALERT QUEUE</p><h2>{formatNumber(data.total)} security alerts</h2></div><span className="panel-meta">Showing {data.items.length}</span></div>{error && <div className="inline-warning">Refresh failed. Showing the last successful response.</div>}{data.items.length === 0 ? <EmptyState title="No matching alerts" message="No security alerts match the selected filters." /> : <div className="alert-cards">{data.items.map((alert) => <article className="alert-card" key={alert.id}><div className="alert-card-head"><span className={`severity severity--${alert.severity.toLowerCase()}`}>{alert.severity}</span><span className="alert-status">{alert.status}</span><time>{formatRelativeTime(alert.timestamp)}</time></div><h2>{alert.alert_type.replaceAll("_", " ")}</h2><p>{alert.description}</p><div className="alert-route"><span className="mono">{alert.source_ip ?? "Unknown source"}</span><i>→</i><span className="mono">{alert.destination_ip ?? "Unknown destination"}</span></div></article>)}</div>}</section>}</>;
}

