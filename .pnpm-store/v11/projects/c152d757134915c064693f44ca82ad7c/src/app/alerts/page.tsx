"use client";

import { useState } from "react";
import { EmptyState, ErrorState, LoadingState } from "@/components/page-states";
import { AgentFilter } from "@/components/agent-filter";
import { SectionHeader } from "@/components/section-header";
import { useApiData } from "@/hooks/use-api-data";
import {
  AlertStatus,
  PageResponse,
  SecurityAlert,
  updateAlertStatus,
} from "@/lib/api";
import { formatNumber, formatRelativeTime } from "@/lib/format";

const workflowStates: AlertStatus[] = ["NEW", "ACKNOWLEDGED", "RESOLVED"];

export default function AlertsPage() {
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [agentId, setAgentId] = useState("");
  const [updatingId, setUpdatingId] = useState<number | null>(null);
  const [updateError, setUpdateError] = useState(false);
  const params = new URLSearchParams({ limit: "100" });
  if (severity) params.set("severity", severity);
  if (status) params.set("status", status);
  if (agentId) params.set("agent_id", agentId);
  const { data, loading, error, reload } = useApiData<PageResponse<SecurityAlert>>(
    `/api/alerts?${params}`,
  );

  async function changeStatus(alertId: number, nextStatus: AlertStatus) {
    setUpdatingId(alertId);
    setUpdateError(false);
    try {
      await updateAlertStatus(alertId, nextStatus);
      reload();
    } catch {
      setUpdateError(true);
    } finally {
      setUpdatingId(null);
    }
  }

  return <>
    <SectionHeader eyebrow="DETECTION / ALERTS" title="Security alerts" description="Prioritized defensive findings with explainable risk scores." />
    <div className="filter-bar">
      <AgentFilter value={agentId} onChange={setAgentId} />
      <label><span>Severity</span><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">All severities</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option><option value="INFO">Info</option></select></label>
      <label><span>Status</span><select value={status} onChange={(event) => setStatus(event.target.value)}><option value="">All statuses</option>{workflowStates.map((state) => <option key={state} value={state}>{state.replaceAll("_", " ")}</option>)}</select></label>
    </div>
    {updateError && <div className="inline-warning">The alert status could not be updated. Try again.</div>}
    {loading && !data ? <LoadingState rows={6} /> : error && !data ? <ErrorState onRetry={reload} /> : data && <section className="panel data-panel">
      <div className="panel-header"><div><p className="kicker">ALERT QUEUE</p><h2>{formatNumber(data.total)} security alerts</h2></div><span className="panel-meta">Showing {data.items.length}</span></div>
      {error && <div className="inline-warning">Refresh failed. Showing the last successful response.</div>}
      {data.items.length === 0 ? <EmptyState title="No matching alerts" message="No security alerts match the selected filters." /> : <div className="alert-cards">{data.items.map((alert) => <article className="alert-card" key={alert.id}>
        <div className="alert-card-head">
          <span className={`severity severity--${alert.severity.toLowerCase()}`}>{alert.severity}</span>
          <span className={`risk-score risk-score--${alert.severity.toLowerCase()}`} aria-label={`Risk score ${alert.risk_score} out of 100`}>{alert.risk_score}<small>/100</small></span>
          <label className="status-control"><span className="sr-only">Status for {alert.alert_type.replaceAll("_", " ")}</span><select value={alert.status} disabled={updatingId === alert.id} onChange={(event) => changeStatus(alert.id, event.target.value as AlertStatus)}>{workflowStates.map((state) => <option key={state} value={state}>{state.replaceAll("_", " ")}</option>)}</select></label>
          <time>{formatRelativeTime(alert.timestamp)}</time>
        </div>
        <h2>{alert.alert_type.replaceAll("_", " ")}</h2>
        <p>{alert.description}</p>
        <div className="alert-route"><span className="mono">{alert.source_ip ?? "Unknown source"}</span><i>→</i><span className="mono">{alert.destination_ip ?? "Not applicable"}</span></div>
      </article>)}</div>}
    </section>}
  </>;
}
