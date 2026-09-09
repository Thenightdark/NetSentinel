"use client";

import { FormEvent, useState } from "react";
import { EmptyState, ErrorState, LoadingState } from "@/components/page-states";
import { SectionHeader } from "@/components/section-header";
import { useApiData } from "@/hooks/use-api-data";
import { NetworkFlow, PageResponse } from "@/lib/api";
import { endpoint, formatBytes, formatNumber, formatRelativeTime } from "@/lib/format";

function ProcessCell({ flow }: { flow: NetworkFlow }) {
  const label = flow.process_name ?? flow.executable_name ??
    (flow.process_id !== null ? `PID ${flow.process_id}` : null);
  if (!label) return <span className="process-unavailable">Unavailable</span>;
  return (
    <span className="process-cell">
      <strong>{label}</strong>
      <small>
        {flow.process_id !== null && label !== `PID ${flow.process_id}`
          ? `PID ${flow.process_id}`
          : "Process identified by the local OS"}
        {flow.executable_name && flow.executable_name !== label
          ? ` · ${flow.executable_name}`
          : ""}
      </small>
    </span>
  );
}

export default function TrafficPage() {
  const [protocol, setProtocol] = useState("");
  const [ipInput, setIpInput] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  const params = new URLSearchParams({ limit: "100" });
  if (protocol) params.set("protocol", protocol);
  if (sourceIp) params.set("source_ip", sourceIp);
  const { data, loading, error, reload } =
    useApiData<PageResponse<NetworkFlow>>(`/api/flows?${params}`);

  function applyFilters(event: FormEvent) {
    event.preventDefault();
    setSourceIp(ipInput.trim());
  }

  return (
    <>
      <SectionHeader
        eyebrow="NETWORK / FLOWS"
        title="Traffic"
        description="Completed directional flows reported by authorized collectors. Local process details appear when optional correlation is enabled and available."
      />
      <form className="filter-bar" onSubmit={applyFilters}>
        <label>
          <span>Protocol</span>
          <select value={protocol} onChange={(event) => setProtocol(event.target.value)}>
            <option value="">All protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
          </select>
        </label>
        <label className="filter-grow">
          <span>Source IP</span>
          <input
            value={ipInput}
            onChange={(event) => setIpInput(event.target.value)}
            placeholder="e.g. 192.168.1.10"
          />
        </label>
        <button className="button" type="submit">Apply filters</button>
      </form>
      {loading && !data ? (
        <LoadingState rows={7} />
      ) : error && !data ? (
        <ErrorState onRetry={reload} />
      ) : data && (
        <section className="panel data-panel">
          <div className="panel-header">
            <div>
              <p className="kicker">FLOW INVENTORY</p>
              <h2>{formatNumber(data.total)} observed flows</h2>
            </div>
            <span className="panel-meta">Showing {data.items.length}</span>
          </div>
          {error && <div className="inline-warning">Refresh failed. Showing the last successful response.</div>}
          {data.items.length === 0 ? (
            <EmptyState title="No matching flows" message="Adjust the filters or wait for completed flows to arrive." />
          ) : (
            <div className="table-scroll">
              <table>
                <thead><tr><th>Last seen</th><th>Process</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Volume</th><th>Duration</th></tr></thead>
                <tbody>
                  {data.items.map((flow) => (
                    <tr key={flow.id}>
                      <td>{formatRelativeTime(flow.last_seen)}</td>
                      <td><ProcessCell flow={flow} /></td>
                      <td className="mono">{endpoint(flow.source_ip, flow.source_port)}</td>
                      <td className="mono">{endpoint(flow.destination_ip, flow.destination_port)}</td>
                      <td><span className="protocol-pill">{flow.protocol}</span></td>
                      <td>{formatNumber(flow.packet_count)}</td>
                      <td>{formatBytes(flow.bytes)}</td>
                      <td>{Math.max(0, Math.round((new Date(flow.last_seen).getTime() - new Date(flow.first_seen).getTime()) / 1000))}s</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </>
  );
}
