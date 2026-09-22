"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Background,
  BackgroundVariant,
  Controls,
  MarkerType,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import { AgentFilter } from "@/components/agent-filter";
import { EmptyState, ErrorState, LoadingState } from "@/components/page-states";
import { SectionHeader } from "@/components/section-header";
import { useApiData } from "@/hooks/use-api-data";
import { NetworkMapNode, NetworkMapResponse } from "@/lib/api";
import { formatBytes, formatNumber } from "@/lib/format";
import styles from "./network-map.module.css";

const nodeColors: Record<NetworkMapNode["kind"], string> = {
  collector: "#123c3a",
  lan: "#102c3c",
  external: "#221e35",
  lan_group: "#172831",
  external_group: "#25232c",
};

function positionNodes(items: NetworkMapNode[]): Node[] {
  const columns: Record<string, NetworkMapNode[]> = { collector: [], lan: [], external: [], group: [] };
  for (const item of items) {
    if (item.kind.endsWith("_group")) columns.group.push(item);
    else columns[item.kind].push(item);
  }
  const positions = { collector: 40, lan: 320, external: 680, group: 990 };
  return Object.entries(columns).flatMap(([column, nodes]) => nodes.map((item, index) => ({
    id: item.id,
    position: { x: positions[column as keyof typeof positions], y: 45 + index * 112 },
    data: {
      label: <div className={styles.nodeContent}>
        <span>{item.kind.replaceAll("_", " ")}</span>
        <strong>{item.label}</strong>
        {item.ip_address && item.label !== item.ip_address && <small>{item.ip_address}</small>}
        <em>{formatNumber(item.connections)} flows · {formatBytes(item.bytes)}</em>
        {item.host_id && <b>Open host →</b>}
      </div>,
      mapNode: item,
    },
    style: {
      background: nodeColors[item.kind],
      border: `1px solid ${item.host_id ? "#35e6c4" : "#315064"}`,
      borderRadius: 10,
      color: "#e8f4f5",
      cursor: item.host_id ? "pointer" : "default",
      padding: 0,
      width: 205,
    },
  })));
}

export default function NetworkMapPage() {
  const router = useRouter();
  const [minutes, setMinutes] = useState("60");
  const [agentId, setAgentId] = useState("");
  const [externalLimit, setExternalLimit] = useState("12");
  const params = new URLSearchParams({ minutes, max_external_nodes: externalLimit });
  if (agentId) params.set("agent_id", agentId);
  const { data, loading, error, reload } = useApiData<NetworkMapResponse>(`/api/map?${params}`, 30_000);

  const graph = useMemo(() => {
    if (!data) return { nodes: [], edges: [] };
    const nodes = positionNodes(data.nodes);
    const largest = Math.max(1, ...data.edges.map((edge) => edge.bytes));
    const edges: Edge[] = data.edges.map((edge) => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      label: `${formatNumber(edge.connections)} flows`,
      labelStyle: { fill: "#7895a1", fontSize: 10 },
      labelBgStyle: { fill: "#07111a", fillOpacity: 0.88 },
      markerEnd: { type: MarkerType.ArrowClosed, color: "#3a7181" },
      style: {
        stroke: "#3a7181",
        strokeWidth: 1 + Math.sqrt(edge.bytes / largest) * 4,
        opacity: 0.72,
      },
      data: edge,
    }));
    return { nodes, edges };
  }, [data]);

  return <>
    <SectionHeader eyebrow="NETWORK / TOPOLOGY" title="Network map" description="A bounded view of aggregated flows between collectors, LAN hosts, and external destinations. Grouped nodes keep high-volume environments readable." />
    <div className="filter-bar">
      <AgentFilter value={agentId} onChange={setAgentId} />
      <label><span>Time window</span><select value={minutes} onChange={(event) => setMinutes(event.target.value)}><option value="60">Last hour</option><option value="1440">Last 24 hours</option><option value="10080">Last 7 days</option></select></label>
      <label><span>External detail</span><select value={externalLimit} onChange={(event) => setExternalLimit(event.target.value)}><option value="8">Top 8 destinations</option><option value="12">Top 12 destinations</option><option value="20">Top 20 destinations</option></select></label>
      {data && <div className={styles.summary}><strong>{data.nodes.length}</strong> nodes <i /> <strong>{data.edges.length}</strong> connections</div>}
    </div>
    {loading && !data ? <LoadingState rows={7} /> : error && !data ? <ErrorState onRetry={reload} /> : data && (data.nodes.length === 0 ? <section className="panel"><EmptyState title="No topology data" message="The map appears after collectors submit completed network flows." /></section> : <section className={styles.shell}>
      {error && <div className="inline-warning">Refresh failed. Showing the last successful topology.</div>}
      <div className={styles.legend}><span><i className={styles.collector} />Collector</span><span><i className={styles.lan} />LAN host</span><span><i className={styles.external} />External</span><span><i className={styles.group} />Grouped</span><small>Edge thickness represents aggregated bytes</small></div>
      <div className={styles.canvas}>
        <ReactFlow
          nodes={graph.nodes}
          edges={graph.edges}
          fitView
          fitViewOptions={{ padding: 0.18 }}
          minZoom={0.2}
          maxZoom={1.8}
          nodesConnectable={false}
          onNodeClick={(_event, node) => {
            const mapNode = node.data.mapNode as NetworkMapNode;
            if (mapNode.host_id) router.push(`/hosts/${mapNode.host_id}`);
          }}
        >
          <Background variant={BackgroundVariant.Dots} gap={24} size={1} color="#17303d" />
          <Controls showInteractive={false} />
          <MiniMap pannable zoomable nodeColor={(node) => String(node.style?.background ?? "#17303d")} maskColor="#061019bb" />
        </ReactFlow>
      </div>
    </section>)}
  </>;
}
