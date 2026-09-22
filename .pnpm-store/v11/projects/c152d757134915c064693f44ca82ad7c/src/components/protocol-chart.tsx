"use client";

import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { EmptyState } from "./page-states";

const colors = ["#35e6c4", "#7cf06d", "#48a4ff", "#ffb84d", "#b78cff", "#ff718d"];

export function ProtocolChart({ data }: { data: { protocol: string; flow_count: number }[] }) {
  if (data.length === 0) return <EmptyState title="No protocol data" message="Protocol distribution appears after completed flows are ingested." />;
  const total = data.reduce((sum, item) => sum + item.flow_count, 0);
  return <div className="protocol-layout"><div className="donut"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={data} dataKey="flow_count" nameKey="protocol" innerRadius="64%" outerRadius="88%" paddingAngle={3} stroke="none">{data.map((item, index) => <Cell key={item.protocol} fill={colors[index % colors.length]} />)}</Pie><Tooltip contentStyle={{ background: "#0c1924", border: "1px solid #203647", borderRadius: 10 }} /></PieChart></ResponsiveContainer><div className="donut-label"><strong>{total}</strong><span>flows</span></div></div><ul className="legend">{data.slice(0, 6).map((item, index) => <li key={item.protocol}><i style={{ backgroundColor: colors[index % colors.length] }} /><span>{item.protocol}</span><strong>{Math.round((item.flow_count / total) * 100)}%</strong></li>)}</ul></div>;
}

