"use client";

import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { EmptyState } from "./page-states";

export type DNSChartPoint = { time: string; requests: number };

export function DNSRequestsChart({ data }: { data: DNSChartPoint[] }) {
  if (!data.some((point) => point.requests > 0)) {
    return <EmptyState title="No DNS requests" message="Passive DNS query metadata from the last hour will appear here." />;
  }
  return <div className="dns-chart"><ResponsiveContainer width="100%" height="100%"><AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -24 }}><defs><linearGradient id="dnsFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#35e6c4" stopOpacity={0.34} /><stop offset="100%" stopColor="#35e6c4" stopOpacity={0} /></linearGradient></defs><CartesianGrid stroke="#122533" strokeDasharray="3 5" vertical={false} /><XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fill: "#678491", fontSize: 11 }} /><YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: "#678491", fontSize: 11 }} /><Tooltip contentStyle={{ background: "#0c1924", border: "1px solid #203647", borderRadius: 10 }} /><Area type="monotone" dataKey="requests" stroke="#35e6c4" strokeWidth={2} fill="url(#dnsFill)" /></AreaChart></ResponsiveContainer></div>;
}
