"use client";

import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { HostTimelinePoint } from "@/lib/api";
import { formatBytes } from "@/lib/format";
import { EmptyState } from "./page-states";

function chartData(data: HostTimelinePoint[]) {
  return data.map((point) => ({
    ...point,
    label: new Intl.DateTimeFormat("en", { hour: "2-digit", minute: "2-digit" })
      .format(new Date(point.timestamp)),
  }));
}

const tooltipStyle = {
  background: "#0c1924",
  border: "1px solid #203647",
  borderRadius: 10,
};

export function HostTrafficChart({ data }: { data: HostTimelinePoint[] }) {
  if (!data.some((point) => point.bytes > 0)) {
    return <EmptyState title="No recent traffic" message="Completed flow volume from the last 24 hours will appear here." />;
  }
  return (
    <div className="host-chart">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={chartData(data)} margin={{ top: 8, right: 10, bottom: 0, left: 4 }}>
          <defs><linearGradient id="hostTrafficFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#35e6c4" stopOpacity={0.34} /><stop offset="100%" stopColor="#35e6c4" stopOpacity={0} /></linearGradient></defs>
          <CartesianGrid stroke="#122533" strokeDasharray="3 5" vertical={false} />
          <XAxis dataKey="label" axisLine={false} tickLine={false} minTickGap={32} tick={{ fill: "#678491", fontSize: 12 }} />
          <YAxis axisLine={false} tickLine={false} width={62} tickFormatter={(value: number) => formatBytes(value)} tick={{ fill: "#678491", fontSize: 12 }} />
          <Tooltip contentStyle={tooltipStyle} formatter={(value) => [formatBytes(Number(value)), "Traffic"]} />
          <Area type="monotone" dataKey="bytes" stroke="#35e6c4" strokeWidth={2} fill="url(#hostTrafficFill)" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

export function HostConnectionsChart({ data }: { data: HostTimelinePoint[] }) {
  if (!data.some((point) => point.connections > 0)) {
    return <EmptyState title="No recent connections" message="Completed connections from the last 24 hours will appear here." />;
  }
  return (
    <div className="host-chart">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={chartData(data)} margin={{ top: 8, right: 10, bottom: 0, left: -12 }}>
          <CartesianGrid stroke="#122533" strokeDasharray="3 5" vertical={false} />
          <XAxis dataKey="label" axisLine={false} tickLine={false} minTickGap={32} tick={{ fill: "#678491", fontSize: 12 }} />
          <YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: "#678491", fontSize: 12 }} />
          <Tooltip contentStyle={tooltipStyle} />
          <Bar dataKey="connections" name="Connections" fill="#48a4ff" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
