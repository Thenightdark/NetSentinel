"use client";

import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { HistoricalStats } from "@/lib/api";
import { formatBytes } from "@/lib/format";
import { EmptyState } from "./page-states";

const tooltipStyle = {
  background: "#0c1924",
  border: "1px solid #203647",
  borderRadius: 10,
};

function labelFor(timestamp: string, bucketSeconds: number) {
  const date = new Date(timestamp);
  if (bucketSeconds < 3600) {
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  if (bucketSeconds === 3600) {
    return date.toLocaleTimeString([], { hour: "2-digit" });
  }
  return date.toLocaleDateString([], { weekday: "short", hour: "2-digit" });
}

function normalized(data: HistoricalStats) {
  return data.items.map((point) => ({
    ...point,
    label: labelFor(point.timestamp, data.bucket_seconds),
  }));
}

export function HistoricalTrafficChart({ data }: { data: HistoricalStats }) {
  if (!data.items.some((point) => point.bytes_uploaded || point.bytes_downloaded)) {
    return <EmptyState title="No traffic in this range" message="Upload and download history will appear as completed flows arrive." />;
  }
  return (
    <div className="history-chart">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={normalized(data)} margin={{ top: 8, right: 12, bottom: 0, left: 6 }}>
          <defs>
            <linearGradient id="historyUpload" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#48a4ff" stopOpacity={0.42} /><stop offset="100%" stopColor="#48a4ff" stopOpacity={0.03} /></linearGradient>
            <linearGradient id="historyDownload" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#35e6c4" stopOpacity={0.42} /><stop offset="100%" stopColor="#35e6c4" stopOpacity={0.03} /></linearGradient>
          </defs>
          <CartesianGrid stroke="#122533" strokeDasharray="3 5" vertical={false} />
          <XAxis dataKey="label" axisLine={false} tickLine={false} minTickGap={30} tick={{ fill: "#678491", fontSize: 12 }} />
          <YAxis axisLine={false} tickLine={false} width={62} tickFormatter={(value: number) => formatBytes(value)} tick={{ fill: "#678491", fontSize: 12 }} />
          <Tooltip contentStyle={tooltipStyle} formatter={(value) => formatBytes(Number(value))} />
          <Legend iconType="circle" wrapperStyle={{ fontSize: 12, color: "#8da6b0" }} />
          <Area name="Uploaded" type="monotone" dataKey="bytes_uploaded" stackId="traffic" stroke="#48a4ff" strokeWidth={2} fill="url(#historyUpload)" />
          <Area name="Downloaded" type="monotone" dataKey="bytes_downloaded" stackId="traffic" stroke="#35e6c4" strokeWidth={2} fill="url(#historyDownload)" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

export function HistoricalActivityChart({ data }: { data: HistoricalStats }) {
  if (!data.items.some((point) => point.flow_count || point.active_hosts || point.alerts)) {
    return <EmptyState title="No activity in this range" message="Flow, host, and alert history will appear after telemetry is ingested." />;
  }
  return (
    <div className="history-chart">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={normalized(data)} margin={{ top: 8, right: 8, bottom: 0, left: -12 }}>
          <CartesianGrid stroke="#122533" strokeDasharray="3 5" vertical={false} />
          <XAxis dataKey="label" axisLine={false} tickLine={false} minTickGap={30} tick={{ fill: "#678491", fontSize: 12 }} />
          <YAxis yAxisId="activity" allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: "#678491", fontSize: 12 }} />
          <YAxis yAxisId="alerts" orientation="right" allowDecimals={false} axisLine={false} tickLine={false} width={30} tick={{ fill: "#678491", fontSize: 12 }} />
          <Tooltip contentStyle={tooltipStyle} />
          <Legend iconType="circle" wrapperStyle={{ fontSize: 12, color: "#8da6b0" }} />
          <Line yAxisId="activity" name="Flows" type="monotone" dataKey="flow_count" stroke="#48a4ff" strokeWidth={2} dot={false} />
          <Line yAxisId="activity" name="Active hosts" type="monotone" dataKey="active_hosts" stroke="#7cf06d" strokeWidth={2} dot={false} />
          <Line yAxisId="alerts" name="Alerts" type="monotone" dataKey="alerts" stroke="#ffb84d" strokeWidth={2} dot={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
