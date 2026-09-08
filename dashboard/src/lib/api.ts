export const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export type NetworkFlow = {
  id: number;
  source_ip: string;
  destination_ip: string;
  source_port: number | null;
  destination_port: number | null;
  protocol: string;
  bytes: number;
  packet_count: number;
  first_seen: string;
  last_seen: string;
};

export type Host = {
  id: number;
  ip_address: string;
  hostname: string | null;
  first_seen: string;
  last_seen: string;
  total_bytes: number;
  total_connections: number;
  is_active: boolean;
};

export type SecurityAlert = {
  id: number;
  timestamp: string;
  severity: string;
  alert_type: string;
  source_ip: string | null;
  destination_ip: string | null;
  description: string;
  status: string;
};

export type PageResponse<T> = {
  items: T[];
  total: number;
  limit: number;
  offset: number;
};

export type StatsSummary = {
  hosts: number;
  flows: number;
  alerts: number;
  open_alerts: number;
  total_bytes: number;
  total_packets: number;
  protocols: { protocol: string; flow_count: number }[];
};

export type LiveSummary = {
  throughput_bps: number;
  active_connections: number;
  total_flows: number;
  total_bytes: number;
  total_packets: number;
  protocols: { protocol: string; flow_count: number }[];
};

export type LiveUpdate = {
  type: "live.update";
  timestamp: string;
  summary: LiveSummary;
  recent_flows: NetworkFlow[];
  completed_flows: NetworkFlow[];
};

export async function fetchApi<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    cache: "no-store",
    headers: { Accept: "application/json" },
    signal,
  });
  if (!response.ok) {
    throw new Error(`API request failed with status ${response.status}`);
  }
  return response.json() as Promise<T>;
}
