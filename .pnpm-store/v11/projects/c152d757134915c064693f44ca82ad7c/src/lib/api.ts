export const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export type AuthUser = {
  id: number;
  username: string;
  role: string;
};

export type NetworkFlow = {
  id: number;
  agent_id: string | null;
  source_ip: string;
  destination_ip: string;
  source_port: number | null;
  destination_port: number | null;
  protocol: string;
  process_id: number | null;
  process_name: string | null;
  executable_name: string | null;
  bytes: number;
  packet_count: number;
  first_seen: string;
  last_seen: string;
};

export type Host = {
  id: number;
  agent_id: string | null;
  ip_address: string;
  hostname: string | null;
  first_seen: string;
  last_seen: string;
  total_bytes: number;
  total_connections: number;
  is_active: boolean;
};

export type HostDestinationStats = {
  ip_address: string;
  bytes: number;
  connections: number;
};

export type HostPortStats = {
  port: number;
  bytes: number;
  connections: number;
};

export type HostProtocolStats = {
  protocol: string;
  bytes: number;
  connections: number;
};

export type HostTimelinePoint = {
  timestamp: string;
  bytes: number;
  connections: number;
};

export type HostDetail = Host & {
  risk_score: number;
  top_destinations: HostDestinationStats[];
  top_destination_ports: HostPortStats[];
  most_used_protocols: HostProtocolStats[];
  activity_over_time: HostTimelinePoint[];
  recent_flows: NetworkFlow[];
  recent_alerts: SecurityAlert[];
};

export type SecurityAlert = {
  id: number;
  agent_id: string | null;
  timestamp: string;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  risk_score: number;
  alert_type: string;
  source_ip: string | null;
  destination_ip: string | null;
  description: string;
  evidence: Record<string, unknown>;
  status: AlertStatus;
};

export type SecurityEventHost = {
  id: number;
  ip_address: string;
  hostname: string | null;
  first_seen: string;
  last_seen: string;
  total_bytes: number;
  total_connections: number;
  is_active: boolean;
};

export type SecurityEventDetail = SecurityAlert & {
  why_flagged: string;
  related_flows: NetworkFlow[];
  host: SecurityEventHost | null;
  recommended_investigation_steps: string[];
};

export type AlertStatus = "NEW" | "ACKNOWLEDGED" | "RESOLVED";

export type DNSObservation = {
  id: number;
  requesting_host: string;
  queried_domain: string;
  timestamp: string;
  query_type: string;
  response_status: string | null;
  is_response: boolean;
};

export type TopDomain = {
  domain: string;
  query_count: number;
  unique_clients: number;
};

export type PageResponse<T> = {
  items: T[];
  total: number;
  limit: number;
  offset: number;
};

export type CollectorAgent = {
  agent_id: string;
  hostname: string;
  operating_system: string;
  ip_address: string;
  version: string;
  first_seen: string;
  last_seen: string;
  status: "ONLINE" | "OFFLINE";
};

export type AgentPageResponse = {
  items: CollectorAgent[];
  total: number;
};

export type NetworkMapNode = {
  id: string;
  label: string;
  ip_address: string | null;
  kind: "collector" | "lan" | "external" | "lan_group" | "external_group";
  agent_id: string | null;
  host_id: number | null;
  connections: number;
  bytes: number;
  grouped_destinations: number;
};

export type NetworkMapEdge = {
  id: string;
  source: string;
  target: string;
  connections: number;
  bytes: number;
  protocols: string[];
};

export type NetworkMapResponse = {
  window_minutes: number;
  nodes: NetworkMapNode[];
  edges: NetworkMapEdge[];
  aggregated_flow_groups: number;
};

export type DetectionSettings = {
  port_scan_unique_ports: number;
  port_scan_window_seconds: number;
  bandwidth_spike_megabytes: number;
  bandwidth_spike_window_seconds: number;
  connection_spike_connections: number;
  connection_spike_window_seconds: number;
  updated_at: string;
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

export type HistoryRange = "5m" | "1h" | "24h" | "7d";

export type HistoricalMetricPoint = {
  timestamp: string;
  bytes_uploaded: number;
  bytes_downloaded: number;
  flow_count: number;
  active_hosts: number;
  alerts: number;
};

export type HistoricalStats = {
  range: HistoryRange;
  bucket_seconds: number;
  start: string;
  end: string;
  items: HistoricalMetricPoint[];
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
    credentials: "include",
    headers: { Accept: "application/json" },
    signal,
  });
  if (response.status === 401 && typeof window !== "undefined") {
    const returnTo = `${window.location.pathname}${window.location.search}`;
    window.dispatchEvent(new CustomEvent("netsentinel:unauthorized", { detail: returnTo }));
  }
  if (!response.ok) {
    throw new Error(`API request failed with status ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export async function updateAlertStatus(
  alertId: number,
  status: AlertStatus,
): Promise<SecurityAlert> {
  const response = await fetch(`${API_URL}/api/alerts/${alertId}/status`, {
    method: "PATCH",
    credentials: "include",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
  });
  if (!response.ok) {
    throw new Error(`Alert update failed with status ${response.status}`);
  }
  return response.json() as Promise<SecurityAlert>;
}

export async function updateDetectionSettings(
  settings: Omit<DetectionSettings, "updated_at">,
): Promise<DetectionSettings> {
  const response = await fetch(`${API_URL}/api/settings/detection`, {
    method: "PUT",
    credentials: "include",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify(settings),
  });
  if (!response.ok) throw new Error(`Settings update failed with status ${response.status}`);
  return response.json() as Promise<DetectionSettings>;
}

export async function login(username: string, password: string): Promise<AuthUser> {
  const response = await fetch(`${API_URL}/api/auth/login`, {
    method: "POST",
    credentials: "include",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!response.ok) throw new Error("Login failed");
  const body = await response.json() as { user: AuthUser };
  return body.user;
}

export async function getCurrentUser(): Promise<AuthUser | null> {
  const response = await fetch(`${API_URL}/api/auth/me`, {
    cache: "no-store",
    credentials: "include",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) return null;
  return response.json() as Promise<AuthUser>;
}

export async function logout(): Promise<void> {
  await fetch(`${API_URL}/api/auth/logout`, {
    method: "POST",
    credentials: "include",
    headers: { Accept: "application/json" },
  });
}
