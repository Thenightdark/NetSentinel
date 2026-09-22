"use client";

import { useApiData } from "@/hooks/use-api-data";
import { AgentPageResponse } from "@/lib/api";

export function AgentFilter({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const { data } = useApiData<AgentPageResponse>("/api/agents");
  return (
    <label>
      <span>Collector</span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        <option value="">All collectors</option>
        {data?.items.map((agent) => (
          <option key={agent.agent_id} value={agent.agent_id}>
            {agent.hostname} · {agent.status.toLowerCase()}
          </option>
        ))}
      </select>
    </label>
  );
}
