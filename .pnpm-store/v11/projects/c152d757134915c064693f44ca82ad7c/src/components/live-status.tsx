"use client";

import { useLiveFlowUpdates, type LiveConnectionState } from "@/hooks/use-live-flow-updates";

export function LiveStatus({ state: suppliedState }: { state?: LiveConnectionState }) {
  const ownState = useLiveFlowUpdates(undefined, suppliedState === undefined);
  const state = suppliedState ?? ownState;
  const label = state === "connected" ? "Live" : state === "reconnecting" ? "Reconnecting" : state;
  return <div className={`live-status live-status--${state}`} title={`Live stream: ${label}`}><span />{label}</div>;
}
