"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { LiveUpdate } from "@/lib/api";

export type LiveConnectionState = "connecting" | "connected" | "reconnecting" | "offline";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000/ws/live";

export function useLiveFlowUpdates(onUpdate?: (update: LiveUpdate) => void, enabled = true) {
  const [state, setState] = useState<LiveConnectionState>("connecting");
  const updateHandler = useRef(onUpdate);

  useEffect(() => {
    updateHandler.current = onUpdate;
  }, [onUpdate]);

  const handleMessage = useCallback((event: MessageEvent<string>) => {
    try {
      const message = JSON.parse(event.data) as { type?: string };
      if (message.type === "live.update") updateHandler.current?.(message as LiveUpdate);
    } catch {
      // Ignore malformed or forward-compatible messages without interrupting the stream.
    }
  }, []);

  useEffect(() => {
    if (!enabled) return;
    let socket: WebSocket | null = null;
    let reconnectTimer: number | null = null;
    let heartbeatTimer: number | null = null;
    let stopped = false;
    let attempts = 0;

    const connect = () => {
      if (stopped) return;
      setState(attempts === 0 ? "connecting" : "reconnecting");
      socket = new WebSocket(WS_URL);
      socket.onopen = () => {
        attempts = 0;
        setState("connected");
        heartbeatTimer = window.setInterval(() => {
          if (socket?.readyState === WebSocket.OPEN) socket.send("ping");
        }, 20_000);
      };
      socket.onmessage = handleMessage;
      socket.onerror = () => socket?.close();
      socket.onclose = () => {
        if (heartbeatTimer !== null) window.clearInterval(heartbeatTimer);
        heartbeatTimer = null;
        if (stopped) return;
        attempts += 1;
        setState(attempts >= 6 ? "offline" : "reconnecting");
        const delay = Math.min(1_000 * 2 ** (attempts - 1), 30_000);
        reconnectTimer = window.setTimeout(connect, delay);
      };
    };

    connect();
    return () => {
      stopped = true;
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
      if (heartbeatTimer !== null) window.clearInterval(heartbeatTimer);
      socket?.close(1000, "Dashboard disconnected");
    };
  }, [enabled, handleMessage]);

  return state;
}
