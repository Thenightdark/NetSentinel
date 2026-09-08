"use client";

import { useCallback, useEffect, useState } from "react";
import { fetchApi } from "@/lib/api";

export function useApiData<T>(path: string, refreshMs = 15_000) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [revision, setRevision] = useState(0);
  const reload = useCallback(() => {
    setLoading(true);
    setError(false);
    setRevision((value) => value + 1);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    const load = async (signal?: AbortSignal) => {
      try {
        setData(await fetchApi<T>(path, signal));
        setError(false);
      } catch (requestError) {
        if ((requestError as Error).name !== "AbortError") setError(true);
      } finally {
        if (!signal?.aborted) setLoading(false);
      }
    };
    load(controller.signal);
    const interval = window.setInterval(() => load(), refreshMs);
    return () => { controller.abort(); window.clearInterval(interval); };
  }, [path, refreshMs, revision]);

  return { data, loading, error, reload };
}
