import { useCallback, useEffect, useState } from "react";

async function req(path, opts = {}) {
  const res = await fetch("/api" + path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      msg = (await res.json()).detail || msg;
    } catch {}
    throw new Error(msg);
  }
  return res.json();
}

const qs = (p = {}) => {
  const q = new URLSearchParams();
  Object.entries(p).forEach(([k, v]) => v !== "" && v != null && q.set(k, v));
  const s = q.toString();
  return s ? "?" + s : "";
};

export const api = {
  incidents: (p) => req("/incidents" + qs(p)),
  incident: (id) => req(`/incidents/${id}`),
  resolve: (id, body) => req(`/incidents/${id}/resolve`, { method: "POST", body: JSON.stringify(body) }),
  investigate: (id) => req(`/incidents/${id}/investigate`, { method: "POST" }),
  logs: (p) => req("/logs" + qs(p)),
  live: (p) => req("/live" + qs(p)),
  ingest: () => req("/ingest/status"),
  services: () => req("/services"),
  rules: () => req("/rules"),
};

/** Calls fn() now and every `ms`, returns { data, error, reload }. */
export function usePoll(fn, ms, deps = []) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    let alive = true;
    const run = async () => {
      try {
        const d = await fn();
        if (alive) {
          setData(d);
          setError(null);
        }
      } catch (e) {
        if (alive) setError(e.message);
      }
    };
    run();
    const t = setInterval(run, ms);
    return () => {
      alive = false;
      clearInterval(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick, ms]);

  return { data, error, reload };
}
