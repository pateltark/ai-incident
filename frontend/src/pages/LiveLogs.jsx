import { useEffect, useRef, useState } from "react";
import { api, usePoll } from "../api.js";

const MAX_LINES = 500;

export default function LiveLogs() {
  const [service, setService] = useState("");
  const [level, setLevel] = useState("");
  const [paused, setPaused] = useState(false);
  const [lines, setLines] = useState([]);
  const [error, setError] = useState("");
  const cursor = useRef(null);
  const pausedRef = useRef(false);
  const box = useRef(null);
  const { data: svc } = usePoll(() => api.services(), 30000);

  pausedRef.current = paused;

  useEffect(() => {
    cursor.current = null;
    setLines([]);
    let alive = true;

    const tick = async () => {
      if (pausedRef.current) return;
      try {
        const r = await api.logs({ service, level, after: cursor.current, limit: 200 });
        if (!alive) return;
        setError("");
        if (r.logs.length) {
          cursor.current = r.cursor;
          setLines((prev) => [...prev, ...r.logs].slice(-MAX_LINES));
        }
      } catch (e) {
        if (alive) setError(e.message);
      }
    };

    tick();
    const t = setInterval(tick, 2000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [service, level]);

  // stick to the bottom while new lines arrive
  useEffect(() => {
    if (!paused && box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [lines, paused]);

  return (
    <>
      <div className="page-head">
        <h1>Live logs</h1>
        <div className="filters">
          <select aria-label="Service" value={service} onChange={(e) => setService(e.target.value)}>
            <option value="">All services</option>
            {(svc?.services || []).map((s) => <option key={s.id} value={s.name}>{s.name}</option>)}
          </select>
          <select aria-label="Level" value={level} onChange={(e) => setLevel(e.target.value)}>
            <option value="">All levels</option>
            <option value="ERROR">ERROR</option>
            <option value="WARN">WARN</option>
            <option value="INFO">INFO</option>
          </select>
          <button type="button" className="btn ghost" onClick={() => setPaused((p) => !p)}>
            {paused ? "Resume" : "Pause"}
          </button>
        </div>
      </div>
      {error && <div className="error">Could not load logs: {error}</div>}
      <div className="terminal mono" ref={box}>
        {lines.length === 0 && <span className="muted">Waiting for logs...</span>}
        {lines.map((l, i) => (
          <div key={i}>
            <span className="muted">{l.ts.slice(11, 23)}</span>{" "}
            <span className="svc">[{l.service}]</span>{" "}
            <span className={`lvl ${l.level}`}>{l.level}</span> {l.message}
          </div>
        ))}
      </div>
    </>
  );
}
