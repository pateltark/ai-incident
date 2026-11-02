import { Link } from "react-router-dom";
import { api, usePoll } from "../api.js";
import { timeAgo } from "../components.jsx";

export default function Services() {
  const { data, error } = usePoll(() => api.services(), 10000);
  const mins = data?.window_minutes ?? 15;

  return (
    <>
      <div className="page-head"><h1>Services</h1><span className="muted">last {mins} minutes</span></div>
      {error && <div className="error">Could not load services: {error}</div>}
      <div className="cards">
        {(data?.services || []).map((s) => (
          <section key={s.id} className="card svc-card">
            <div className="svc-head">
              <h2>{s.name}</h2>
              <span className={`dot ${s.status}`} aria-hidden="true" />
              <span className="muted">{s.status === "incident" ? "Incident open" : "Healthy"}</span>
            </div>
            <dl>
              <div><dt>Logs</dt><dd>{s.logs}</dd></div>
              <div><dt>Error rate</dt><dd>{s.error_rate_pct}%</dd></div>
              <div><dt>p95 latency</dt><dd>{s.p95_ms != null ? `${s.p95_ms} ms` : "-"}</dd></div>
              <div><dt>Last log</dt><dd>{timeAgo(s.last_log_at)}</dd></div>
            </dl>
            <Link to={`/incidents`} className="muted">{s.open_incidents} open incident(s)</Link>
          </section>
        ))}
      </div>
    </>
  );
}
