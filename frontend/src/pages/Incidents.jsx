import { useState } from "react";
import { Link } from "react-router-dom";
import { api, usePoll } from "../api.js";
import { SeverityBadge, StatusBadge, stamp, timeAgo } from "../components.jsx";

export default function Incidents() {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [service, setService] = useState("");

  const { data, error } = usePoll(() => api.incidents({ status, severity, service }), 5000, [status, severity, service]);
  const { data: svc } = usePoll(() => api.services(), 30000);

  return (
    <>
      <div className="page-head">
        <h1>Incidents</h1>
        <div className="filters">
          <select aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All status</option>
            <option value="open">Open</option>
            <option value="resolved">Resolved</option>
          </select>
          <select aria-label="Severity" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All severity</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select aria-label="Service" value={service} onChange={(e) => setService(e.target.value)}>
            <option value="">All services</option>
            {(svc?.services || []).map((s) => (
              <option key={s.id} value={s.name}>{s.name}</option>
            ))}
          </select>
        </div>
      </div>

      {error && <div className="error">Could not load incidents: {error}</div>}

      <div className="card table-wrap">
        <table>
          <thead>
            <tr><th>ID</th><th>Title</th><th>Service</th><th>Rule</th><th>Severity</th><th>Status</th><th>AI</th><th>Started</th></tr>
          </thead>
          <tbody>
            {(data || []).map((i) => (
              <tr key={i.id}>
                <td className="mono">#{i.id}</td>
                <td><Link to={`/incidents/${i.id}`} className="rowlink">{i.title}</Link></td>
                <td>{i.service}</td>
                <td className="mono muted">{i.rule}</td>
                <td><SeverityBadge value={i.severity} /></td>
                <td><StatusBadge value={i.status} /></td>
                <td className="muted">{i.ai_confidence || "-"}</td>
                <td className="muted" title={stamp(i.started_at)}>{timeAgo(i.started_at)}</td>
              </tr>
            ))}
            {data && data.length === 0 && (
              <tr><td colSpan="8" className="muted empty">No incidents match these filters.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
