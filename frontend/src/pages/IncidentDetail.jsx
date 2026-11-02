import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, usePoll } from "../api.js";
import { ErrorChart, SeverityBadge, StatusBadge, stamp } from "../components.jsx";

const NO_ANSWER = /^(unable to determine|no specific fix)/i;
const usable = (t) => (t && !NO_ANSWER.test(t.trim()) ? t.trim() : "");

export default function IncidentDetail() {
  const { id } = useParams();
  const { data: inc, error, reload } = usePoll(() => api.incident(id), 4000, [id]);

  const [rootCause, setRootCause] = useState("");
  const [resolution, setResolution] = useState("");
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState("");
  const prefilled = useRef(false);

  // Pre-fill the form once with the AI suggestion (the human can edit it).
  useEffect(() => {
    if (inc?.ai && !prefilled.current) {
      prefilled.current = true;
      setRootCause(usable(inc.ai.root_cause));
      setResolution(usable(inc.ai.solution));
    }
  }, [inc]);

  if (error && !inc) return <div className="error">Could not load incident: {error}</div>;
  if (!inc) return <div className="muted">Loading...</div>;

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setFormError("");
    try {
      await api.resolve(id, { root_cause: rootCause, resolution });
      reload();
    } catch (err) {
      setFormError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const rerun = async () => {
    try {
      await api.investigate(id);
    } catch (err) {
      setFormError(err.message);
    }
  };

  return (
    <>
      <div className="crumbs"><Link to="/incidents">Incidents</Link> / #{inc.id}</div>
      <header className="detail-head">
        <h1>{inc.title}</h1>
        <SeverityBadge value={inc.severity} />
        <StatusBadge value={inc.status} />
        <span className="muted right">#{inc.id} &middot; {inc.service} &middot; {stamp(inc.started_at)}</span>
      </header>

      {/* AI suggestion */}
      <section className="ai-card">
        <div className="ai-head">
          <span className="ai-label">AI SUGGESTION</span>
          {inc.ai?.confidence && <span className="muted">Confidence: {inc.ai.confidence}</span>}
          <button type="button" className="btn ghost right" onClick={rerun}>Re-run investigation</button>
        </div>
        {inc.ai ? (
          <div className="ai-grid">
            <div><div className="label">Symptoms</div><p>{inc.ai.symptoms || inc.symptoms || "-"}</p></div>
            <div><div className="label">Root cause</div><p>{inc.ai.root_cause || "-"}</p></div>
            <div><div className="label">Solution</div><p>{inc.ai.solution || "-"}</p></div>
          </div>
        ) : (
          <p className="muted">No AI report yet. It appears here when the investigation finishes.</p>
        )}
        {inc.ai?.evidence && (
          <details>
            <summary className="label">Evidence cited</summary>
            <pre className="plain">{inc.ai.evidence}</pre>
          </details>
        )}
      </section>

      <div className="two-col">
        <section className="card">
          <h2>Errors per minute</h2>
          <ErrorChart data={inc.timeline} markAt={inc.started_at} />
        </section>
        <section className="card">
          <h2>Similar past incidents</h2>
          {inc.similar.length === 0 ? (
            <p className="muted">No resolved incidents match yet. Resolving this one makes it a reference for the future.</p>
          ) : (
            inc.similar.map((s) => (
              <div key={s.incident_id} className="similar">
                <div>
                  <Link to={`/incidents/${s.incident_id}`}>#{s.incident_id}</Link>
                  <span className="muted"> &middot; {Math.round(s.similarity * 100)}% similar &middot; {s.verified}</span>
                </div>
                <div><span className="label">Cause: </span>{s.root_cause}</div>
                <div><span className="label">Fix: </span>{s.resolution}</div>
              </div>
            ))
          )}
        </section>
      </div>

      <section className="card logbox">
        <h2>Log evidence</h2>
        <div className="loglines mono">
          {inc.log_lines.length === 0 && <span className="muted">No ERROR / WARN lines found near this incident.</span>}
          {inc.log_lines.map((l, i) => (
            <div key={i}>
              <span className="muted">{l.ts.slice(11, 23)}</span>{" "}
              <span className={`lvl ${l.level}`}>{l.level}</span> {l.message}
            </div>
          ))}
        </div>
      </section>

      {/* Resolve form, or the confirmed answer once resolved */}
      {inc.status === "resolved" && inc.confirmed ? (
        <section className="card">
          <h2>Resolved <span className="muted">&middot; {stamp(inc.resolved_at)} &middot; {inc.confirmed.confidence}</span></h2>
          <div className="ai-grid two">
            <div><div className="label">Root cause</div><p>{inc.confirmed.root_cause}</p></div>
            <div><div className="label">Resolution</div><p>{inc.confirmed.resolution}</p></div>
          </div>
        </section>
      ) : (
        <form className="card" onSubmit={submit}>
          <h2>Resolve incident</h2>
          <div className="form-grid">
            <label>Root cause (what was wrong)
              <input value={rootCause} onChange={(e) => setRootCause(e.target.value)} required />
            </label>
            <label>Resolution (what fixed it)
              <input value={resolution} onChange={(e) => setResolution(e.target.value)} required />
            </label>
          </div>
          {formError && <div className="error">{formError}</div>}
          <button className="btn" disabled={busy || !rootCause.trim() || !resolution.trim()}>
            {busy ? "Saving..." : "Mark as resolved"}
          </button>
        </form>
      )}
    </>
  );
}
