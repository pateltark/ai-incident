import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, usePoll } from "../api.js";
import {
  ConfidenceBadge, ErrorChart, LinkedText, SeverityBadge, StatusBadge, stamp,
} from "../components.jsx";

const NO_ANSWER = /^(unable to determine|no specific fix)/i;
const usable = (t) => (t && !NO_ANSWER.test(t.trim()) ? t.trim() : "");

function AiCard({ ai, onRerun, rerunMsg }) {
  return (
    <section className="ai-card">
      <div className="ai-head">
        <span className="ai-label">AI INVESTIGATION</span>
        <ConfidenceBadge value={ai?.confidence} />
        <button type="button" className="btn ghost right" onClick={onRerun}>
          {ai ? "Re-run investigation" : "Run investigation"}
        </button>
      </div>

      {!ai ? (
        <p className="muted">{rerunMsg || "No AI report for this incident yet. It appears here when the agent finishes."}</p>
      ) : (
        <>
          <div className="ai-grid">
            <div><div className="label">Symptoms</div><p><LinkedText text={ai.symptoms} /></p></div>
            <div><div className="label">Root cause (suggested)</div><p><LinkedText text={ai.root_cause} /></p></div>
            <div><div className="label">Solution (suggested)</div><p><LinkedText text={ai.solution} /></p></div>
          </div>
          {ai.evidence_points.length > 0 && (
            <div className="ai-section">
              <div className="label">Evidence behind this</div>
              <ul className="points">{ai.evidence_points.map((e, i) => <li key={i}><LinkedText text={e} /></li>)}</ul>
            </div>
          )}
          {rerunMsg && <p className="muted">{rerunMsg}</p>}
        </>
      )}
    </section>
  );
}

export default function IncidentDetail() {
  const { id } = useParams();
  const { data: inc, error, reload } = usePoll(() => api.incident(id), 4000, [id]);

  const [rootCause, setRootCause] = useState("");
  const [resolution, setResolution] = useState("");
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState("");
  const [rerunMsg, setRerunMsg] = useState("");
  const prefilled = useRef(false);

  // Pre-fill the resolve form once with the AI suggestion (the human edits it).
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
    setFormError("");
    try {
      await api.investigate(id);
      prefilled.current = false;       // use the new suggestion for the form
      setRerunMsg("Investigation started. The report updates here in a few seconds.");
      setTimeout(() => setRerunMsg(""), 20000);
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

      <AiCard ai={inc.ai} onRerun={rerun} rerunMsg={rerunMsg} />
      {formError && <div className="error">{formError}</div>}

      <div className="two-col">
        <section className="card">
          <h2>Errors per minute</h2>
          <ErrorChart data={inc.timeline} markAt={inc.started_at} />
        </section>
        <section className="card">
          <h2>Similar past incidents</h2>
          {inc.similar.length === 0 ? (
            <p className="muted">No resolved incidents matched. Resolving this one makes it a reference for the future.</p>
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

      {inc.status === "resolved" && inc.confirmed ? (
        <section className="card">
          <h2>Resolved <span className="muted">&middot; {stamp(inc.resolved_at)} &middot; {inc.confirmed.confidence}</span></h2>
          <div className="ai-grid two">
            <div><div className="label">Root cause (confirmed)</div><p>{inc.confirmed.root_cause}</p></div>
            <div><div className="label">Resolution (confirmed)</div><p>{inc.confirmed.resolution}</p></div>
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
          <button className="btn" disabled={busy || !rootCause.trim() || !resolution.trim()}>
            {busy ? "Saving..." : "Mark as resolved"}
          </button>
        </form>
      )}
    </>
  );
}
