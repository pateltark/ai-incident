import { api, usePoll } from "../api.js";
import { SeverityBadge } from "../components.jsx";

export default function Rules() {
  const { data, error } = usePoll(() => api.rules(), 600000);
  if (error) return <div className="error">Could not load rules: {error}</div>;
  if (!data) return <div className="muted">Loading...</div>;

  return (
    <>
      <div className="page-head"><h1>Detection rules</h1><span className="muted">read-only</span></div>

      <h2 className="section">Built-in</h2>
      <div className="card table-wrap"><table>
        <thead><tr><th>Rule</th><th>Fires when</th><th>Severity</th></tr></thead>
        <tbody>{data.builtin.map((r) => (
          <tr key={r.rule}><td className="mono">{r.rule}</td><td>{r.description}</td><td><SeverityBadge value={r.severity} /></td></tr>
        ))}</tbody>
      </table></div>

      <h2 className="section">Log pattern rules</h2>
      <div className="card table-wrap"><table>
        <thead><tr><th>Rule</th><th>Pattern</th><th>Threshold</th><th>Severity</th></tr></thead>
        <tbody>{data.pattern.map((r) => (
          <tr key={r.rule}>
            <td className="mono">{r.rule}</td>
            <td className="mono muted wrap">{r.regex}</td>
            <td>{r.min_count}+ in {r.minutes} min</td>
            <td><SeverityBadge value={r.severity} /></td>
          </tr>
        ))}</tbody>
      </table></div>

      <h2 className="section">Metric rules</h2>
      <div className="card table-wrap"><table>
        <thead><tr><th>Rule</th><th>Metric</th><th>Condition</th><th>Severity</th></tr></thead>
        <tbody>{data.metric.map((r) => (
          <tr key={r.rule}>
            <td className="mono">{r.rule}</td>
            <td className="mono muted">{r.metric}</td>
            <td>{r.kind} {r.threshold} over {r.minutes} min</td>
            <td><SeverityBadge value={r.severity} /></td>
          </tr>
        ))}</tbody>
      </table></div>
    </>
  );
}
