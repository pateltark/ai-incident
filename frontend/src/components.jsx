// Small shared pieces: badges, time helpers, the error chart.

export const hhmm = (iso) => (iso ? iso.slice(11, 16) : "-");
export const stamp = (iso) => (iso ? iso.slice(0, 19).replace("T", " ") + " UTC" : "-");

export function timeAgo(iso) {
  if (!iso) return "-";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function Badge({ kind, children }) {
  return <span className={`badge ${kind}`}>{String(children).toUpperCase()}</span>;
}

export const SeverityBadge = ({ value }) => <Badge kind={`sev-${value}`}>{value}</Badge>;
export const StatusBadge = ({ value }) => <Badge kind={`st-${value}`}>{value}</Badge>;

export function ErrorChart({ data, markAt }) {
  if (!data || !data.length) return <div className="muted">No logs found for this window.</div>;

  const W = 640, H = 150, left = 28, bottom = 22, top = 10;
  const max = Math.max(1, ...data.map((d) => d.errors));
  const bw = (W - left) / data.length;
  const y = (v) => H - bottom - (v / max) * (H - bottom - top);

  let markIdx = -1;
  if (markAt) {
    const t = new Date(markAt).getTime();
    markIdx = data.findIndex((d) => new Date(d.minute).getTime() + 60000 > t);
  }
  const ticks = [0, Math.floor(data.length / 2), data.length - 1];

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="chart" role="img" aria-label="Errors per minute">
      <line x1={left} x2={W} y1={H - bottom} y2={H - bottom} stroke="var(--line)" />
      <text x={left - 6} y={H - bottom + 4} className="axis" textAnchor="end">0</text>
      <text x={left - 6} y={y(max) + 4} className="axis" textAnchor="end">{max}</text>
      {data.map((d, i) =>
        d.errors > 0 ? (
          <rect key={d.minute} x={left + i * bw + 1} y={y(d.errors)} width={Math.max(bw - 2, 1)}
                height={H - bottom - y(d.errors)} rx="2" fill="var(--red)" />
        ) : null
      )}
      {markIdx >= 0 && (
        <g>
          <line x1={left + markIdx * bw + bw / 2} x2={left + markIdx * bw + bw / 2}
                y1={top} y2={H - bottom} stroke="var(--blue)" strokeDasharray="4 3" />
          <text x={left + markIdx * bw + bw / 2 + 4} y={top + 8} className="axis" fill="var(--blue)">opened</text>
        </g>
      )}
      {ticks.map((i) => (
        <text key={i} x={left + i * bw} y={H - 6} className="axis">{hhmm(data[i].minute)}</text>
      ))}
    </svg>
  );
}
