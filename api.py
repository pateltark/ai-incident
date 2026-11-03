"""
api.py  -  FastAPI backend for the AI Incident Copilot UI.

Put this file next to db.py (D:\\dc\\ai-incident) and run:
    pip install fastapi uvicorn
    uvicorn api:app --reload --port 8000

It only READS from Postgres / ClickHouse, plus two actions:
  - POST /api/incidents/{id}/resolve       (human closes an incident)
  - POST /api/incidents/{id}/investigate   (re-run the LangGraph agent)
The detector (watch.py) keeps running as its own process.
"""
import os
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from db import (get_connection, ch_query, resolve_incident,
                get_incident_embedding, find_similar_incidents,
                LOG_PATTERN_RULES, METRIC_RULES)

LOGS_TABLE = "incident_copilot.application_logs"
ERROR_LEVELS = ("ERROR", "CRITICAL", "FATAL")
TIMELINE_BACK_MIN = 60
TIMELINE_MAX_MIN = 240
INGEST_ENABLED = os.getenv("INGEST_ENABLED", "1") == "1"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _utc(dt):
    """Naive datetimes from the DBs are UTC. Return an aware UTC datetime."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso(dt):
    d = _utc(dt)
    return d.isoformat() if d else None


def naive_utc(dt):
    return _utc(dt).replace(tzinfo=None)


def now_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _num(x):
    """NaN / None safe float for JSON."""
    if x is None or x != x:
        return None
    return round(float(x), 1)


def _bullets(text):
    """'- a\n- b' -> ['a', 'b']"""
    out = []
    for line in (text or "").splitlines():
        line = line.strip().lstrip("-*\u2022").strip()
        if line:
            out.append(line)
    return out


# --------------------------------------------------------------------------
# app
# --------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app):
    # The AI report (root cause / solution / confidence) is stored as ONE text
    # column, separate from the human-confirmed root_cause / resolution columns.
    with get_connection() as cur:
        cols = ["ai_symptoms", "ai_root_cause", "ai_solution", "ai_evidence", "ai_confidence"]
        cur.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = 'incidents' AND column_name = ANY(%s);",
            (cols,),
        )
        have = {r[0] for r in cur.fetchall()}
        missing = [c for c in cols if c not in have]
        if missing:     # ALTER TABLE locks the table, so only run it when really needed
            cur.execute("ALTER TABLE public.incidents " +
                        ", ".join(f"ADD COLUMN IF NOT EXISTS {c} text" for c in missing) + ";")
    if INGEST_ENABLED:
        from ingest import start_ingest     # app.log -> UI -> ClickHouse -> incidents
        start_ingest()
    yield


app = FastAPI(title="AI Incident Copilot API", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return {"ok": True}


# --------------------------------------------------------------------------
# incidents
# --------------------------------------------------------------------------

@app.get("/api/incidents")
def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    service: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
):
    sql = """
        SELECT i.id, s.name, i.rule, i.title, i.severity, i.status,
               i.started_at, i.resolved_at, i.ai_confidence
        FROM public.incidents i JOIN public.services s ON s.id = i.service_id
        WHERE 1 = 1
    """
    params = []
    if status:
        sql += " AND LOWER(i.status) = LOWER(%s)"
        params.append(status)
    if severity:
        sql += " AND LOWER(i.severity) = LOWER(%s)"
        params.append(severity)
    if service:
        sql += " AND s.name = %s"
        params.append(service)
    sql += " ORDER BY (i.status = 'open') DESC, i.started_at DESC LIMIT %s"
    params.append(limit)

    with get_connection() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()

    return [
        {"id": r[0], "service": r[1], "rule": r[2], "title": r[3], "severity": r[4],
         "status": r[5], "started_at": iso(r[6]), "resolved_at": iso(r[7]),
         "ai_confidence": r[8]}
        for r in rows
    ]


def _error_timeline(service, start, end):
    """Per-minute total/error counts, with empty minutes filled with zeros."""
    start = start.replace(second=0, microsecond=0)
    if (end - start) > timedelta(minutes=TIMELINE_MAX_MIN):
        start = end - timedelta(minutes=TIMELINE_MAX_MIN)
    result = ch_query(
        f"""
        SELECT toStartOfMinute(timestamp) AS minute,
               count() AS total,
               countIf(UPPER(level) IN %(levels)s) AS errors
        FROM {LOGS_TABLE}
        WHERE service_name = %(service)s
          AND timestamp >= %(start)s AND timestamp < %(end)s
        GROUP BY minute ORDER BY minute;
        """,
        parameters={"service": service, "levels": ERROR_LEVELS, "start": start, "end": end},
    )
    found = {m.replace(tzinfo=None): (int(t), int(e)) for m, t, e in result.result_rows}
    out, cur_min = [], start
    while cur_min < end:
        total, errors = found.get(cur_min, (0, 0))
        out.append({"minute": iso(cur_min), "total": total, "errors": errors})
        cur_min += timedelta(minutes=1)
    return out


def _evidence_lines(service, start, end, limit=50):
    result = ch_query(
        f"""
        SELECT timestamp, level, message
        FROM {LOGS_TABLE}
        WHERE service_name = %(service)s
          AND timestamp >= %(start)s AND timestamp < %(end)s
          AND UPPER(level) IN %(levels)s
        ORDER BY timestamp
        LIMIT %(limit)s;
        """,
        parameters={"service": service, "start": start, "end": end,
                    "levels": ERROR_LEVELS + ("WARN",), "limit": limit},
    )
    return [{"ts": iso(ts), "level": lvl, "message": msg} for ts, lvl, msg in result.result_rows]


@app.get("/api/incidents/{incident_id}")
def incident_detail(incident_id: int):
    with get_connection() as cur:
        cur.execute(
            """
            SELECT i.id, s.name, i.rule, i.title, i.severity, i.status,
                   i.started_at, i.resolved_at, i.fingerprint, i.description,
                   i.evidence, i.signature_text, i.root_cause, i.resolution,
                   i.resolution_confidence, i.ai_symptoms, i.ai_root_cause,
                   i.ai_solution, i.ai_evidence, i.ai_confidence
            FROM public.incidents i JOIN public.services s ON s.id = i.service_id
            WHERE i.id = %s;
            """,
            (incident_id,),
        )
        r = cur.fetchone()
    if not r:
        raise HTTPException(404, f"incident {incident_id} not found")

    (iid, service, rule, title, severity, status, started_at, resolved_at, fp,
     description, evidence, signature, root_cause, resolution, confidence,
     ai_symptoms, ai_root_cause, ai_solution, ai_evidence, ai_confidence) = r

    start = naive_utc(started_at)
    end = naive_utc(resolved_at) if resolved_at else now_naive()
    end = min(end + timedelta(minutes=5), now_naive() + timedelta(minutes=1))

    try:
        timeline = _error_timeline(service, start - timedelta(minutes=TIMELINE_BACK_MIN), end)
        lines = _evidence_lines(service, start - timedelta(minutes=15), end)
    except Exception as e:                      # ClickHouse down: keep the page usable
        timeline, lines = [], []
        print(f"[api] clickhouse query failed for incident {incident_id}: {e}")

    try:
        embedding, svc_name = get_incident_embedding(incident_id)
        similar = find_similar_incidents(embedding, svc_name, exclude_incident_id=incident_id) if embedding else []
    except Exception as e:
        similar = []
        print(f"[api] similar-incident search failed for {incident_id}: {e}")

    ai = None
    if any([ai_symptoms, ai_root_cause, ai_solution, ai_evidence, ai_confidence]):
        ai = {
            "symptoms": ai_symptoms, "root_cause": ai_root_cause, "solution": ai_solution,
            "evidence_points": _bullets(ai_evidence), "confidence": ai_confidence,
        }

    return {
        "id": iid, "service": service, "rule": rule, "title": title,
        "severity": severity, "status": status,
        "started_at": iso(started_at), "resolved_at": iso(resolved_at),
        "fingerprint": fp, "symptoms": description, "evidence_summary": evidence,
        "signature_text": signature,
        "ai": ai,
        "confirmed": ({"root_cause": root_cause, "resolution": resolution,
                       "confidence": confidence} if status == "resolved" else None),
        "timeline": timeline,
        "log_lines": lines,
        "similar": similar,
    }


class ResolveBody(BaseModel):
    root_cause: str
    resolution: str


@app.post("/api/incidents/{incident_id}/resolve")
def resolve(incident_id: int, body: ResolveBody):
    try:
        ok = resolve_incident(incident_id, body.root_cause, body.resolution)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if not ok:
        raise HTTPException(409, "incident not found or already resolved")
    return {"ok": True}


@app.post("/api/incidents/{incident_id}/investigate", status_code=202)
def reinvestigate(incident_id: int):
    from main import investigate            # lazy: loads Groq / LangGraph only when needed

    def run():
        try:
            investigate(incident_id)
        except Exception as e:
            print(f"[api] investigation of {incident_id} failed: {e}")

    threading.Thread(target=run, daemon=True).start()
    return {"status": "started"}


# --------------------------------------------------------------------------
# logs (the UI polls this with a cursor; no websockets needed)
# --------------------------------------------------------------------------

def _cursor_str(value: str) -> str:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return naive_utc(dt).strftime("%Y-%m-%d %H:%M:%S.%f")


@app.get("/api/logs")
def logs(
    service: Optional[str] = None,
    level: Optional[str] = None,
    after: Optional[str] = None,
    limit: int = Query(200, ge=1, le=1000),
):
    where, params = ["1 = 1"], {"limit": limit}
    if service:
        where.append("service_name = %(service)s")
        params["service"] = service
    if level:
        where.append("UPPER(level) = UPPER(%(level)s)")
        params["level"] = level
    if after:
        try:
            params["after"] = _cursor_str(after)
        except ValueError:
            raise HTTPException(400, "bad 'after' timestamp")
        where.append("timestamp > toDateTime64(%(after)s, 6)")

    order = "ASC" if after else "DESC"
    result = ch_query(
        f"""
        SELECT timestamp, service_name, level, message, latency_ms
        FROM {LOGS_TABLE}
        WHERE {' AND '.join(where)}
        ORDER BY timestamp {order}
        LIMIT %(limit)s;
        """,
        parameters=params,
    )
    rows = result.result_rows
    if not after:
        rows = list(reversed(rows))             # newest `limit` rows, oldest first
    out = [{"ts": iso(ts), "service": svc, "level": lvl, "message": msg,
            "latency_ms": _num(lat)} for ts, svc, lvl, msg, lat in rows]
    return {"logs": out, "cursor": out[-1]["ts"] if out else after}


# --------------------------------------------------------------------------
# live tail of app.log (filled by ingest.py, before the lines reach ClickHouse)
# --------------------------------------------------------------------------

@app.get("/api/live")
def live(
    after: Optional[int] = None,
    service: Optional[str] = None,
    level: Optional[str] = None,
    limit: int = Query(200, ge=1, le=1000),
):
    if not INGEST_ENABLED:
        raise HTTPException(503, "ingest is disabled (INGEST_ENABLED=0)")
    from ingest import get_live
    return get_live(after, service, level, limit)


@app.get("/api/ingest/status")
def ingest_status():
    if not INGEST_ENABLED:
        return {"running": False, "disabled": True}
    from ingest import STATUS
    return STATUS


# --------------------------------------------------------------------------
# services overview
# --------------------------------------------------------------------------

@app.get("/api/services")
def services(window_minutes: int = Query(15, ge=1, le=240)):
    with get_connection() as cur:
        cur.execute("SELECT id, name, environment FROM public.services ORDER BY name;")
        svc_rows = cur.fetchall()
        cur.execute(
            """
            SELECT s.name,
                   count(*) FILTER (WHERE i.status = 'open') AS open_count,
                   count(*) FILTER (WHERE i.status = 'open' AND i.severity = 'high') AS high_count
            FROM public.incidents i JOIN public.services s ON s.id = i.service_id
            GROUP BY s.name;
            """
        )
        inc = {n: (o, h) for n, o, h in cur.fetchall()}

    result = ch_query(
        f"""
        SELECT service_name,
               count() AS logs,
               countIf(UPPER(level) IN %(levels)s) AS errors,
               quantileIf(0.95)(latency_ms, latency_ms IS NOT NULL) AS p95,
               max(timestamp) AS last_log
        FROM {LOGS_TABLE}
        WHERE timestamp >= now() - INTERVAL %(m)s MINUTE
        GROUP BY service_name;
        """,
        parameters={"levels": ERROR_LEVELS, "m": window_minutes},
    )
    stats = {n: (int(c), int(e), _num(p), iso(last)) for n, c, e, p, last in result.result_rows}

    out = []
    for sid, name, env in svc_rows:
        logs_n, errs, p95, last_log = stats.get(name, (0, 0, None, None))
        open_n, high_n = inc.get(name, (0, 0))
        out.append({
            "id": sid, "name": name, "environment": env,
            "logs": logs_n, "errors": errs,
            "error_rate_pct": round(100 * errs / logs_n, 1) if logs_n else 0.0,
            "p95_ms": p95, "last_log_at": last_log,
            "open_incidents": open_n, "high_incidents": high_n,
            "status": "incident" if open_n else "healthy",
        })
    return {"window_minutes": window_minutes, "services": out}


# --------------------------------------------------------------------------
# rules (read-only)
# --------------------------------------------------------------------------

BUILTIN_RULES = [
    {"rule": "error_rate", "description": "Error share above max(5%, 3x baseline) for 2 minutes", "severity": "high"},
    {"rule": "new_error_type", "description": "New error fingerprint seen 5+ times in 2 minutes, not in the last 24h", "severity": "medium"},
    {"rule": "latency_spike", "description": "p95 latency above 2x baseline for 3 minutes", "severity": "medium"},
    {"rule": "traffic_silence", "description": "No logs from a service for 5 minutes", "severity": "high"},
    {"rule": "traffic_drop", "description": "Log volume below 30% of the same time yesterday (5 min)", "severity": "medium"},
    {"rule": "security_ip_spike", "description": "15+ failed-auth / 4xx / 5xx lines from one IP in 5 minutes", "severity": "high"},
    {"rule": "certificate_expiry", "description": "Certificate expires within 30 / 14 / 7 days", "severity": "medium"},
]


@app.get("/api/rules")
def rules():
    return {
        "builtin": BUILTIN_RULES,
        "pattern": [{"rule": k, "regex": v["regex"], "min_count": v["min_count"],
                     "minutes": v["minutes"], "severity": v["severity"]}
                    for k, v in LOG_PATTERN_RULES.items()],
        "metric": [{"rule": k, "metric": v["metric"], "kind": v["kind"],
                    "threshold": v["threshold"], "minutes": v["minutes"],
                    "severity": v["severity"]}
                   for k, v in METRIC_RULES.items()],
    }