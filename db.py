import os
import re
import hashlib
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import psycopg2
import psycopg2.pool
import clickhouse_connect
from dotenv import load_dotenv

load_dotenv()


# --------------------------------------------------
# FINGERPRINTING (same logic as console.py, so hashes match incidents.fingerprint)
# --------------------------------------------------

_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HEX_RE = re.compile(r"\b(?=[0-9a-f]*[a-f])[0-9a-f]{6,}\b", re.IGNORECASE)
_NUM_RE = re.compile(r"\b\d+\b")
_WS_RE = re.compile(r"\s+")


def normalize(message: str) -> str:
    text = message.lower().strip()
    text = _UUID_RE.sub("<uuid>", text)
    text = _IP_RE.sub("<ip>", text)
    text = _HEX_RE.sub("<hex>", text)
    text = _NUM_RE.sub("<n>", text)
    text = _WS_RE.sub(" ", text)
    return text


def fingerprint(message: str, length: int = 12) -> str:
    return hashlib.sha1(normalize(message).encode("utf-8")).hexdigest()[:length]


# --------------------------------------------------
# DATABASE CONNECTIONS (PostgreSQL + ClickHouse)
# --------------------------------------------------

# Postgres Pool for Incidents, Embeddings, Services Metadata
connection_pool = psycopg2.pool.ThreadedConnectionPool(
    minconn=1,
    maxconn=int(os.getenv("DB_POOL_MAX", "10")),
    database=os.getenv("DB_NAME", "ai_incident"),
    user=os.getenv("DB_USER", "postgres"),
    password=os.getenv("DB_PASSWORD"),
    host=os.getenv("DB_HOST", "localhost"),
    port=int(os.getenv("DB_PORT", "5432")),
)

@contextmanager
def get_connection():
    conn = connection_pool.getconn()
    conn.autocommit = True
    try:
        with conn.cursor() as cursor:
            yield cursor
    finally:
        connection_pool.putconn(conn)


# ClickHouse Client for incident_copilot.application_logs
ch_client = clickhouse_connect.get_client(
    host=os.getenv("CH_HOST", "localhost"),
    port=int(os.getenv("CH_PORT", "8123")),
    username=os.getenv("CH_USER", "default"),
    password=os.getenv("CH_PASSWORD", ""),
)


# --------------------------------------------------
# SERVICES (PostgreSQL)
# --------------------------------------------------

def get_service(service_name):
    with get_connection() as cur:
        cur.execute(
            """
            SELECT id, name, environment, created_at
            FROM public.services
            WHERE name ILIKE %s;
            """,
            (f"%{service_name}%",)
        )
        return cur.fetchone()


# --------------------------------------------------
# APPLICATION LOGS (ClickHouse: incident_copilot.application_logs)
# --------------------------------------------------

def query_logs(
    service_name=None,
    level=None,
    start_time=None,
    end_time=None
):
    query = """
        SELECT
            id,
            service_name AS service,
            environment,
            level,
            message,
            latency_ms,
            request_id,
            timestamp
        FROM incident_copilot.application_logs
        WHERE 1 = 1
    """
    params = {}

    if service_name:
        query += " AND service_name ILIKE %(service)s"
        params["service"] = f"%{service_name}%"

    if level:
        query += " AND UPPER(level) = UPPER(%(level)s)"
        params["level"] = level

    if start_time:
        query += " AND timestamp >= %(start_time)s"
        params["start_time"] = start_time

    if end_time:
        query += " AND timestamp <= %(end_time)s"
        params["end_time"] = end_time

    query += " ORDER BY timestamp DESC"

    result = ch_client.query(query, parameters=params)
    return result.result_rows


# --------------------------------------------------
# INCIDENTS (PostgreSQL)
# --------------------------------------------------

def get_incidents(service_name=None, status=None, severity=None):
    with get_connection() as cur:
        query = """
            SELECT i.id, s.name AS service, s.environment, i.title,
                   i.description, i.severity, i.status,
                   i.started_at, i.resolved_at, i.created_at
            FROM public.incidents AS i
            JOIN public.services AS s ON i.service_id = s.id
            WHERE 1 = 1
        """
        params = []

        if service_name:
            query += " AND s.name ILIKE %s"
            params.append(f"%{service_name}%")
        if status:
            query += " AND LOWER(i.status) = LOWER(%s)"
            params.append(status)
        if severity:
            query += " AND LOWER(i.severity) = LOWER(%s)"
            params.append(severity)

        query += " ORDER BY i.started_at DESC"
        cur.execute(query, params)
        return cur.fetchall()


# --------------------------------------------------
# SLOW REQUESTS (ClickHouse)
# --------------------------------------------------

def query_slow_requests(
    service_name=None,
    min_latency_ms=5000
):
    query = """
        SELECT
            id,
            service_name AS service,
            environment,
            level,
            message,
            latency_ms,
            request_id,
            timestamp
        FROM incident_copilot.application_logs
        WHERE latency_ms >= %(min_latency)s
    """
    params = {"min_latency": min_latency_ms}

    if service_name:
        query += " AND service_name = %(service)s"
        params["service"] = service_name

    query += " ORDER BY latency_ms DESC"

    result = ch_client.query(query, parameters=params)
    return result.result_rows


# ======================= Error Rate =====================================

ERROR_LEVELS = ["ERROR", "CRITICAL", "FATAL"]

INCIDENT_LOOKBACK_MIN = 15
BASELINE_MIN = 60


def _to_datetime(value):
    """Accept datetime or ISO-like string ('2026-10-01 07:08:37.884965')."""
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


# --------------------------------------------------
# TOOL 1: FIND WINDOWS
# --------------------------------------------------

def find_windows(started_at, resolved_at=None, baseline_gap_minutes=0, baseline_minutes=None):
    started_at = _to_datetime(started_at)
    resolved_at = _to_datetime(resolved_at)

    incident_end = resolved_at or datetime.now(started_at.tzinfo)
    duration = incident_end - started_at

    baseline_len = timedelta(minutes=baseline_minutes) if baseline_minutes else duration
    baseline_end = started_at - timedelta(minutes=baseline_gap_minutes)
    baseline_start = baseline_end - baseline_len

    return {
        "incident": {
            "start": started_at,
            "end": incident_end,
            "minutes": round(duration.total_seconds() / 60, 1),
        },
        "baseline": {
            "start": baseline_start,
            "end": baseline_end,
            "minutes": round(baseline_len.total_seconds() / 60, 1),
        },
    }


# --------------------------------------------------
# TOOL 2: WINDOW STATS (ClickHouse)
# --------------------------------------------------

def get_window_stats(service_name, start_time, end_time):
    query = """
        SELECT
            count(*) AS total_logs,
            countIf(UPPER(level) IN %(error_levels)s) AS error_count
        FROM incident_copilot.application_logs
        WHERE service_name = %(service)s
          AND timestamp >= %(start)s
          AND timestamp < %(end)s;
    """
    result = ch_client.query(query, parameters={
        "error_levels": tuple(ERROR_LEVELS),
        "service": service_name,
        "start": start_time,
        "end": end_time
    })
    total, errors = result.result_rows[0]

    return {
        "total_logs": total,
        "error_count": errors,
        "error_rate_pct": round(100 * errors / total, 2) if total else 0.0,
    }


# --------------------------------------------------
# TOOL 3: GROUP ERRORS (ClickHouse)
# --------------------------------------------------

def group_errors(service_name, start_time, end_time, limit=10):
    query = """
        WITH errs AS (
            SELECT
                message,
                request_id,
                timestamp,
                regexpReplaceAll(
                    regexpReplaceAll(
                        message,
                        '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
                        '<uuid>'
                    ),
                    '[0-9]+', '<n>'
                ) AS fingerprint
            FROM incident_copilot.application_logs
            WHERE service_name = %(service)s
              AND UPPER(level) IN %(error_levels)s
              AND timestamp >= %(start)s
              AND timestamp < %(end)s
        )
        SELECT
            fingerprint,
            count(*)          AS count,
            min(timestamp)    AS first_seen,
            max(timestamp)    AS last_seen,
            argMin(message, timestamp)    AS sample_message,
            argMin(request_id, timestamp) AS sample_request_id
        FROM errs
        GROUP BY fingerprint
        ORDER BY count DESC
        LIMIT %(limit)s;
    """
    result = ch_client.query(query, parameters={
        "service": service_name,
        "error_levels": tuple(ERROR_LEVELS),
        "start": start_time,
        "end": end_time,
        "limit": limit
    })

    return [
        {
            "fingerprint": r[0],
            "count": r[1],
            "first_seen": r[2],
            "last_seen": r[3],
            "sample_message": r[4],
            "sample_request_id": r[5],
        }
        for r in result.result_rows
    ]


# --------------------------------------------------
# ORCHESTRATOR: BUILD EVIDENCE BUNDLE
# --------------------------------------------------

def collect_error_rate_evidence(service_name, started_at, resolved_at=None, top_n=10,
                                lookback_minutes=INCIDENT_LOOKBACK_MIN):
    started_at = _to_datetime(started_at)
    resolved_at = _to_datetime(resolved_at)

    windows = find_windows(
        started_at - timedelta(minutes=lookback_minutes),
        resolved_at,
        baseline_minutes=BASELINE_MIN,
    )
    inc, base = windows["incident"], windows["baseline"]

    incident_stats = get_window_stats(service_name, inc["start"], inc["end"])
    baseline_stats = get_window_stats(service_name, base["start"], base["end"])

    incident_groups = group_errors(service_name, inc["start"], inc["end"], top_n)
    baseline_groups = group_errors(service_name, base["start"], base["end"], 50)
    baseline_counts = {g["fingerprint"]: g["count"] for g in baseline_groups}

    for g in incident_groups:
        g["baseline_count"] = baseline_counts.get(g["fingerprint"], 0)
        g["is_new"] = g["baseline_count"] == 0

    b_rate, i_rate = baseline_stats["error_rate_pct"], incident_stats["error_rate_pct"]

    return {
        "incident": {"type": "error_rate", "service": service_name},
        "windows": windows,
        "evidence": {
            "baseline_stats": baseline_stats,
            "incident_stats": incident_stats,
            "rate_change": {
                "baseline_pct": b_rate,
                "incident_pct": i_rate,
                "multiplier": round(i_rate / b_rate, 1) if b_rate else None,
            },
            "top_error_groups": incident_groups,
            "notes": [] if incident_groups else ["No error logs found in the incident window."],
        },
    }


# ======================= New Error Type =====================================

TRIGGER_LOOKBACK_MIN = 15
WARN_LOOKBACK_MIN = 30
HISTORY_HOURS = 24
TRACE_REQUESTS = 3
MAX_LINES = 20

BASE_SELECT = """
    SELECT timestamp, service_name, level, latency_ms, request_id, message
    FROM incident_copilot.application_logs
"""


def _row(r):
    ts, service, level, latency, request_id, message = r
    return {
        "ts": ts, "service": service, "level": level,
        "latency_ms": float(latency) if latency is not None else None,
        "request_id": request_id, "message": message,
    }


def _fmt(rec):
    return {**rec, "ts": rec["ts"].isoformat() if isinstance(rec["ts"], datetime) else rec["ts"]}


def get_trigger_logs(service, fp):
    query = BASE_SELECT + """
        WHERE service_name = %(service)s AND level = 'ERROR'
          AND timestamp >= now() - INTERVAL %(hours)s HOUR
        ORDER BY timestamp;
    """
    result = ch_client.query(query, parameters={"service": service, "hours": HISTORY_HOURS})
    rows = [_row(r) for r in result.result_rows]

    matches = [r for r in rows if fingerprint(r["message"]) == fp]
    if not matches:
        return {"count": 0, "first_seen": None, "last_seen": None, "samples": []}

    anchor = matches[-1]["ts"]
    since = anchor - timedelta(minutes=TRIGGER_LOOKBACK_MIN)
    hits = [r for r in matches if r["ts"] >= since]
    return {
        "count": len(hits),
        "first_seen": hits[0]["ts"],
        "last_seen": hits[-1]["ts"],
        "samples": [_fmt(h) for h in hits[:5]],
    }


def get_warns_before(service, first_seen):
    if first_seen is None:
        return []
    query = BASE_SELECT + """
        WHERE service_name = %(service)s AND level = 'WARN'
          AND timestamp < %(first_seen)s
          AND timestamp >= %(first_seen)s - INTERVAL %(mins)s MINUTE
        ORDER BY timestamp DESC
        LIMIT %(limit)s;
    """
    result = ch_client.query(query, parameters={
        "service": service,
        "first_seen": first_seen,
        "mins": WARN_LOOKBACK_MIN,
        "limit": MAX_LINES
    })
    rows = [_row(r) for r in result.result_rows]
    rows.reverse()
    return [_fmt(r) for r in rows]


def get_trace(trigger_samples):
    request_ids = []
    for s in trigger_samples:
        if s["request_id"] not in request_ids:
            request_ids.append(s["request_id"])
    request_ids = request_ids[:TRACE_REQUESTS]
    if not request_ids:
        return {}

    query = BASE_SELECT + " WHERE request_id IN %(req_ids)s ORDER BY timestamp;"
    result = ch_client.query(query, parameters={"req_ids": tuple(request_ids)})
    rows = [_row(r) for r in result.result_rows]

    traces = {rid: [] for rid in request_ids}
    for r in rows:
        if r["request_id"] in traces and len(traces[r["request_id"]]) < MAX_LINES:
            traces[r["request_id"]].append(_fmt(r))
    return traces


def fetch_new_error_type(incident):
    trigger = get_trigger_logs(incident["service"], incident["fingerprint"])
    warns = get_warns_before(incident["service"], trigger["first_seen"])
    trace = get_trace(trigger["samples"])

    notes = []
    if trigger["count"] == 0:
        notes.append("No trigger errors found in the DB for this fingerprint.")
    if not warns:
        notes.append("No WARN logs found before the first occurrence.")
    if trace and all(len(v) <= 1 for v in trace.values()):
        notes.append("Each traced request has only one log line (no cross-service trail).")

    return {
        "trigger": {
            "count": trigger["count"],
            "first_seen": trigger["first_seen"].isoformat() if trigger["first_seen"] else None,
            "last_seen": trigger["last_seen"].isoformat() if trigger["last_seen"] else None,
            "samples": trigger["samples"],
        },
        "warns_before_first_error": warns,
        "request_traces": trace,
        "notes": notes,
    }


# ======================= Latency Spike =====================================

LATENCY_SPIKE_MULT = 2.0
LATENCY_LOOKBACK_MIN = 15
LATENCY_BASELINE_MIN = 60


def get_incident_started_at(incident_id):
    with get_connection() as cur:
        cur.execute("SELECT started_at FROM public.incidents WHERE id = %s;", (incident_id,))
        row = cur.fetchone()
    return row[0] if row else None


def _f(x):
    return round(float(x), 1) if x is not None else None


def get_latency_stats(service_name, start_time, end_time):
    query = """
        SELECT
            count(latency_ms),
            quantile(0.5)(latency_ms),
            quantile(0.95)(latency_ms),
            max(latency_ms)
        FROM incident_copilot.application_logs
        WHERE service_name = %(service)s
          AND latency_ms IS NOT NULL
          AND timestamp >= %(start)s
          AND timestamp < %(end)s;
    """
    result = ch_client.query(query, parameters={
        "service": service_name,
        "start": start_time,
        "end": end_time
    })
    n, p50, p95, mx = result.result_rows[0]
    return {"count": n, "p50_ms": _f(p50), "p95_ms": _f(p95), "max_ms": _f(mx)}


def get_latency_timeline(service_name, start_time, end_time, limit=30):
    query = """
        SELECT
            toStartOfMinute(timestamp) AS minute,
            count(*) AS requests,
            quantile(0.95)(latency_ms) AS p95
        FROM incident_copilot.application_logs
        WHERE service_name = %(service)s
          AND latency_ms IS NOT NULL
          AND timestamp >= %(start)s
          AND timestamp < %(end)s
        GROUP BY minute
        ORDER BY minute DESC
        LIMIT %(limit)s;
    """
    result = ch_client.query(query, parameters={
        "service": service_name,
        "start": start_time,
        "end": end_time,
        "limit": limit
    })
    rows = result.result_rows
    rows.reverse()
    return [{"minute": m.isoformat() if isinstance(m, datetime) else str(m), "requests": n, "p95_ms": _f(p)} for m, n, p in rows]


def get_slow_requests(service_name, start_time, end_time, threshold_ms=None, limit=MAX_LINES):
    query = BASE_SELECT + """
        WHERE service_name = %(service)s
          AND latency_ms IS NOT NULL
          AND timestamp >= %(start)s
          AND timestamp < %(end)s
          AND (%(threshold)s IS NULL OR latency_ms >= %(threshold)s)
        ORDER BY latency_ms DESC
        LIMIT %(limit)s;
    """
    result = ch_client.query(query, parameters={
        "service": service_name,
        "start": start_time,
        "end": end_time,
        "threshold": threshold_ms,
        "limit": limit
    })
    return [_fmt(_row(r)) for r in result.result_rows]


def get_neighbor_latency(service_name, base_start, inc_start, inc_end):
    query = """
        SELECT
            service_name,
            quantile(0.95) FILTER (WHERE timestamp < %(inc_start)s) AS base_p95,
            quantile(0.95) FILTER (WHERE timestamp >= %(inc_start)s) AS inc_p95
        FROM incident_copilot.application_logs
        WHERE service_name <> %(service)s
          AND latency_ms IS NOT NULL
          AND timestamp >= %(base_start)s
          AND timestamp < %(inc_end)s
        GROUP BY service_name;
    """
    result = ch_client.query(query, parameters={
        "service": service_name,
        "inc_start": inc_start,
        "base_start": base_start,
        "inc_end": inc_end
    })

    out = []
    for name, b, i in result.result_rows:
        b, i = _f(b), _f(i)
        out.append({
            "service": name,
            "baseline_p95_ms": b,
            "incident_p95_ms": i,
            "multiplier": round(i / b, 1) if b and i else None,
        })
    return sorted(out, key=lambda x: x["multiplier"] or 0, reverse=True)


def fetch_latency_spike(incident):
    service = incident["service"]
    started_at = incident.get("started_at") or get_incident_started_at(incident["incident_id"])
    started_at = _to_datetime(started_at)

    windows = find_windows(
        started_at - timedelta(minutes=LATENCY_LOOKBACK_MIN),
        incident.get("resolved_at"),
        baseline_minutes=LATENCY_BASELINE_MIN,
    )
    inc, base = windows["incident"], windows["baseline"]

    inc_stats = get_latency_stats(service, inc["start"], inc["end"])
    base_stats = get_latency_stats(service, base["start"], base["end"])

    b95, i95 = base_stats["p95_ms"], inc_stats["p95_ms"]
    multiplier = round(i95 / b95, 1) if b95 and i95 else None
    threshold = LATENCY_SPIKE_MULT * b95 if b95 else None

    slow = get_slow_requests(service, inc["start"], inc["end"], threshold)
    timeline = get_latency_timeline(service, base["start"], inc["end"])
    neighbors = get_neighbor_latency(service, base["start"], inc["start"], inc["end"])

    notes = []
    if inc_stats["count"] == 0:
        notes.append("No logs with latency found in the incident window.")
    if not b95:
        notes.append("No baseline latency data, so the spike cannot be compared to normal.")
    if not slow:
        notes.append("No individual requests above the slow threshold.")
    slow_neighbors = [n["service"] for n in neighbors if n["multiplier"] and n["multiplier"] >= LATENCY_SPIKE_MULT]
    if slow_neighbors:
        notes.append(f"Other services also slowed down: {', '.join(slow_neighbors)} (possible upstream cause).")
    elif neighbors:
        notes.append("No other service slowed down, so the slowness looks local to this service.")

    return {
        "incident": {"type": "latency_spike", "service": service},
        "windows": windows,
        "evidence": {
            "baseline_stats": base_stats,
            "incident_stats": inc_stats,
            "p95_change": {"baseline_ms": b95, "incident_ms": i95, "multiplier": multiplier},
            "slow_threshold_ms": threshold,
            "slow_requests": slow,
            "timeline_by_minute": timeline,
            "neighbor_services": neighbors,
            "notes": notes,
        },
    }


# --------------------------------------------------
# INCIDENTS REPORT & RESOLUTION (PostgreSQL)
# --------------------------------------------------

def ensure_report_columns():
    with get_connection() as cur:
        cur.execute("ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS evidence text;")


def parse_report(text):
    _SECTION_RE = re.compile(
        r"^\s*(Symptoms|Root cause|Solution|Evidence|Confidence)\s*:\s*",
        re.IGNORECASE | re.MULTILINE,
    )
    text = text or ""
    matches = list(_SECTION_RE.finditer(text))
    sections = {}
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        sections[m.group(1).lower()] = text[m.end():end].strip()

    conf_word = re.match(r"[A-Za-z]+", sections.get("confidence", "") or "")
    return {
        "symptoms": sections.get("symptoms") or None,
        "root_cause": sections.get("root cause") or None,
        "solution": sections.get("solution") or None,
        "evidence": sections.get("evidence") or None,
        "confidence": conf_word.group(0).upper() if conf_word else None,
    }


def save_investigation_result(incident_id, symptoms=None, evidence=None):
    with get_connection() as cur:
        cur.execute(
            """
            UPDATE public.incidents
            SET description = COALESCE(%s, description),
                evidence    = COALESCE(%s, evidence)
            WHERE id = %s;
            """,
            (symptoms, evidence, incident_id),
        )
        return cur.rowcount == 1


def get_incident(incident_id):
    with get_connection() as cur:
        cur.execute(
            """
            SELECT i.id, s.name, i.title, i.rule, i.status, i.severity,
                   i.started_at, i.description, i.root_cause, i.resolution,
                   i.resolution_confidence
            FROM public.incidents i
            JOIN public.services s ON s.id = i.service_id
            WHERE i.id = %s;
            """,
            (incident_id,),
        )
        r = cur.fetchone()
    if not r:
        return None
    keys = ["id", "service", "title", "rule", "status", "severity",
            "started_at", "description", "root_cause", "resolution", "confidence"]
    return dict(zip(keys, r))


def resolve_incident(incident_id, root_cause, resolution):
    root_cause = (root_cause or "").strip()
    resolution = (resolution or "").strip()
    if not root_cause or not resolution:
        raise ValueError("root_cause and resolution are both required")

    with get_connection() as cur:
        cur.execute(
            """
            UPDATE public.incidents
            SET root_cause = %s,
                resolution = %s,
                resolution_confidence = 'confirmed',
                status = 'resolved',
                resolved_at = now()
            WHERE id = %s
            AND status <> 'resolved';
            """,
            (root_cause, resolution, incident_id),
        )
        return cur.rowcount == 1


# --------------------------------------------------
# SIMILAR INCIDENTS VECTOR SEARCH (PostgreSQL pgvector)
# --------------------------------------------------

SIMILAR_MIN_SIMILARITY = 0.75


def _to_pgvector(vec):
    if isinstance(vec, str):
        return vec
    return "[" + ",".join(f"{float(x):.6f}" for x in vec) + "]"


def get_incident_embedding(incident_id):
    with get_connection() as cur:
        cur.execute(
            """
            SELECT i.embedding::text, s.name
            FROM public.incidents AS i
            JOIN public.services AS s ON s.id = i.service_id
            WHERE i.id = %s;
            """,
            (incident_id,),
        )
        row = cur.fetchone()
    return (row[0], row[1]) if row else (None, None)


def find_similar_incidents(
    embedding,
    service_name,
    exclude_incident_id=None,
    limit=3,
    min_similarity=SIMILAR_MIN_SIMILARITY,
    only_confirmed=True,
):
    if embedding is None:
        return []

    vec = _to_pgvector(embedding)
    levels = ["confirmed"] if only_confirmed else ["confirmed", "inferred"]

    with get_connection() as cur:
        cur.execute(
            """
            SELECT i.id,
                   1 - (i.embedding <=> %s::vector) AS similarity,
                   i.signature_text,
                   i.root_cause,
                   i.resolution,
                   i.resolution_confidence
            FROM public.incidents AS i
            JOIN public.services AS s ON s.id = i.service_id
            WHERE s.name = %s
              AND i.status = 'resolved'
              AND i.embedding IS NOT NULL
              AND i.signature_text IS NOT NULL
              AND i.root_cause IS NOT NULL
              AND i.resolution IS NOT NULL
              AND i.resolution_confidence = ANY(%s)
              AND (%s::int IS NULL OR i.id <> %s::int)
            ORDER BY i.embedding <=> %s::vector
            LIMIT %s;
            """,
            (vec, service_name, levels,
             exclude_incident_id, exclude_incident_id, vec, limit),
        )
        rows = cur.fetchall()

    return [
        {
            "incident_id": r[0],
            "similarity": round(float(r[1]), 2),
            "signature_text": r[2],
            "root_cause": r[3],
            "resolution": r[4],
            "verified": r[5],
        }
        for r in rows
        if r[1] is not None and float(r[1]) >= min_similarity
    ]