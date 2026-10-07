import os
import re
import hashlib
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import psycopg2
import psycopg2.pool
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
# DATABASE CONNECTION POOL
# --------------------------------------------------

connection_pool = psycopg2.pool.ThreadedConnectionPool(
    minconn=1,
    maxconn=int(os.getenv("DB_POOL_MAX", "10")),
    database=os.getenv("DB_NAME", "ai_incident"),
    user=os.getenv("DB_USER", "postgres"),
    password=os.getenv("DB_PASSWORD"),
    host=os.getenv("DB_HOST", "localhost"),
    port=int(os.getenv("DB_PORT", "5432")),
)


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

@contextmanager
def get_connection():
    conn = connection_pool.getconn()
    conn.autocommit = True

    try:
        with conn.cursor() as cursor:
            yield cursor
    finally:
        connection_pool.putconn(conn)


# --------------------------------------------------
# SERVICES
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
# APPLICATION LOGS
# --------------------------------------------------

def query_logs(
    service_name=None,
    level=None,
    start_time=None,
    end_time=None
):
    with get_connection() as cur:

        query = """
            SELECT
                l.id,
                s.name AS service,
                s.environment,
                l.level,
                l.message,
                l.latency_ms,
                l.request_id,
                l.timestamp
            FROM public.application_logs AS l
            JOIN public.services AS s
                ON l.service_id = s.id
            WHERE 1 = 1
        """

        params = []

        if service_name:
            query += " AND s.name ILIKE %s"
            params.append(f"%{service_name}%")

        if level:
            query += " AND UPPER(l.level) = UPPER(%s)"
            params.append(level)

        if start_time:
            query += " AND l.timestamp >= %s"
            params.append(start_time)

        if end_time:
            query += " AND l.timestamp <= %s"
            params.append(end_time)

        query += " ORDER BY l.timestamp DESC"

        cur.execute(query, params)

        return cur.fetchall()


# --------------------------------------------------
# INCIDENTS
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
# SLOW REQUESTS
# --------------------------------------------------

def query_slow_requests(
    service_name=None,
    min_latency_ms=5000
):
    with get_connection() as cur:

        query = """
            SELECT
                l.id,
                s.name AS service,
                s.environment,
                l.level,
                l.message,
                l.latency_ms,
                l.request_id,
                l.timestamp
            FROM public.application_logs AS l
            JOIN public.services AS s
                ON l.service_id = s.id
            WHERE l.latency_ms >= %s
        """

        params = [min_latency_ms]

        if service_name:
            query += " AND s.name = %s"
            params.append(service_name)

        query += " ORDER BY l.latency_ms DESC"

        cur.execute(query, params)

        return cur.fetchall()


# ======================= Error Rate =====================================

ERROR_LEVELS = ["ERROR", "CRITICAL", "FATAL"]

# The burst of errors that opens an incident is written BEFORE started_at
# (started_at = moment of detection), so the incident window starts earlier.
INCIDENT_LOOKBACK_MIN = 15
BASELINE_MIN = 60            # fixed baseline length, so long-open incidents don't stretch it


def _to_datetime(value):
    """Accept datetime or ISO-like string ('2026-10-01 07:08:37.884965')."""
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


# --------------------------------------------------
# TOOL 1: FIND WINDOWS
# --------------------------------------------------

def find_windows(started_at, resolved_at=None, baseline_gap_minutes=0, baseline_minutes=None):
    """
    Incident window = [started_at, resolved_at or now).
    Baseline window = ends right before the incident (optionally shifted back
    by baseline_gap_minutes). Its length is baseline_minutes if given,
    otherwise the same length as the incident window.
    """
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
# TOOL 2: WINDOW STATS (baseline / incident)
# --------------------------------------------------

def get_window_stats(service_name, start_time, end_time):
    """Total logs, error count and error rate (%) for one window. Window is [start, end)."""
    with get_connection() as cur:
        cur.execute(
            """
            SELECT
                COUNT(*) AS total_logs,
                COUNT(*) FILTER (WHERE UPPER(l.level) = ANY(%s)) AS error_count
            FROM public.application_logs AS l
            JOIN public.services AS s ON l.service_id = s.id
            WHERE s.name = %s
              AND l.timestamp >= %s
              AND l.timestamp <  %s;
            """,
            (ERROR_LEVELS, service_name, start_time, end_time),
        )
        total, errors = cur.fetchone()

    return {
        "total_logs": total,
        "error_count": errors,
        "error_rate_pct": round(100 * errors / total, 2) if total else 0.0,
    }


# --------------------------------------------------
# TOOL 3: GROUP ERRORS
# --------------------------------------------------

def group_errors(service_name, start_time, end_time, limit=10):
    """
    Cluster errors by fingerprint. The fingerprint is the message with
    UUIDs and numbers replaced, so "timeout after 5023ms for user 88"
    and "timeout after 4101ms for user 12" land in the same group.
    """
    with get_connection() as cur:
        cur.execute(
            """
            WITH errs AS (
                SELECT
                    l.message,
                    l.request_id,
                    l.timestamp,
                    regexp_replace(
                        regexp_replace(
                            l.message,
                            '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
                            '<uuid>', 'g'
                        ),
                        '[0-9]+', '<n>', 'g'
                    ) AS fingerprint
                FROM public.application_logs AS l
                JOIN public.services AS s ON l.service_id = s.id
                WHERE s.name = %s
                  AND UPPER(l.level) = ANY(%s)
                  AND l.timestamp >= %s
                  AND l.timestamp <  %s
            )
            SELECT
                fingerprint,
                COUNT(*)          AS count,
                MIN(timestamp)    AS first_seen,
                MAX(timestamp)    AS last_seen,
                (ARRAY_AGG(message ORDER BY timestamp))[1]    AS sample_message,
                (ARRAY_AGG(request_id ORDER BY timestamp))[1] AS sample_request_id
            FROM errs
            GROUP BY fingerprint
            ORDER BY count DESC
            LIMIT %s;
            """,
            (service_name, ERROR_LEVELS, start_time, end_time, limit),
        )
        rows = cur.fetchall()

    return [
        {
            "fingerprint": r[0],
            "count": r[1],
            "first_seen": r[2],
            "last_seen": r[3],
            "sample_message": r[4],
            "sample_request_id": r[5],
        }
        for r in rows
    ]


# --------------------------------------------------
# ORCHESTRATOR: BUILD EVIDENCE BUNDLE
# --------------------------------------------------

def collect_error_rate_evidence(service_name, started_at, resolved_at=None, top_n=10,
                                lookback_minutes=INCIDENT_LOOKBACK_MIN):
    started_at = _to_datetime(started_at)
    resolved_at = _to_datetime(resolved_at)

    # start the incident window earlier, so the errors that triggered detection are inside it
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

    # Add baseline count per error group, so the analyst sees what actually changed
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

TRIGGER_LOOKBACK_MIN = 15    # window around the newest matching error
WARN_LOOKBACK_MIN = 30       # how far before the first error to look for warnings
HISTORY_HOURS = 24           # how far back to scan for matching errors
TRACE_REQUESTS = 3
MAX_LINES = 20


BASE_SELECT = """
    SELECT l.timestamp, s.name, l.level, l.latency_ms, l.request_id, l.message
    FROM application_logs l
    JOIN services s ON s.id = l.service_id
"""


def _row(r):
    ts, service, level, latency, request_id, message = r
    return {
        "ts": ts, "service": service, "level": level,
        "latency_ms": float(latency) if latency is not None else None,
        "request_id": request_id, "message": message,
    }


def _fmt(rec):
    """ISO string timestamp for the LLM."""
    return {**rec, "ts": rec["ts"].isoformat()}


# ---------- the three fetchers for new_error_type ----------

def get_trigger_logs(service, fp):
    """ERROR rows for this service whose fingerprint matches, clustered around the newest one."""
    with get_connection() as cur:
        cur.execute(
            BASE_SELECT + """
            WHERE s.name = %s AND l.level = 'ERROR'
              AND l.timestamp >= now() - (%s * interval '1 hour')
            ORDER BY l.timestamp;
            """,
            (service, HISTORY_HOURS),
        )
        rows = [_row(r) for r in cur.fetchall()]

    # the logs table has no fingerprint column, so compute it per message here
    matches = [r for r in rows if fingerprint(r["message"]) == fp]
    if not matches:
        return {"count": 0, "first_seen": None, "last_seen": None, "samples": []}

    anchor = matches[-1]["ts"]                         # newest matching error
    since = anchor - timedelta(minutes=TRIGGER_LOOKBACK_MIN)
    hits = [r for r in matches if r["ts"] >= since]    # the cluster that opened the incident
    return {
        "count": len(hits),
        "first_seen": hits[0]["ts"],                   # raw datetime, reused by the next fetcher
        "last_seen": hits[-1]["ts"],
        "samples": [_fmt(h) for h in hits[:5]],
    }


def get_warns_before(service, first_seen):
    """WARN rows in the 30 min BEFORE the first trigger error."""
    if first_seen is None:
        return []
    with get_connection() as cur:
        cur.execute(
            BASE_SELECT + """
            WHERE s.name = %s AND l.level = 'WARN'
              AND l.timestamp <  %s
              AND l.timestamp >= %s - (%s * interval '1 minute')
            ORDER BY l.timestamp DESC
            LIMIT %s;
            """,
            (service, first_seen, first_seen, WARN_LOOKBACK_MIN, MAX_LINES),
        )
        rows = [_row(r) for r in cur.fetchall()]
    rows.reverse()                                     # oldest first
    return [_fmt(r) for r in rows]


def get_trace(trigger_samples):
    """Every row (all services) sharing a request_id with a failing request."""
    request_ids = []
    for s in trigger_samples:
        if s["request_id"] not in request_ids:
            request_ids.append(s["request_id"])
    request_ids = request_ids[:TRACE_REQUESTS]
    if not request_ids:
        return {}

    with get_connection() as cur:
        cur.execute(
            BASE_SELECT + " WHERE l.request_id = ANY(%s) ORDER BY l.timestamp;",
            (request_ids,),
        )
        rows = [_row(r) for r in cur.fetchall()]

    traces = {rid: [] for rid in request_ids}
    for r in rows:
        if len(traces[r["request_id"]]) < MAX_LINES:
            traces[r["request_id"]].append(_fmt(r))
    return traces


# ---------- put it together ----------

def fetch_new_error_type(incident):
    """incident = {incident_id, service, rule, fingerprint}"""
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

LATENCY_SPIKE_MULT = 2.0      # same multiplier your detector uses
LATENCY_LOOKBACK_MIN = 15     # start the incident window before started_at
LATENCY_BASELINE_MIN = 60     # fixed baseline length


def get_incident_started_at(incident_id):
    with get_connection() as cur:
        cur.execute("SELECT started_at FROM public.incidents WHERE id = %s;", (incident_id,))
        row = cur.fetchone()
    return row[0] if row else None


def _f(x):
    return round(float(x), 1) if x is not None else None


# ---------- 1. latency stats for one window ----------

def get_latency_stats(service_name, start_time, end_time):
    """count, p50, p95, max of latency_ms for one window [start, end)."""
    with get_connection() as cur:
        cur.execute(
            """
            SELECT COUNT(l.latency_ms),
                   percentile_cont(0.5)  WITHIN GROUP (ORDER BY l.latency_ms),
                   percentile_cont(0.95) WITHIN GROUP (ORDER BY l.latency_ms),
                   MAX(l.latency_ms)
            FROM public.application_logs l
            JOIN public.services s ON s.id = l.service_id
            WHERE s.name = %s AND l.latency_ms IS NOT NULL
              AND l.timestamp >= %s AND l.timestamp < %s;
            """,
            (service_name, start_time, end_time),
        )
        n, p50, p95, mx = cur.fetchone()
    return {"count": n, "p50_ms": _f(p50), "p95_ms": _f(p95), "max_ms": _f(mx)}


# ---------- 2. latency per minute (shows sudden jump vs slow creep) ----------

def get_latency_timeline(service_name, start_time, end_time, limit=30):
    with get_connection() as cur:
        cur.execute(
            """
            SELECT date_trunc('minute', l.timestamp) AS minute,
                   COUNT(*) AS requests,
                   percentile_cont(0.95) WITHIN GROUP (ORDER BY l.latency_ms) AS p95
            FROM public.application_logs l
            JOIN public.services s ON s.id = l.service_id
            WHERE s.name = %s AND l.latency_ms IS NOT NULL
              AND l.timestamp >= %s AND l.timestamp < %s
            GROUP BY minute ORDER BY minute DESC
            LIMIT %s;
            """,
            (service_name, start_time, end_time, limit),
        )
        rows = cur.fetchall()
    rows.reverse()  # oldest first
    return [{"minute": m.isoformat(), "requests": n, "p95_ms": _f(p)} for m, n, p in rows]


# ---------- 3. the slow requests themselves ----------

def get_slow_requests(service_name, start_time, end_time, threshold_ms=None, limit=MAX_LINES):
    """Slowest rows in the window. If threshold_ms is None, just the top N slowest."""
    with get_connection() as cur:
        cur.execute(
            BASE_SELECT + """
            WHERE s.name = %s AND l.latency_ms IS NOT NULL
              AND l.timestamp >= %s AND l.timestamp < %s
              AND (%s::float IS NULL OR l.latency_ms >= %s::float)
            ORDER BY l.latency_ms DESC
            LIMIT %s;
            """,
            (service_name, start_time, end_time, threshold_ms, threshold_ms, limit),
        )
        return [_fmt(_row(r)) for r in cur.fetchall()]


# ---------- 4. neighbouring services (is the slowness coming from upstream?) ----------

def get_neighbor_latency(service_name, base_start, inc_start, inc_end):
    """p95 per OTHER service: baseline window vs incident window."""
    with get_connection() as cur:
        cur.execute(
            """
            SELECT s.name,
                   percentile_cont(0.95) WITHIN GROUP (ORDER BY l.latency_ms)
                       FILTER (WHERE l.timestamp <  %s) AS base_p95,
                   percentile_cont(0.95) WITHIN GROUP (ORDER BY l.latency_ms)
                       FILTER (WHERE l.timestamp >= %s) AS inc_p95
            FROM public.application_logs l
            JOIN public.services s ON s.id = l.service_id
            WHERE s.name <> %s AND l.latency_ms IS NOT NULL
              AND l.timestamp >= %s AND l.timestamp < %s
            GROUP BY s.name;
            """,
            (inc_start, inc_start, service_name, base_start, inc_end),
        )
        rows = cur.fetchall()

    out = []
    for name, b, i in rows:
        b, i = _f(b), _f(i)
        out.append({
            "service": name,
            "baseline_p95_ms": b,
            "incident_p95_ms": i,
            "multiplier": round(i / b, 1) if b and i else None,
        })
    return sorted(out, key=lambda x: x["multiplier"] or 0, reverse=True)


# ---------- put it together ----------

def fetch_latency_spike(incident):
    """incident = {incident_id, service, rule, fingerprint}  (started_at optional)"""
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


# ======================= Incident Report (LLM result) =====================================
#
# Saves the LLM investigation result on the incident row.
#   Symptoms    -> description
#   Root cause  -> root_cause
#   Solution    -> resolution
#   Evidence    -> evidence               (new column, see ensure_report_columns)
#   Confidence  -> resolution_confidence  ('inferred' or 'unknown', never 'confirmed')
#
# This does NOT close the incident: status and resolved_at are left alone.


def ensure_report_columns():
    """Adds the evidence column (safe to call on every start)."""
    with get_connection() as cur:
        cur.execute("ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS evidence text;")


# ---------- parsing the LLM text ----------

_SECTION_RE = re.compile(
    r"^\s*(Symptoms|Root cause|Solution|Evidence|Confidence)\s*:\s*",
    re.IGNORECASE | re.MULTILINE,
)


def parse_report(text):
    """
    Splits the LLM report into its five sections.
    Returns a dict with keys: symptoms, root_cause, solution, evidence, confidence
    (a missing section gives None).
    """
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


# ---------- cleaning the values before they go into the db ----------

_UNDETERMINED_PHRASES = (
    "unable to determine",
    "cannot be determined",
    "can't be determined",
    "not enough evidence",
    "insufficient evidence",
    "no specific fix",
    "no fix can be",
    "unknown",
)


def is_undetermined(text):
    """True when the LLM said 'I don't know' instead of giving a real answer."""
    if not text:
        return True
    lowered = text.lower()
    return any(p in lowered for p in _UNDETERMINED_PHRASES)


def map_confidence(llm_confidence, root_cause):
    """
    LLM says HIGH / MEDIUM / LOW. The db uses confirmed / inferred / unknown.
    Nobody has confirmed an LLM guess, so 'confirmed' is never used here.
    """
    if root_cause is None:
        return "unknown"
    if (llm_confidence or "").upper() in ("HIGH", "MEDIUM"):
        return "inferred"
    return "unknown"


# ---------- the function you call from the graph ----------

SAVE_REPORT_SQL = """
    UPDATE public.incidents
    SET description = COALESCE(%s, description),
        root_cause = %s,
        resolution = %s,
        resolution_confidence = %s,
        evidence = %s
    WHERE id = %s
      AND root_cause IS NULL;   -- never overwrite a root cause someone already wrote
"""


def save_investigation_result(
    incident_id,
    symptoms=None,
    root_cause=None,
    solution=None,
    evidence=None,
    confidence=None,
):
    """
    Saves the LLM investigation result on the incident row.
    Returns True if the row was updated, False if it was skipped
    (incident not found, or it already has a root cause).

    "Unable to determine..." style answers are NOT saved as root_cause /
    resolution (they stay NULL), and the confidence becomes 'unknown'.
    Otherwise those placeholder sentences would later show up as "fixes"
    when you search for similar past incidents.
    """
    if is_undetermined(root_cause):
        root_cause = None
    if is_undetermined(solution):
        solution = None

    db_confidence = map_confidence(confidence, root_cause)

    with get_connection() as cur:
        cur.execute(
            SAVE_REPORT_SQL,
            (symptoms, root_cause, solution, db_confidence, evidence, incident_id),
        )
        return cur.rowcount == 1