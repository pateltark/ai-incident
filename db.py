import os
import re
import hashlib
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from collections import Counter
import psycopg2
import psycopg2.pool
import clickhouse_connect
from dotenv import load_dotenv

load_dotenv()


# --------------------------------------------------
# FINGERPRINTING
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
# DATABASE CONNECTIONS (PostgreSQL + Thread-Local ClickHouse)
# --------------------------------------------------

# Postgres Pool for Control Plane (Incidents, Services, Embeddings)
connection_pool = psycopg2.pool.ThreadedConnectionPool(
    minconn=1,
    maxconn=int(os.getenv("DB_POOL_MAX", "10")),
    database=os.getenv("DB_NAME", "incident_copilot"),
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


# Thread-Local ClickHouse Client Storage
_thread_local = threading.local()


def get_ch_client():
    """Returns a ClickHouse client session isolated to the current calling thread."""
    if not hasattr(_thread_local, "client"):
        _thread_local.client = clickhouse_connect.get_client(
            host=os.getenv("CH_HOST", "localhost"),
            port=int(os.getenv("CH_PORT", "8123")),
            username=os.getenv("CH_USER", "default"),
            password=os.getenv("CH_PASSWORD", ""),
            database=os.getenv("CH_DATABASE", "incident_copilot"),
        )
    return _thread_local.client


def ch_query(query, parameters=None):
    """Helper function for thread-safe ClickHouse queries."""
    client = get_ch_client()
    return client.query(query, parameters=parameters)


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
# APPLICATION LOGS (ClickHouse)
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

    result = ch_query(query, parameters=params)
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

    result = ch_query(query, parameters=params)
    return result.result_rows


# ======================= Error Rate =====================================

ERROR_LEVELS = ["ERROR", "CRITICAL", "FATAL"]

INCIDENT_LOOKBACK_MIN = 15
BASELINE_MIN = 60


def _to_datetime(value):
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


def find_windows(started_at, resolved_at=None, baseline_gap_minutes=0, baseline_minutes=None):
    started_at = _to_datetime(started_at)
    resolved_at = _to_datetime(resolved_at)

    if resolved_at:
        incident_end = resolved_at
    elif started_at.tzinfo is None:
        # DB timestamps are naive UTC, so use naive UTC "now" (not local IST)
        incident_end = datetime.now(timezone.utc).replace(tzinfo=None)
    else:
        incident_end = datetime.now(timezone.utc)

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
    result = ch_query(query, parameters={
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


def group_errors(service_name, start_time, end_time, limit=10):
    query = """
        WITH errs AS (
            SELECT
                message,
                request_id,
                timestamp,
                REGEXP_REPLACE(
                    REGEXP_REPLACE(
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
            count(*)            AS count,
            min(timestamp)      AS first_seen,
            max(timestamp)      AS last_seen,
            argMin(message, timestamp)    AS sample_message,
            argMin(request_id, timestamp) AS sample_request_id
        FROM errs
        GROUP BY fingerprint
        ORDER BY count DESC
        LIMIT %(limit)s;
    """
    result = ch_query(query, parameters={
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
    result = ch_query(query, parameters={"service": service, "hours": HISTORY_HOURS})
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
    result = ch_query(query, parameters={
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
    result = ch_query(query, parameters={"req_ids": tuple(request_ids)})
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
    if x is None or x != x:
        return None
    return round(float(x), 1)


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
    result = ch_query(query, parameters={
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
    result = ch_query(query, parameters={
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
    result = ch_query(query, parameters={
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
            quantileIf(0.95)(latency_ms, timestamp <  %(inc_start)s) AS base_p95,
            quantileIf(0.95)(latency_ms, timestamp >= %(inc_start)s) AS inc_p95
        FROM incident_copilot.application_logs
        WHERE service_name <> %(service)s
          AND latency_ms IS NOT NULL
          AND timestamp >= %(base_start)s
          AND timestamp < %(inc_end)s
        GROUP BY service_name;
    """
    result = ch_query(query, parameters={
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


# ======================= Pattern Rules =====================================

LOG_PATTERN_RULES = {
    "dependency_failure": {
        "regex": r"connection refused|timed? ?out|throttl|could not connect|name resolution|certificate|\bssl\b|\b(502|503|504)\b",
        "levels": ("ERROR", "WARN"),
        "min_count": 5,
        "minutes": 5,
        "severity": "high",
    },
    "resource_exhaustion": {
        "regex": r"out of memory|\boom\b|too many connections|no space left|pool exhausted|disk full|\bkilled\b",
        "levels": ("ERROR", "WARN"),
        "min_count": 3,
        "minutes": 5,
        "severity": "high",
    },
    "queue_backlog": {
        "regex": r"dead.?letter|\bdlq\b|queue.*(full|backlog)|consumer lag",
        "levels": ("ERROR", "WARN"),
        "min_count": 3,
        "minutes": 5,
        "severity": "medium",
    },
    "auth_failure_spike": {
        "regex": r"unauthorized|authentication failed|invalid token|failed login|forbidden",
        "levels": ("ERROR", "WARN", "INFO"),
        "min_count": 20,
        "minutes": 5,
        "severity": "high",
    },
}

PATTERN_LOOKBACK_MIN = 15
PATTERN_BASELINE_MIN = 60

_FP_SQL = """REGEXP_REPLACE(
                    REGEXP_REPLACE(
                        message,
                        '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
                        '<uuid>'
                    ),
                    '[0-9]+', '<n>'
                )"""


def _re(regex):
    return "(?i)" + regex


def count_recent_pattern_hits(service_name, regex, levels, minutes):
    query = """
        SELECT count(*), argMax(message, timestamp)
        FROM incident_copilot.application_logs
        WHERE service_name = %(service)s
          AND UPPER(level) IN %(levels)s
          AND timestamp >= now() - INTERVAL %(mins)s MINUTE
          AND match(message, %(regex)s);
    """
    result = ch_query(query, parameters={
        "service": service_name, "levels": tuple(levels),
        "mins": minutes, "regex": _re(regex),
    })
    count, sample = result.result_rows[0]
    return count, (sample or None)


def get_pattern_count(service_name, regex, levels, start_time, end_time):
    query = """
        SELECT count(*)
        FROM incident_copilot.application_logs
        WHERE service_name = %(service)s
          AND UPPER(level) IN %(levels)s
          AND timestamp >= %(start)s AND timestamp < %(end)s
          AND match(message, %(regex)s);
    """
    result = ch_query(query, parameters={
        "service": service_name, "levels": tuple(levels),
        "start": start_time, "end": end_time, "regex": _re(regex),
    })
    return result.result_rows[0][0]


def get_pattern_groups(service_name, regex, levels, start_time, end_time, limit=10):
    query = """
        SELECT fingerprint,
               count(*)                       AS count,
               min(timestamp)                 AS first_seen,
               max(timestamp)                 AS last_seen,
               argMin(message, timestamp)     AS sample_message,
               argMin(request_id, timestamp)  AS sample_request_id
        FROM (
            SELECT message, request_id, timestamp, """ + _FP_SQL + """ AS fingerprint
            FROM incident_copilot.application_logs
            WHERE service_name = %(service)s
              AND UPPER(level) IN %(levels)s
              AND timestamp >= %(start)s AND timestamp < %(end)s
              AND match(message, %(regex)s)
        )
        GROUP BY fingerprint
        ORDER BY count DESC
        LIMIT %(limit)s;
    """
    result = ch_query(query, parameters={
        "service": service_name, "levels": tuple(levels),
        "start": start_time, "end": end_time,
        "regex": _re(regex), "limit": limit,
    })
    return [
        {
            "fingerprint": r[0], "count": r[1],
            "first_seen": r[2], "last_seen": r[3],
            "sample_message": r[4], "sample_request_id": r[5],
        }
        for r in result.result_rows
    ]


def get_pattern_samples(service_name, regex, levels, start_time, end_time, limit=5):
    query = BASE_SELECT + """
        WHERE service_name = %(service)s
          AND UPPER(level) IN %(levels)s
          AND timestamp >= %(start)s AND timestamp < %(end)s
          AND match(message, %(regex)s)
        ORDER BY timestamp
        LIMIT %(limit)s;
    """
    result = ch_query(query, parameters={
        "service": service_name, "levels": tuple(levels),
        "start": start_time, "end": end_time,
        "regex": _re(regex), "limit": limit,
    })
    return [_fmt(_row(r)) for r in result.result_rows]


def get_pattern_timeline(service_name, regex, levels, start_time, end_time, limit=30):
    query = """
        SELECT toStartOfMinute(timestamp) AS minute,
               countIf(UPPER(level) IN %(levels)s AND match(message, %(regex)s)) AS matches,
               count(*) AS total_logs
        FROM incident_copilot.application_logs
        WHERE service_name = %(service)s
          AND timestamp >= %(start)s AND timestamp < %(end)s
        GROUP BY minute
        ORDER BY minute DESC
        LIMIT %(limit)s;
    """
    result = ch_query(query, parameters={
        "service": service_name, "levels": tuple(levels),
        "start": start_time, "end": end_time,
        "regex": _re(regex), "limit": limit,
    })
    rows = result.result_rows
    rows.reverse()
    return [
        {"minute": m.isoformat() if isinstance(m, datetime) else str(m),
         "matches": n, "total_logs": t}
        for m, n, t in rows
    ]


def get_pattern_by_service(regex, levels, start_time, end_time):
    query = """
        SELECT service_name,
               countIf(UPPER(level) IN %(levels)s AND match(message, %(regex)s)) AS matches
        FROM incident_copilot.application_logs
        WHERE timestamp >= %(start)s AND timestamp < %(end)s
        GROUP BY service_name
        HAVING matches > 0
        ORDER BY matches DESC;
    """
    result = ch_query(query, parameters={
        "levels": tuple(levels), "start": start_time, "end": end_time, "regex": _re(regex),
    })
    return [{"service": s, "matches": n} for s, n in result.result_rows]


def fetch_pattern_incident(incident):
    service, rule = incident["service"], incident["rule"]
    cfg = LOG_PATTERN_RULES[rule]
    regex, levels = cfg["regex"], cfg["levels"]

    started_at = incident.get("started_at") or get_incident_started_at(incident["incident_id"])
    started_at = _to_datetime(started_at)

    windows = find_windows(
        started_at - timedelta(minutes=PATTERN_LOOKBACK_MIN),
        incident.get("resolved_at"),
        baseline_minutes=PATTERN_BASELINE_MIN,
    )
    inc, base = windows["incident"], windows["baseline"]

    inc_count = get_pattern_count(service, regex, levels, inc["start"], inc["end"])
    base_count = get_pattern_count(service, regex, levels, base["start"], base["end"])
    groups = get_pattern_groups(service, regex, levels, inc["start"], inc["end"], 10)
    samples = get_pattern_samples(service, regex, levels, inc["start"], inc["end"], 5)
    timeline = get_pattern_timeline(service, regex, levels, base["start"], inc["end"])
    by_service = get_pattern_by_service(regex, levels, inc["start"], inc["end"])

    trace = get_trace(samples)
    first_seen = min((g["first_seen"] for g in groups), default=None)
    warns = get_warns_before(service, first_seen)

    inc_per_min = round(inc_count / inc["minutes"], 2) if inc["minutes"] else None
    base_per_min = round(base_count / base["minutes"], 2) if base["minutes"] else None

    others = [s for s in by_service if s["service"] != service]

    notes = []
    if inc_count == 0:
        notes.append("No logs matching this rule's pattern in the incident window.")
    if base_count == 0 and inc_count > 0:
        notes.append("The pattern did not appear at all in the baseline hour, so it is new.")
    if others:
        names = ", ".join(f"{s['service']} ({s['matches']})" for s in others)
        notes.append(f"The same pattern also appears in: {names} (possible shared dependency).")
    elif inc_count > 0:
        notes.append("No other service shows this pattern, so the problem looks local to this service.")
    if not warns:
        notes.append("No WARN logs found before the first match.")
    if trace and all(len(v) <= 1 for v in trace.values()):
        notes.append("Each traced request has only one log line (no cross-service trail).")

    return {
        "incident": {"type": rule, "service": service},
        "windows": windows,
        "evidence": {
            "pattern_matched": regex,
            "match_change": {
                "baseline_count": base_count, "incident_count": inc_count,
                "baseline_per_min": base_per_min, "incident_per_min": inc_per_min,
            },
            "top_match_groups": groups,
            "sample_lines": samples,
            "timeline_by_minute": timeline,
            "services_with_same_pattern": by_service,
            "warns_before_first_match": warns,
            "request_traces": trace,
            "notes": notes,
        },
    }


# ======================= Traffic Silence =====================================

SILENCE_HISTORY_MIN = 60
SILENCE_ACTIVITY_HOURS = 24


def get_service_activity(recent_minutes=SILENCE_HISTORY_MIN, hours=SILENCE_ACTIVITY_HOURS):
    query = """
        SELECT service_name,
               max(timestamp) AS last_log_at,
               countIf(timestamp >= now() - INTERVAL %(mins)s MINUTE) AS logs_recent
        FROM incident_copilot.application_logs
        WHERE timestamp >= now() - INTERVAL %(hours)s HOUR
        GROUP BY service_name;
    """
    result = ch_query(query, parameters={"mins": recent_minutes, "hours": hours})
    return result.result_rows


def get_volume_timeline(service_name, start_time, end_time, limit=SILENCE_HISTORY_MIN):
    query = """
        SELECT toStartOfMinute(timestamp) AS minute, count(*) AS logs
        FROM incident_copilot.application_logs
        WHERE service_name = %(service)s
          AND timestamp >= %(start)s AND timestamp < %(end)s
        GROUP BY minute
        ORDER BY minute DESC
        LIMIT %(limit)s;
    """
    result = ch_query(query, parameters={
        "service": service_name, "start": start_time, "end": end_time, "limit": limit,
    })
    rows = result.result_rows
    rows.reverse()
    return [
        {"minute": m.isoformat() if isinstance(m, datetime) else str(m), "logs": n}
        for m, n in rows
    ]


def get_last_lines(service_name, limit=5, only_problems=False):
    level_filter = "AND level IN ('ERROR', 'WARN')" if only_problems else ""
    query = BASE_SELECT + f"""
        WHERE service_name = %(service)s
          {level_filter}
        ORDER BY timestamp DESC
        LIMIT %(limit)s;
    """
    result = ch_query(query, parameters={"service": service_name, "limit": limit})
    rows = [_fmt(_row(r)) for r in result.result_rows]
    rows.reverse()
    return rows


def fetch_silence(incident):
    service = incident["service"]
    activity = get_service_activity()

    mine = next((r for r in activity if r[0] == service), None)
    last_log_at = mine[1] if mine else None

    others = []
    for name, last_at, recent in activity:
        if name == service:
            continue
        others.append({
            "service": name,
            "last_log_at": last_at.isoformat() if isinstance(last_at, datetime) else str(last_at),
            "logs_last_60min": recent,
        })
    silent_others = [o["service"] for o in others if not o["logs_last_60min"]]

    timeline = []
    if last_log_at:
        timeline = get_volume_timeline(
            service,
            last_log_at - timedelta(minutes=SILENCE_HISTORY_MIN),
            last_log_at + timedelta(minutes=1),
        )

    notes = []
    if mine is None:
        notes.append(f"No logs from this service at all in the last {SILENCE_ACTIVITY_HOURS} hours.")
    if silent_others:
        notes.append(f"Other services are silent too: {', '.join(silent_others)}.")
    elif others:
        notes.append("Other services are still logging, so the silence is specific to this service.")

    return {
        "incident": {"type": "traffic_silence", "service": service},
        "evidence": {
            "last_log_at": last_log_at.isoformat() if isinstance(last_log_at, datetime) else None,
            "logs_last_60min": mine[2] if mine else 0,
            "volume_before_silence_by_minute": timeline,
            "last_lines": get_last_lines(service, limit=5),
            "last_warn_error_lines": get_last_lines(service, limit=MAX_LINES, only_problems=True),
            "other_services": others,
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


# ======================= Extra Rules: Config & Helpers =====================

METRIC_RULES = {
    "cpu_high":            {"metric": "cpu_pct",          "kind": "above",    "threshold": 90,  "minutes": 5,  "min_samples": 3, "severity": "high",   "family": "resource"},
    "memory_high":         {"metric": "memory_pct",       "kind": "above",    "threshold": 90,  "minutes": 5,  "min_samples": 3, "severity": "high",   "family": "resource"},
    "disk_high":           {"metric": "disk_pct",         "kind": "above",    "threshold": 85,  "minutes": 5,  "min_samples": 3, "severity": "high",   "family": "resource"},
    "restart_loop":        {"metric": "restart_count",    "kind": "increase", "threshold": 2,   "minutes": 10, "min_samples": 2, "severity": "high",   "family": "resource"},
    "queue_age_high":      {"metric": "sqs_oldest_age_s", "kind": "above",    "threshold": 300, "minutes": 5,  "min_samples": 3, "severity": "medium", "family": "queue"},
    "queue_depth_growing": {"metric": "sqs_depth",        "kind": "growing",  "threshold": 100, "minutes": 10, "min_samples": 4, "severity": "medium", "family": "queue"},
    "dlq_not_empty":       {"metric": "sqs_dlq_depth",    "kind": "above",    "threshold": 0,   "minutes": 2,  "min_samples": 1, "severity": "medium", "family": "queue"},
}

RESOURCE_METRICS = ["cpu_pct", "memory_pct", "disk_pct", "restart_count"]
QUEUE_METRICS = ["sqs_oldest_age_s", "sqs_depth", "sqs_dlq_depth", "consumer_count"]

SECURITY_RE = re.compile(
    r"unauthorized|authentication failed|invalid token|failed login|forbidden|\b(?:401|403|429|5\d\d)\b",
    re.IGNORECASE,
)
_ENDPOINT_RE = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE)\s+(\S+)")
SECURITY_MINUTES = 5
SECURITY_MIN_PER_IP = 15

DEPENDENCY_NAMES = ["rds", "aurora", "redis", "elasticache", "dynamodb", "s3", "sqs", "sns",
                    "kafka", "postgres", "mysql", "mongodb", "stripe"]

CHANGE_LOOKBACK_MIN = 60


def _incident_windows(incident, lookback=15, baseline=60):
    started_at = incident.get("started_at") or get_incident_started_at(incident["incident_id"])
    started_at = _to_datetime(started_at)
    return find_windows(
        started_at - timedelta(minutes=lookback),
        incident.get("resolved_at"),
        baseline_minutes=baseline,
    )


def get_metric_timeline(service_name, metric, start_time, end_time, limit=60):
    with get_connection() as cur:
        cur.execute(
            """
            SELECT date_trunc('minute', m.timestamp) AS minute, round(avg(m.value)::numeric, 1)
            FROM public.metrics m JOIN public.services s ON s.id = m.service_id
            WHERE s.name = %s AND m.metric = %s AND m.timestamp >= %s AND m.timestamp < %s
            GROUP BY 1 ORDER BY 1 DESC LIMIT %s;
            """,
            (service_name, metric, start_time, end_time, limit),
        )
        rows = cur.fetchall()
    rows.reverse()
    return [{"minute": m.isoformat(), "value": float(v)} for m, v in rows]


def get_metric_timelines(service_name, metrics, start_time, end_time):
    out = {}
    for name in metrics:
        series = get_metric_timeline(service_name, name, start_time, end_time)
        if series:
            out[name] = series
    return out


def get_metrics_by_prefix(prefix, start_time, end_time, limit=30):
    with get_connection() as cur:
        cur.execute(
            """
            SELECT metric, date_trunc('minute', timestamp), round(avg(value)::numeric, 1)
            FROM public.metrics
            WHERE metric LIKE %s AND timestamp >= %s AND timestamp < %s
            GROUP BY 1, 2 ORDER BY 1, 2;
            """,
            (prefix + "\\_%", start_time, end_time),
        )
        rows = cur.fetchall()
    out = {}
    for metric, minute, value in rows:
        out.setdefault(metric, []).append({"minute": minute.isoformat(), "value": float(value)})
    return {k: v[-limit:] for k, v in out.items()}


def get_events(start_time, end_time, kinds=None, service_name=None):
    with get_connection() as cur:
        cur.execute(
            """
            SELECT c.timestamp, c.kind, c.description, s.name
            FROM public.change_events c
            LEFT JOIN public.services s ON s.id = c.service_id
            WHERE c.timestamp >= %s AND c.timestamp < %s
              AND (%s::text[] IS NULL OR c.kind = ANY(%s))
              AND (%s::text IS NULL OR s.name = %s OR c.service_id IS NULL)
            ORDER BY c.timestamp;
            """,
            (start_time, end_time, kinds, kinds, service_name, service_name),
        )
        rows = cur.fetchall()
    return [{"ts": t.isoformat(), "kind": k, "description": d, "service": s} for t, k, d, s in rows]


def get_recent_changes(service_name, started_at, minutes=CHANGE_LOOKBACK_MIN):
    started_at = _to_datetime(started_at)
    return get_events(started_at - timedelta(minutes=minutes), started_at, None, service_name)


def get_minute_counts(service_name, start_time, end_time):
    query = """
        SELECT toStartOfMinute(timestamp) AS minute, count(*) AS logs
        FROM incident_copilot.application_logs
        WHERE service_name = %(service)s AND timestamp >= %(start)s AND timestamp < %(end)s
        GROUP BY minute ORDER BY minute;
    """
    result = ch_query(query, parameters={"service": service_name, "start": start_time, "end": end_time})
    return [{"minute": m.isoformat(), "logs": n} for m, n in result.result_rows]


def get_neighbor_volume(service_name, start_time, end_time):
    day = timedelta(days=1)
    query = """
        SELECT service_name,
               countIf(timestamp >= %(start)s AND timestamp < %(end)s) AS now_count,
               countIf(timestamp >= %(y_start)s AND timestamp < %(y_end)s) AS yesterday_count
        FROM incident_copilot.application_logs
        WHERE service_name <> %(service)s AND timestamp >= %(y_start)s AND timestamp < %(end)s
        GROUP BY service_name;
    """
    result = ch_query(query, parameters={
        "service": service_name, "start": start_time, "end": end_time,
        "y_start": start_time - day, "y_end": end_time - day,
    })
    return [
        {"service": s, "logs_now": n, "logs_same_time_yesterday": y,
         "ratio": round(n / y, 2) if y else None}
        for s, n, y in result.result_rows
    ]


def fetch_traffic_drop(incident):
    service = incident["service"]
    w = _incident_windows(incident, lookback=10)
    inc = w["incident"]
    start = inc["start"] - timedelta(minutes=30)
    day = timedelta(days=1)

    today = get_minute_counts(service, start, inc["end"])
    yesterday = get_minute_counts(service, start - day, inc["end"] - day)
    neighbors = get_neighbor_volume(service, inc["start"], inc["end"])
    alb = get_metric_timeline(service, "alb_request_count", start, inc["end"])

    dropped = [n["service"] for n in neighbors if n["ratio"] is not None and n["ratio"] < 0.5]
    notes = []
    if dropped:
        notes.append(f"Other services also dropped vs yesterday: {', '.join(dropped)}.")
    elif neighbors:
        notes.append("Other services are normal, so the drop looks specific to this service.")

    return {
        "incident": {"type": "traffic_drop", "service": service},
        "windows": w,
        "evidence": {
            "logs_per_minute_today": today,
            "logs_per_minute_same_time_yesterday": yesterday,
            "neighbor_services": neighbors,
            "alb_request_count_by_minute": alb,
            "last_lines": get_last_lines(service, limit=5),
            "notes": notes,
        },
    }


def fetch_resource_evidence(incident):
    service, rule = incident["service"], incident["rule"]
    w = _incident_windows(incident)
    inc, base = w["incident"], w["baseline"]
    cfg = LOG_PATTERN_RULES["resource_exhaustion"]

    metrics = get_metric_timelines(service, RESOURCE_METRICS, base["start"], inc["end"])
    events = get_events(base["start"], inc["end"], ["restart", "oom", "oom_kill", "scale"], service)
    oom_logs = get_pattern_samples(service, cfg["regex"], cfg["levels"], inc["start"], inc["end"], 10)
    errors = group_errors(service, inc["start"], inc["end"], 10)

    notes = []
    if not metrics:
        notes.append("No resource metrics found for this service.")

    return {
        "incident": {"type": rule, "service": service},
        "windows": w,
        "evidence": {
            "metric": METRIC_RULES[rule]["metric"],
            "metric_timelines": metrics,
            "restart_oom_events": events,
            "oom_like_log_lines": oom_logs,
            "top_error_groups": errors,
            "notes": notes,
        },
    }


def fetch_queue_evidence(incident):
    service, rule = incident["service"], incident["rule"]
    w = _incident_windows(incident)
    inc, base = w["incident"], w["baseline"]
    cfg = LOG_PATTERN_RULES["queue_backlog"]

    metrics = get_metric_timelines(service, QUEUE_METRICS, base["start"], inc["end"])
    consumer_errors = group_errors(service, inc["start"], inc["end"], 10)
    queue_logs = get_pattern_samples(service, cfg["regex"], cfg["levels"], inc["start"], inc["end"], 5)

    notes = []
    if not metrics:
        notes.append("No queue metrics found for this service.")

    return {
        "incident": {"type": rule, "service": service},
        "windows": w,
        "evidence": {
            "metric": METRIC_RULES[rule]["metric"],
            "queue_metric_timelines": metrics,
            "consumer_error_groups": consumer_errors,
            "queue_log_lines": queue_logs,
            "notes": notes,
        },
    }


def fetch_dependency_evidence(incident):
    service = incident["service"]
    result = fetch_pattern_incident(incident)
    inc = result["windows"]["incident"]
    cfg = LOG_PATTERN_RULES["dependency_failure"]

    lines = get_pattern_samples(service, cfg["regex"], cfg["levels"], inc["start"], inc["end"], 500)
    counts = Counter()
    for line in lines:
        low = line["message"].lower()
        for dep in DEPENDENCY_NAMES:
            if re.search(rf"\b{dep}\b", low):
                counts[dep] += 1

    ev = result["evidence"]
    ev["errors_by_dependency"] = dict(counts.most_common())
    ev["dependency_events"] = get_events(
        inc["start"] - timedelta(minutes=15), inc["end"], ["aws_health", "rds_event", "dependency"], None)
    ev["dependency_metrics"] = {
        dep: get_metrics_by_prefix(dep, inc["start"] - timedelta(minutes=30), inc["end"])
        for dep in list(counts)[:3]
    }
    return result


def fetch_security_evidence(incident):
    service = incident["service"]
    w = _incident_windows(incident, lookback=10)
    inc = w["incident"]

    result = ch_query(
        BASE_SELECT + """
        WHERE service_name = %(service)s AND timestamp >= %(start)s AND timestamp < %(end)s
        ORDER BY timestamp LIMIT 20000;
        """,
        parameters={"service": service, "start": inc["start"], "end": inc["end"]},
    )
    hits = [r for r in (_row(x) for x in result.result_rows) if SECURITY_RE.search(r["message"])]

    ips, endpoints, per_minute = Counter(), Counter(), Counter()
    for r in hits:
        m = _IP_RE.search(r["message"])
        ips[m.group(0) if m else "unknown"] += 1
        e = _ENDPOINT_RE.search(r["message"])
        if e:
            endpoints[f"{e.group(1)} {e.group(2)}"] += 1
        per_minute[r["ts"].replace(second=0, microsecond=0).isoformat()] += 1

    notes = []
    if not hits:
        notes.append("No auth-failure or 4xx/5xx lines found in the incident window.")

    return {
        "incident": {"type": "security_ip_spike", "service": service},
        "windows": w,
        "evidence": {
            "matching_lines": len(hits),
            "top_ips": [{"ip": ip, "count": c} for ip, c in ips.most_common(10)],
            "top_endpoints": [{"endpoint": e, "count": c} for e, c in endpoints.most_common(10)],
            "timeline_by_minute": [{"minute": k, "count": v} for k, v in sorted(per_minute.items())],
            "sample_lines": [_fmt(h) for h in hits[:5]],
            "notes": notes,
        },
    }


def fetch_certificate_evidence(incident):
    with get_connection() as cur:
        cur.execute(
            """
            SELECT name, expires_at, services
            FROM public.certificates
            WHERE expires_at < now() + interval '30 days'
            ORDER BY expires_at;
            """
        )
        rows = cur.fetchall()
    now = datetime.now(timezone.utc)
    certs = []
    for name, expires_at, services in rows:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        certs.append({
            "name": name,
            "expires_at": expires_at.isoformat(),
            "days_left": (expires_at - now).days,
            "services": services,
        })
    return {
        "incident": {"type": "certificate_expiry", "service": incident["service"]},
        "evidence": {
            "expiring_certificates": certs,
            "notes": [] if certs else ["No certificate expiring within 30 days was found."],
        },
    }


# --------------------------------------------------
# SINGLE ENTRY POINT
# --------------------------------------------------

def fetch_evidence(incident):
    rule = incident["rule"]

    if rule == "error_rate":
        result = collect_error_rate_evidence(
            service_name=incident["service"], started_at=incident["started_at"],
            resolved_at=incident.get("resolved_at"), top_n=10)
    elif rule == "new_error_type":
        result = fetch_new_error_type(incident)
    elif rule == "latency_spike":
        result = fetch_latency_spike(incident)
    elif rule == "traffic_silence":
        result = fetch_silence(incident)
    elif rule == "traffic_drop":
        result = fetch_traffic_drop(incident)
    elif rule == "dependency_failure":
        result = fetch_dependency_evidence(incident)
    elif rule in LOG_PATTERN_RULES:
        result = fetch_pattern_incident(incident)
    elif rule in METRIC_RULES:
        family = METRIC_RULES[rule]["family"]
        result = fetch_resource_evidence(incident) if family == "resource" else fetch_queue_evidence(incident)
    elif rule == "security_ip_spike":
        result = fetch_security_evidence(incident)
    elif rule == "certificate_expiry":
        result = fetch_certificate_evidence(incident)
    else:
        raise ValueError(f"Unknown rule: {rule}")

    try:
        result["recent_changes"] = get_recent_changes(incident["service"], incident["started_at"])
    except Exception as e:
        result["recent_changes"] = []
        result.setdefault("evidence", {}).setdefault("notes", []).append(
            f"Could not read change_events: {e}")
    return result
