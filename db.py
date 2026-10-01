import os
from contextlib import contextmanager

import psycopg2
import psycopg2.pool
from dotenv import load_dotenv


load_dotenv()


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

from datetime import datetime, timedelta


ERROR_LEVELS = ["ERROR", "CRITICAL", "FATAL"]
 
 
# --------------------------------------------------
# TOOL 1: FIND WINDOWS
# --------------------------------------------------
 
def find_windows(started_at, resolved_at=None, baseline_gap_minutes=0):
    """
    Incident window = [started_at, resolved_at or now).
    Baseline window = same length, ending right before the incident
    (optionally shifted back by baseline_gap_minutes to skip the ramp-up).
    """
    incident_end = resolved_at or datetime.now(started_at.tzinfo)
    duration = incident_end - started_at
 
    baseline_end = started_at - timedelta(minutes=baseline_gap_minutes)
    baseline_start = baseline_end - duration
 
    return {
        "incident": {
            "start": started_at,
            "end": incident_end,
            "minutes": round(duration.total_seconds() / 60, 1),
        },
        "baseline": {
            "start": baseline_start,
            "end": baseline_end,
            "minutes": round(duration.total_seconds() / 60, 1),
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
 
def collect_error_rate_evidence(service_name, started_at, resolved_at=None, top_n=10):
    windows = find_windows(started_at, resolved_at)
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
 