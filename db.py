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