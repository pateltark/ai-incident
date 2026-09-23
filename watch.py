"""
watch.py

Run this in a second terminal alongside console.py to see raw log rows
land in the database live, as you trigger them - the DB equivalent of
`tail -f`. It only shows NEW rows from the moment it starts (not your
existing 46k+ history), polling every second by default.

Usage:
    python watch.py                          # all services, application_logs
    python watch.py --service checkout       # just one service
    python watch.py --incidents              # watch the incidents table instead
    python watch.py --interval 0.5           # poll faster

Stop with Ctrl+C.
"""

import argparse
import os
import time

import psycopg2
from dotenv import load_dotenv

LEVEL_COLOR = {
    "ERROR": "\033[31m",
    "WARN": "\033[33m",
    "INFO": "\033[37m",
}
RESET = "\033[0m"


def load_db_config():
    load_dotenv()
    if os.getenv("DATABASE_URL"):
        return {"dsn": os.environ["DATABASE_URL"]}
    return {
        "dsn": None,
        "host": os.getenv("DB_HOST", "localhost"),
        "port": os.getenv("DB_PORT", "5432"),
        "dbname": os.getenv("DB_NAME", "incident_copilot"),
        "user": os.getenv("DB_USER", "postgres"),
        "password": os.getenv("DB_PASSWORD", ""),
    }


def connect():
    cfg = load_db_config()
    if cfg.get("dsn"):
        return psycopg2.connect(cfg["dsn"])
    return psycopg2.connect(
        host=cfg["host"], port=cfg["port"], dbname=cfg["dbname"],
        user=cfg["user"], password=cfg["password"],
    )


def get_max_id(conn, table):
    with conn.cursor() as cur:
        cur.execute(f"SELECT COALESCE(max(id), 0) FROM {table};")
        return cur.fetchone()[0]


def watch_logs(conn, service_filter, interval):
    last_id = get_max_id(conn, "application_logs")
    print(f"[watch] watching application_logs from id > {last_id}"
          f"{f' (service={service_filter})' if service_filter else ''}. Ctrl+C to stop.\n")

    while True:
        with conn.cursor() as cur:
            if service_filter:
                cur.execute(
                    """
                    SELECT al.id, al.timestamp, s.name, al.level, al.message, al.latency_ms, al.request_id
                    FROM application_logs al JOIN services s ON s.id = al.service_id
                    WHERE al.id > %s AND s.name = %s
                    ORDER BY al.id ASC;
                    """,
                    (last_id, service_filter),
                )
            else:
                cur.execute(
                    """
                    SELECT al.id, al.timestamp, s.name, al.level, al.message, al.latency_ms, al.request_id
                    FROM application_logs al JOIN services s ON s.id = al.service_id
                    WHERE al.id > %s
                    ORDER BY al.id ASC;
                    """,
                    (last_id,),
                )
            rows = cur.fetchall()

        for row_id, ts, service, level, message, latency_ms, request_id in rows:
            color = LEVEL_COLOR.get(level, "")
            print(f"{color}[{ts}] {service:<10} {level:<5} {message}{RESET}  "
                  f"({latency_ms}ms, req={request_id})")
            last_id = row_id

        time.sleep(interval)


def watch_incidents(conn, interval):
    last_id = get_max_id(conn, "incidents")
    print(f"[watch] watching incidents from id > {last_id}. Ctrl+C to stop.\n")

    while True:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT i.id, i.started_at, s.name, i.rule, i.fingerprint, i.severity, i.title
                FROM incidents i JOIN services s ON s.id = i.service_id
                WHERE i.id > %s
                ORDER BY i.id ASC;
                """,
                (last_id,),
            )
            rows = cur.fetchall()

        for row_id, started_at, service, rule, fp, severity, title in rows:
            print(f"\033[35m[{started_at}] INCIDENT #{row_id}  {service:<10} rule={rule:<16} "
                  f"severity={severity:<8} fp={fp}\033[0m")
            print(f"  {title}")
            last_id = row_id

        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="Tail application_logs or incidents live, like tail -f for the DB.")
    parser.add_argument("--service", type=str, default=None, help="only show this service's logs")
    parser.add_argument("--interval", type=float, default=1.0, help="poll interval in seconds (default: 1)")
    parser.add_argument("--incidents", action="store_true", help="watch the incidents table instead of application_logs")
    args = parser.parse_args()

    conn = connect()
    try:
        if args.incidents:
            watch_incidents(conn, args.interval)
        else:
            watch_logs(conn, args.service, args.interval)
    except KeyboardInterrupt:
        pass
    finally:
        conn.close()
        print("\n[watch] stopped.")


if __name__ == "__main__":
    main()