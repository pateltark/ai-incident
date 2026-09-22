"""
ingestor.py

Tails the CloudWatch-style app log files written by log_generator.py
(logs/cloudwatch/<service>-<date>.log) and loads each line into the
`application_logs` table in Postgres, as structured rows.

This is the middle stage of the pipeline we talked through:

    raw log lines  ->  ingestor (this file)  ->  application_logs table
    (JSON on disk)      parses + inserts          (indexed, queryable)

The detector (built next) only ever queries `application_logs` - it never
reads log files directly. That's the whole point of this stage: turn
"tail a growing text file" into "run a fast SQL aggregate query."

Design notes
------------
- Only the CloudWatch app logs are ingested here, not the raw Postgres
  log file. Every DB-caused failure already surfaces as a matching
  "database error: ..." ERROR line in the app log (see log_generator.py's
  emit_request), so ingesting the Postgres log too would double-count
  errors in the detector's error-rate rule. The raw Postgres log stays on
  disk as-is, for the Analyst agent to inspect directly in V2/V3 when it
  needs root-cause evidence (e.g. "was there a deadlock around this time?").

- Tailing is done with a byte-offset checkpoint per file, persisted to
  logs/.ingestor_state.json. This is the same idea Filebeat/Fluentd use
  (a "registry" of what's already been read) so that stopping and
  restarting the ingestor never re-inserts old rows or loses new ones.

- Only complete lines (ending in \n) are ever parsed. If the ingestor
  catches the generator mid-write on the last line, that partial line is
  left for the next poll instead of being parsed as broken JSON.

- Malformed lines are skipped and counted, not fatal - a real log stream
  occasionally has a truncated or corrupted line, and a parser that
  crashes the whole pipeline on one bad line is a real production bug.

- service_id is resolved by name (from the `services` table) and cached
  in memory. A service name seen in the logs but missing from `services`
  is inserted automatically (ON CONFLICT DO NOTHING), so ingestion never
  blocks on manual setup.

Usage:
    python ingestor.py
    python ingestor.py --logs logs/cloudwatch --poll-interval 2

Requires a .env with your Postgres connection info (see load_db_config).
Stop with Ctrl+C.
"""

import argparse
import glob
import json
import os
import time

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

STATE_FILE_NAME = ".ingestor_state.json"


# ---------------------------------------------------------------------------
# DB connection
# ---------------------------------------------------------------------------

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


def connect(config):
    if config.get("dsn"):
        return psycopg2.connect(config["dsn"])
    return psycopg2.connect(
        host=config["host"], port=config["port"], dbname=config["dbname"],
        user=config["user"], password=config["password"],
    )


# ---------------------------------------------------------------------------
# Service id cache - resolves service name -> id, inserting if new
# ---------------------------------------------------------------------------

class ServiceCache:
    def __init__(self, conn):
        self.conn = conn
        self._cache = {}
        self._load_all()

    def _load_all(self):
        with self.conn.cursor() as cur:
            cur.execute("SELECT id, name FROM services;")
            for sid, name in cur.fetchall():
                self._cache[name] = sid

    def get_id(self, service_name):
        if service_name in self._cache:
            return self._cache[service_name]
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO services (name, environment)
                VALUES (%s, %s)
                ON CONFLICT (name) DO NOTHING;
                """,
                (service_name, "production"),
            )
            cur.execute("SELECT id FROM services WHERE name = %s;", (service_name,))
            row = cur.fetchone()
        self.conn.commit()
        self._cache[service_name] = row[0]
        return row[0]


# ---------------------------------------------------------------------------
# File tailing with a persisted byte-offset checkpoint
# ---------------------------------------------------------------------------

class StateStore:
    def __init__(self, path):
        self.path = path
        self.offsets = {}
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                try:
                    self.offsets = json.load(f)
                except json.JSONDecodeError:
                    self.offsets = {}

    def get(self, filepath):
        return self.offsets.get(filepath, 0)

    def set(self, filepath, offset):
        self.offsets[filepath] = offset

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.offsets, f)
        os.replace(tmp, self.path)


def read_new_lines(filepath, offset):
    """Read only complete (newline-terminated) lines written since `offset`.
    Returns (lines, new_offset). A trailing partial line is left unread."""
    with open(filepath, "rb") as f:
        f.seek(offset)
        data = f.read()

    if not data:
        return [], offset

    last_nl = data.rfind(b"\n")
    if last_nl == -1:
        return [], offset  # no complete line yet - wait for more data

    complete = data[: last_nl + 1]
    new_offset = offset + len(complete)
    lines = [ln.decode("utf-8", errors="replace") for ln in complete.split(b"\n") if ln]
    return lines, new_offset


# ---------------------------------------------------------------------------
# Parsing a CloudWatch-style JSON app log line into a row
# ---------------------------------------------------------------------------

def parse_app_log_line(line):
    """Returns a dict of row fields, or None if the line is malformed."""
    try:
        obj = json.loads(line)
        return {
            "service": obj["service"],
            "level": obj["level"],
            "message": obj["message"],
            "latency_ms": obj.get("latency_ms"),
            "request_id": obj.get("request_id"),
            "timestamp": obj["timestamp"],  # ISO 8601, Postgres parses this directly
        }
    except (json.JSONDecodeError, KeyError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Insert
# ---------------------------------------------------------------------------

INSERT_SQL = """
    INSERT INTO application_logs (service_id, level, message, latency_ms, request_id, timestamp)
    VALUES %s;
"""


def insert_rows(conn, service_cache, rows):
    if not rows:
        return 0
    values = []
    skipped = 0
    for row in rows:
        parsed = parse_app_log_line(row)
        if parsed is None:
            skipped += 1
            continue
        service_id = service_cache.get_id(parsed["service"])
        values.append((
            service_id, parsed["level"], parsed["message"],
            parsed["latency_ms"], parsed["request_id"], parsed["timestamp"],
        ))

    if values:
        with conn.cursor() as cur:
            psycopg2.extras.execute_values(cur, INSERT_SQL, values)
        conn.commit()

    if skipped:
        print(f"[ingestor] skipped {skipped} malformed line(s)")
    return len(values)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run(logs_dir, poll_interval):
    config = load_db_config()
    conn = connect(config)
    service_cache = ServiceCache(conn)
    state = StateStore(os.path.join(os.path.dirname(logs_dir.rstrip("/")) or ".", STATE_FILE_NAME))

    print(f"[ingestor] watching {logs_dir}/*.log, polling every {poll_interval}s. Ctrl+C to stop.")
    total_inserted = 0

    try:
        while True:
            files = sorted(glob.glob(os.path.join(logs_dir, "*.log")))
            for filepath in files:
                abs_path = os.path.abspath(filepath)
                offset = state.get(abs_path)
                lines, new_offset = read_new_lines(filepath, offset)
                if lines:
                    inserted = insert_rows(conn, service_cache, lines)
                    total_inserted += inserted
                    state.set(abs_path, new_offset)
                    print(f"[ingestor] {os.path.basename(filepath)}: +{inserted} rows "
                          f"(total {total_inserted})")
            state.save()
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        pass
    finally:
        state.save()
        conn.close()
        print("\n[ingestor] stopped.")


def main():
    parser = argparse.ArgumentParser(description="Tail CloudWatch-style app logs into application_logs.")
    parser.add_argument("--logs", type=str, default="logs/cloudwatch",
                         help="directory of app log files to tail (default: logs/cloudwatch)")
    parser.add_argument("--poll-interval", type=float, default=2.0,
                         help="seconds between polls (default: 2)")
    args = parser.parse_args()
    run(args.logs, args.poll_interval)


if __name__ == "__main__":
    main()