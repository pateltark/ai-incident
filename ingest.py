"""
ingest.py  -  app.log  ->  UI  ->  ClickHouse  ->  incident detection

One background thread, started by api.py. For every new batch of lines in app.log:

    1. parse each line and publish it to an in-memory buffer  (the UI reads this: instant)
    2. save the batch to ClickHouse                           (history + evidence for the agent)
    3. for every ERROR line, open an incident if needed       (same rules as watch.py's tailer)

Because this thread does all three steps, do NOT also run connector_layer.py or
watch.py's tailer at the same time (you would insert every log twice).
"""
import os
import re
import threading
import time
from collections import deque

import psycopg2

from connector_layer import LOCAL_LOG_FILE, parse_log_line, save_logs, tail_local_logs
from db import LOG_PATTERN_RULES
from main import handle_incident_opened
from watch import (ERROR_LEVELS, connect, ensure_schema, ensure_services, fingerprint,
                   get_service_id, register_on_incident_opened, try_open_incident)

INGEST_POLL = float(os.getenv("INGEST_POLL", "1"))     # seconds between file checks
BUFFER_SIZE = 2000

LIVE = deque(maxlen=BUFFER_SIZE)        # lines the UI can read
_lock = threading.Lock()
_seq = time.time_ns() // 1000           # grows forever, even across API restarts
_stop = threading.Event()
_started = False

STATUS = {"running": False, "file": LOCAL_LOG_FILE, "lines_seen": 0,
          "last_line_at": None, "last_error": None}


# --------------------------------------------------------------------------
# live buffer (read by GET /api/live)
# --------------------------------------------------------------------------

def _publish(entries):
    global _seq
    with _lock:
        for e in entries:
            _seq += 1
            e["seq"] = _seq
            LIVE.append(e)


def get_live(after=None, service=None, level=None, limit=200):
    with _lock:
        items = list(LIVE)
    if service:
        items = [e for e in items if e["service"] == service]
    if level:
        items = [e for e in items if e["level"].upper() == level.upper()]
    if after is not None:
        items = [e for e in items if e["seq"] > after][:limit]
    else:
        items = items[-limit:]
    return {"logs": items, "cursor": items[-1]["seq"] if items else after}


# --------------------------------------------------------------------------
# pipeline
# --------------------------------------------------------------------------

_conn = None


def _pg():
    global _conn
    if _conn is None or _conn.closed:
        _conn = connect()
        # Autocommit: a normal connection keeps a transaction open after every SELECT.
        # That makes now() return an old time (wrong started_at) and blocks table locks.
        _conn.autocommit = True
    return _conn


def _detect(entry):
    """Same logic as the live tailer in watch.py: one incident per ERROR line (deduped)."""
    if entry["level"] not in ERROR_LEVELS:
        return
    conn = _pg()
    service, msg = entry["service"], entry["message"]
    rule = "new_error_type"
    for name, cfg in LOG_PATTERN_RULES.items():
        if re.search(cfg["regex"], msg, re.IGNORECASE):
            rule = name
            break
    try:
        try_open_incident(
            conn, get_service_id(conn, service), service, rule, fingerprint(msg),
            f"{rule.replace('_', ' ').capitalize()} in {service}", f'"{msg}"',
        )
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        globals()["_conn"] = None
        raise
    except Exception:
        conn.rollback()
        raise


def _parse(lines):
    entries = []
    for message, ts in lines:
        level, service, clean, latency, _req = parse_log_line(message)
        entries.append({"ts": ts.isoformat(), "service": service, "level": level,
                        "message": clean, "latency_ms": latency})
    return entries


def _run():
    if not os.path.exists(LOCAL_LOG_FILE):
        open(LOCAL_LOG_FILE, "a").close()

    pending = deque()       # batches already shown in the UI but not yet saved/detected
    STATUS["running"] = True
    print(f"[ingest] tailing '{LOCAL_LOG_FILE}' (UI -> ClickHouse -> incidents)")

    with open(LOCAL_LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        last_size = f.tell()

        while not _stop.is_set():
            try:
                size = os.path.getsize(LOCAL_LOG_FILE)
                if size < last_size:            # file was cleared: read the new content from the top
                    f.seek(0)
                last_size = size

                lines = tail_local_logs(f)
                if lines:
                    entries = _parse(lines)
                    _publish(entries)                                   # 1. UI
                    pending.append((lines, entries))
                    STATUS["lines_seen"] += len(lines)
                    STATUS["last_line_at"] = entries[-1]["ts"]

                while pending:                                          # 2. DB, then 3. incidents
                    batch_lines, batch_entries = pending[0]
                    save_logs(batch_lines)
                    pending.popleft()
                    for e in batch_entries:
                        try:
                            _detect(e)
                        except Exception as err:
                            print(f"[ingest] detection failed: {err}")
                            STATUS["last_error"] = f"detection: {err}"
                STATUS["last_error"] = None if not pending else STATUS["last_error"]
            except Exception as err:            # ClickHouse down etc.: keep batches, retry next tick
                STATUS["last_error"] = str(err)
                print(f"[ingest] error (will retry): {err}")
            time.sleep(INGEST_POLL)

    STATUS["running"] = False


def start_ingest():
    global _started
    if _started:
        return
    _started = True
    conn = connect()
    ensure_schema(conn)
    ensure_services(conn)
    conn.close()
    register_on_incident_opened(handle_incident_opened)   # agent runs when an incident opens
    threading.Thread(target=_run, daemon=True, name="ingest").start()