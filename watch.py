"""
seed_db.py

Fills the database directly (application_logs + incidents) and tests the
similarity search. Run it from the terminal:

    python seed_db.py            # seed everything + open the new incident + search
    python seed_db.py --cleanup  # remove everything this script created

It uses a separate test service called "seedtest", so your real "payment"
data is never touched.

What it does
  1. PAST incidents (3, already solved) - every column filled:
       application_logs : their error/warn/info logs, 4-10 days ago
       incidents        : rule, fingerprint, title, description, severity, status,
                          started_at, resolved_at, created_at, root_cause, resolution,
                          resolution_confidence, evidence, error_type,
                          signature_text, log_templates, embedding
     signature_text / log_templates / embedding are produced by the SAME code the
     console uses (Drain -> signature -> embedder), from the logs inserted above.
  2. NEW incident: inserts fresh logs (healthy traffic + an error spike in the last
     few minutes), then runs the real detector (console.check_service) so the
     incident is opened the normal way: Drain -> embed -> saved in incidents.embedding.
  3. SEARCH: finds similar past incidents for the new one and prints the list you
     paste into InvestigationState.similar_incidents.

Files needed in the same folder: console.py, drain_templates.py, embedder.py, db.py
(db.py must contain get_incident_embedding / find_similar_incidents).
"""

import json
import os
import random
import re
import sys
import uuid

from loggs import (
    connect, ensure_schema, ensure_services, get_service_id,
    build_signature, check_service, fingerprint,
)
from embedder import embed_incident

SERVICE = "seedtest"
SEED_TITLE_PREFIX = "[SEED] "
PAST_RID_PREFIX = "seedp"      # request_id prefix of past-incident logs
CUR_RID_PREFIX = "seedc"       # request_id prefix of the new-incident logs
STATE_FILE = ".seed_state.json"


def rid(prefix):
    return prefix + uuid.uuid4().hex[:11]      # 16 chars, like the console's request ids


def tx():
    return "txn_" + uuid.uuid4().hex[:10]


# ---------------------------------------------------------------------------
# Past incidents (already solved)
# ---------------------------------------------------------------------------

def logs_db_pool():
    errs = (
        [("ERROR", f"Timeout connecting to payment-db after {5000 + i * 37}ms", 5000 + i * 37) for i in range(30)]
        + [("ERROR", "Connection pool exhausted: 0 of 20 connections available", 120) for _ in range(20)]
        + [("ERROR", f"Payment failed for user {8800 + i} {tx()}", 180) for i in range(15)]
    )
    warns = [("WARN", f"Slow query on payment-db took {900 + i * 80}ms", 900 + i * 80) for i in range(5)]
    return errs, warns


def logs_gateway():
    errs = (
        [("ERROR", f"Upstream card-gateway returned 502 for charge {tx()}", 3000) for _ in range(35)]
        + [("ERROR", "Retry limit reached calling card-gateway after 3 attempts", 9000) for _ in range(25)]
    )
    warns = [("WARN", f"card-gateway response slow: {2000 + i * 300}ms", 2000 + i * 300) for i in range(5)]
    return errs, warns


def logs_memory():
    errs = (
        [("ERROR", f"java.lang.OutOfMemoryError: Java heap space in payment-worker-{i % 3}", 200) for i in range(20)]
        + [("ERROR", f"Worker payment-worker-{i % 3} killed by OOM, restarting", 150) for i in range(20)]
    )
    warns = [("WARN", f"Heap usage at {85 + i * 3}% on payment-worker-{i % 3}", 100) for i in range(5)]
    return errs, warns


PAST = [
    {
        "title": "Elevated error rate in seedtest: DB pool exhausted",
        "days_ago": 10,
        "rule": "error_rate",
        "severity": "high",
        "description": "Error rate 71.4%, 68.9%, threshold 5.0% (baseline 0.0%).",
        "root_cause": "DB connection pool exhausted after a deploy increased traffic",
        "resolution": "Raised pool size from 20 to 50 and restarted the payment service",
        "logs": logs_db_pool,
    },
    {
        "title": "Elevated error rate in seedtest: card gateway outage",
        "days_ago": 7,
        "rule": "error_rate",
        "severity": "high",
        "description": "Error rate 82.0%, 79.5%, threshold 5.0% (baseline 0.0%).",
        "root_cause": "Card gateway outage on the provider side",
        "resolution": "Enabled the fallback gateway and replayed the failed charges",
        "logs": logs_gateway,
    },
    {
        "title": "Elevated error rate in seedtest: memory leak",
        "days_ago": 4,
        "rule": "error_rate",
        "severity": "high",
        "description": "Error rate 55.3%, 61.0%, threshold 5.0% (baseline 0.0%).",
        "root_cause": "Memory leak in receipt generation (unbounded cache)",
        "resolution": "Rolled back release 2.4.1 and fixed the unbounded cache",
        "logs": logs_memory,
    },
]


# ---------------------------------------------------------------------------
# Log levels: the table has a CHECK constraint on `level`, so we read which
# spellings it allows (e.g. WARN vs WARNING) instead of guessing.
# ---------------------------------------------------------------------------

LEVEL_MAP = {"INFO": "INFO", "ERROR": "ERROR", "WARN": "WARN"}


def detect_levels(conn):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conname = 'application_logs_level_check';"
        )
        row = cur.fetchone()
    if not row:
        return dict(LEVEL_MAP)                      # no constraint: keep our spellings
    allowed = {w.upper(): w for w in re.findall(r"'([A-Za-z]+)'", row[0])}
    mapping = {}
    for ours, candidates in (("INFO", ("INFO",)), ("ERROR", ("ERROR",)), ("WARN", ("WARN", "WARNING"))):
        mapping[ours] = next((allowed[c] for c in candidates if c in allowed), None)
    print(f"  allowed levels in the table: {sorted(allowed.values())}")
    print(f"  using: {mapping}")
    return mapping


def apply_levels(rows):
    """rows: tuples whose 2nd item is the level. Renames levels, drops ones the table does not allow."""
    out = []
    for r in rows:
        lvl = LEVEL_MAP.get(r[1])
        if lvl is None:
            continue
        out.append((r[0], lvl) + tuple(r[2:]))
    return out

INSERT_LOG_SQL = """
    INSERT INTO application_logs (service_id, level, message, latency_ms, request_id, timestamp)
    VALUES (%s, %s, %s, %s, %s, now() - (%s * interval '1 second'));
"""

INSERT_INCIDENT_SQL = """
    INSERT INTO incidents
        (service_id, rule, fingerprint, title, description, severity, status,
         started_at, resolved_at, created_at,
         root_cause, resolution, resolution_confidence, evidence,
         error_type, signature_text, log_templates, embedding)
    VALUES
        (%s, %s, %s, %s, %s, %s, 'resolved',
         now() - (%s * interval '1 day'),
         now() - (%s * interval '1 day') + interval '1 hour',
         now() - (%s * interval '1 day'),
         %s, %s, 'confirmed', %s,
         %s, %s, %s::jsonb, %s::vector)
    RETURNING id;
"""


def seed_past_incident(conn, service_id, p):
    title = SEED_TITLE_PREFIX + p["title"]
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM incidents WHERE title = %s;", (title,))
        row = cur.fetchone()
    if row:
        print(f"  already seeded: incident id={row[0]}  {p['title']}")
        return row[0]

    errs, warns = p["logs"]()
    days = p["days_ago"]
    base = days * 86400                      # seconds ago that "incident opened" happened

    # ---- application_logs: warns, then errors, spread over the 15 min before the incident
    log_rows = []
    for k, (level, msg, lat) in enumerate(warns):
        log_rows.append((service_id, level, msg, lat, rid(PAST_RID_PREFIX), base + 900 + 300 - k * 40))
    n = len(errs)
    for k, (level, msg, lat) in enumerate(errs):
        log_rows.append((service_id, level, msg, lat, rid(PAST_RID_PREFIX), base + int(900 * (1 - k / n))))
    for _ in range(40):                      # normal traffic around it
        log_rows.append((service_id, "INFO", "request completed", round(random.uniform(40, 90), 1),
                         rid(PAST_RID_PREFIX), base + random.randint(60, 2400)))
    log_rows = apply_levels(log_rows)
    with conn.cursor() as cur:
        cur.executemany(INSERT_LOG_SQL, log_rows)

    # ---- incidents: signature / templates / embedding built from those same logs
    sig_rows = [(m, lvl) for lvl, m, _ in warns] + [(m, lvl) for lvl, m, _ in errs]
    signature_text, templates = build_signature(SERVICE, p["rule"], sig_rows)
    _, vec = embed_incident(SERVICE, p["rule"], templates)

    top = sorted(templates, key=templates.get, reverse=True)[:3]
    evidence = "\n".join(f"- {t} (x{templates[t]})" for t in top)

    fp = fingerprint(f"elevated_error_rate:{SERVICE}")
    with conn.cursor() as cur:
        cur.execute(
            INSERT_INCIDENT_SQL,
            (service_id, p["rule"], fp, title, p["description"], p["severity"],
             days, days, days,
             p["root_cause"], p["resolution"], evidence,
             p["rule"][:100], signature_text, json.dumps(templates), vec),
        )
        new_id = cur.fetchone()[0]
    conn.commit()
    print(f"  seeded incident id={new_id}  ({len(log_rows)} logs)  {p['title']}")
    return new_id


# ---------------------------------------------------------------------------
# New incident: logs only, the detector opens it
# ---------------------------------------------------------------------------

HISTORY_ERRORS = [
    "Connection pool exhausted: 0 of 20 connections available",
    "Timeout connecting to payment-db: pool wait expired after 6120ms",
]


def insert_current_logs(conn, service_id):
    rows = []

    # healthy traffic from 5 to 25 minutes ago -> baseline error rate 0%
    for m in range(5, 26):
        for g in range(8):
            rows.append((service_id, "INFO", "request completed", round(random.uniform(40, 90), 1),
                         rid(CUR_RID_PREFIX), m * 60 + g * 3))

    # the same two error types 5 hours ago, so the "new_error_type" rule does not also fire
    for msg in HISTORY_ERRORS:
        rows.append((service_id, "ERROR", msg, 100, rid(CUR_RID_PREFIX), 5 * 3600))

    # error spike in the last ~4 minutes (different wording from past incident 1)
    for m in range(0, 4):
        for g in range(1, 7):
            sec = m * 60 + g * 8
            rows.append((service_id, "ERROR", "Connection pool exhausted: 0 of 20 connections available",
                         100, rid(CUR_RID_PREFIX), sec))
            rows.append((service_id, "ERROR",
                         f"Timeout connecting to payment-db: pool wait expired after {5000 + g * 150}ms",
                         100, rid(CUR_RID_PREFIX), sec + 2))
            rows.append((service_id, "INFO", "request completed", 60, rid(CUR_RID_PREFIX), sec + 4))

    rows = apply_levels(rows)
    with conn.cursor() as cur:
        cur.executemany(INSERT_LOG_SQL, rows)
    conn.commit()
    print(f"  inserted {len(rows)} logs for the new incident")


def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def remove_previous_current(conn):
    """Makes the script re-runnable: drops the previous 'new incident' and its logs."""
    state = load_state()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM application_logs WHERE request_id LIKE %s;", (CUR_RID_PREFIX + "%",))
        if state.get("new_incident_id"):
            cur.execute("DELETE FROM incidents WHERE id = %s;", (state["new_incident_id"],))
    conn.commit()


# ---------------------------------------------------------------------------
# Checks / cleanup
# ---------------------------------------------------------------------------

def report_null_columns(conn, table, where_sql, params):
    """Tells you which columns are still NULL in the rows this script created."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = %s AND table_schema = 'public' ORDER BY ordinal_position;",
            (table,),
        )
        cols = [r[0] for r in cur.fetchall()]
        if not cols:
            return
        parts = ", ".join(f'count(*) FILTER (WHERE "{c}" IS NULL)' for c in cols)
        cur.execute(f"SELECT count(*), {parts} FROM public.{table} WHERE {where_sql};", params)
        row = cur.fetchone()
    total, nulls = row[0], row[1:]
    empty = [c for c, n in zip(cols, nulls) if n]
    if empty:
        print(f"  {table}: still NULL in some of the {total} seeded rows -> {', '.join(empty)}")
    else:
        print(f"  {table}: all {len(cols)} columns filled in all {total} seeded rows")


def cleanup(conn):
    state = load_state()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM application_logs WHERE request_id LIKE ANY(%s);",
                    ([PAST_RID_PREFIX + "%", CUR_RID_PREFIX + "%"],))
        logs = cur.rowcount
        cur.execute("DELETE FROM incidents WHERE title LIKE %s;", (SEED_TITLE_PREFIX + "%",))
        inc = cur.rowcount
        if state.get("new_incident_id"):
            cur.execute("DELETE FROM incidents WHERE id = %s;", (state["new_incident_id"],))
            inc += cur.rowcount
    conn.commit()
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)
    print(f"deleted {logs} log rows and {inc} incident rows (service '{SERVICE}' itself is kept)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    conn = connect()
    ensure_schema(conn)
    ensure_services(conn)
    with conn.cursor() as cur:
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS evidence text;")
    conn.commit()

    if "--cleanup" in sys.argv:
        cleanup(conn)
        return

    service_id = get_service_id(conn, SERVICE)
    LEVEL_MAP.update(detect_levels(conn))

    print("\n[1/4] seeding PAST incidents (solved) + their logs")
    for p in PAST:
        seed_past_incident(conn, service_id, p)

    print("\n[2/4] inserting logs for the NEW incident")
    remove_previous_current(conn)
    insert_current_logs(conn, service_id)

    print("\n[3/4] running the detector (opens the incident the normal way)")
    check_service(conn, service_id, SERVICE, quiet_if_nothing=False)
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id FROM incidents WHERE service_id = %s AND status = 'open' AND title NOT LIKE %s "
            "ORDER BY id DESC LIMIT 1;",
            (service_id, SEED_TITLE_PREFIX + "%"),
        )
        row = cur.fetchone()
    if not row:
        print("\n  no incident was opened. Check: other old logs for 'seedtest'? "
              "Run `python seed_db.py --cleanup` and try again.")
        return
    new_id = row[0]
    save_state({"new_incident_id": new_id})
    print(f"\n  new incident id = {new_id}")

    print("\n[4/4] searching similar past incidents")
    try:
        from db import get_incident_embedding, find_similar_incidents, SIMILAR_MIN_SIMILARITY
    except ImportError as e:
        print(f"  cannot import from db.py ({e}). Add get_incident_embedding / "
              f"find_similar_incidents / SIMILAR_MIN_SIMILARITY to db.py first.")
        return

    embedding, service_name = get_incident_embedding(new_id)
    if embedding is None:
        print("  the new incident has no embedding saved (see the embedding error printed above)")
        return

    raw = find_similar_incidents(embedding, service_name, exclude_incident_id=new_id,
                                 limit=5, min_similarity=0.0)
    print("\n  raw scores (no threshold):")
    for r in raw:
        print(f"    id={r['incident_id']:<4} similarity={r['similarity']:<5}  {r['root_cause']}")

    kept = find_similar_incidents(embedding, service_name, exclude_incident_id=new_id,
                                  min_similarity=SIMILAR_MIN_SIMILARITY)
    print(f"\n  after threshold {SIMILAR_MIN_SIMILARITY}: {len(kept)} match(es)")
    print("\n  paste this into InvestigationState.similar_incidents "
          f"(use incident_id={new_id}, service_name='{SERVICE}'):")
    print(json.dumps(kept, indent=2, default=str))

    print("\n  column check:")
    report_null_columns(conn, "incidents", "title LIKE %s", (SEED_TITLE_PREFIX + "%",))
    report_null_columns(conn, "application_logs", "request_id LIKE ANY(%s)",
                        ([PAST_RID_PREFIX + "%", CUR_RID_PREFIX + "%"],))
    conn.close()


if __name__ == "__main__":
    main()