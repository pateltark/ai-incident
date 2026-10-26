"""
loggs.py

Refactored to separate and highlight the Continuous Detector Engine.
It continuously monitors `application_logs` for all registered services,
applies the detection rules (error_rate, new_error_type, latency_spike),
and automatically creates enriched incidents with signature texts,
Drain3 log templates, and vector embeddings.
"""

import datetime
import hashlib
import json
import os
import re
import statistics
import sys
import uuid
from collections import Counter
import threading
import time
import psycopg2
from dotenv import load_dotenv

from drain_templates import cluster_logs, show_clusters
from embedder import embed_incident
from main import handle_incident_opened

# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------

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
    normalized = normalize(message)
    digest = hashlib.sha1(normalized.encode("utf-8")).hexdigest()
    return digest[:length]


# ---------------------------------------------------------------------------
# Signature Text & Embedding Setup
# ---------------------------------------------------------------------------

SIGNATURE_WINDOW_MINUTES = 2
SIGNATURE_TOP_TEMPLATES = 5
SIGNATURE_STORE_TEMPLATES = 50
SIGNATURE_MAX_LOGS = 5000
FIRST_ERROR_MAX_CHARS = 200

_SIG_TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)
_SIG_UUID_RE = re.compile(
    r"(?<![0-9A-Za-z])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9A-Za-z])",
    re.IGNORECASE,
)
_SIG_IP_RE = re.compile(r"(?<![0-9A-Za-z])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Za-z])")
_SIG_HEX_RE = re.compile(
    r"(?<![0-9A-Za-z])(?=[0-9a-f]*\d)(?=[0-9a-f]*[a-f])[0-9a-f]{8,}(?![0-9A-Za-z])",
    re.IGNORECASE,
)
_SIG_NUM_RE = re.compile(r"(?<![A-Za-z])\d+(?:\.\d+)?")


def mask_log(message: str) -> str:
    text = message.strip()
    text = _SIG_TS_RE.sub("<TS>", text)
    text = _SIG_UUID_RE.sub("<ID>", text)
    text = _SIG_IP_RE.sub("<IP>", text)
    text = _SIG_HEX_RE.sub("<ID>", text)
    text = _SIG_NUM_RE.sub("<NUM>", text)
    text = _WS_RE.sub(" ", text)
    return text


def build_signature(service_name, error_type, rows, top_n=SIGNATURE_TOP_TEMPLATES):
    if not rows:
        text = (
            f"service: {service_name}\n"
            f"error_type: {error_type}\n"
            f"top_log_templates:\n"
            f"  (no logs found in the last {SIGNATURE_WINDOW_MINUTES} minutes)\n"
            f"first_error: (none)"
        )
        return text, {}

    templates = cluster_logs(service_name, [msg for msg, _ in rows])
    top = templates.most_common(top_n)

    first_raw = next((msg for msg, level in rows if level == "ERROR"), rows[0][0]).strip()
    if len(first_raw) > FIRST_ERROR_MAX_CHARS:
        first_raw = first_raw[:FIRST_ERROR_MAX_CHARS] + "..."

    lines = [f"service: {service_name}", f"error_type: {error_type}", "top_log_templates:"]
    for template, count in top:
        lines.append(f"  - {template} (x{count})")
    lines.append(f"first_error: {first_raw}")

    return "\n".join(lines), dict(templates.most_common(SIGNATURE_STORE_TEMPLATES))


def fetch_signature_logs(conn, service_id, window_minutes=SIGNATURE_WINDOW_MINUTES):
    sql = """
        SELECT message, level FROM application_logs
        WHERE service_id = %s
          AND timestamp >= now() - (%s * interval '1 minute')
          AND level IN ('ERROR', 'WARN')
        ORDER BY timestamp
        LIMIT %s;
    """
    with conn.cursor() as cur:
        cur.execute(sql, (service_id, window_minutes, SIGNATURE_MAX_LOGS))
        rows = cur.fetchall()
    if rows:
        return rows

    sql_all = """
        SELECT message, level FROM application_logs
        WHERE service_id = %s
          AND timestamp >= now() - (%s * interval '1 minute')
        ORDER BY timestamp
        LIMIT %s;
    """
    with conn.cursor() as cur:
        cur.execute(sql_all, (service_id, window_minutes, SIGNATURE_MAX_LOGS))
        return cur.fetchall()


SAVE_SIGNATURE_SQL = """
    UPDATE incidents
    SET signature_text = %s,
        log_templates = %s::jsonb,
        error_type = %s
    WHERE id = %s;
"""


def save_embedding(conn, incident_id, service_name, rule, templates):
    text, vec_literal = embed_incident(service_name, rule, templates)
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE incidents SET embedding = %s::vector WHERE id = %s;",
            (vec_literal, incident_id),
        )
    conn.commit()
    return text


def store_signature(conn, incident_id, service_id, service_name, rule):
    rows = fetch_signature_logs(conn, service_id)
    signature_text, templates = build_signature(service_name, rule, rows)
    with conn.cursor() as cur:
        cur.execute(
            SAVE_SIGNATURE_SQL,
            (signature_text, json.dumps(templates), rule[:100], incident_id),
        )
    conn.commit()

    try:
        embedded_text = save_embedding(conn, incident_id, service_name, rule, templates)
        print("      embedding saved. text that was embedded:")
        for emb_line in embedded_text.splitlines():
            print(f"        {emb_line}")
    except Exception as e:
        conn.rollback()
        print(f"  (could not save embedding for incident {incident_id}: {e})")

    return signature_text


# ---------------------------------------------------------------------------
# Detection Thresholds
# ---------------------------------------------------------------------------

ERROR_RATE_FLOOR = 0.05
ERROR_RATE_BASELINE_MULT = 3.0
ERROR_RATE_MIN_BUCKET_COUNT = 5
ERROR_RATE_CONSEC_MINUTES = 2

NEW_ERROR_TYPE_MIN_COUNT = 5
NEW_ERROR_TYPE_RECENT_MINUTES = 2
NEW_ERROR_TYPE_HISTORY_HOURS = 24

LATENCY_SPIKE_MULT = 2.0
LATENCY_SPIKE_CONSEC_MINUTES = 3

SEVERITY_BY_RULE = {"error_rate": "high", "new_error_type": "medium", "latency_spike": "medium"}
RESOLVE_COOLDOWN_MINUTES = 10


# ---------------------------------------------------------------------------
# DB Config & Core Utilities
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


def connect():
    cfg = load_db_config()
    if cfg.get("dsn"):
        conn = psycopg2.connect(cfg["dsn"])
    else:
        conn = psycopg2.connect(
            host=cfg["host"], port=cfg["port"], dbname=cfg["dbname"],
            user=cfg["user"], password=cfg["password"],
        )
    return conn


KNOWN_SERVICES = ["checkout", "payment", "auth", "inventory"]


def ensure_schema(conn):
    with conn.cursor() as cur:
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS signature_text text;")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS log_templates jsonb;")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS error_type varchar(100);")
        cur.execute("UPDATE incidents SET error_type = rule WHERE error_type IS NULL AND rule IS NOT NULL;")
    conn.commit()


def ensure_services(conn):
    with conn.cursor() as cur:
        for name in KNOWN_SERVICES:
            cur.execute(
                "INSERT INTO services (name, environment) VALUES (%s, %s) ON CONFLICT (name) DO NOTHING;",
                (name, "production"),
            )
    conn.commit()


def get_service_id(conn, name):
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM services WHERE name = %s;", (name,))
        row = cur.fetchone()
        if row:
            return row[0]
        cur.execute(
            "INSERT INTO services (name, environment) VALUES (%s, %s) ON CONFLICT (name) DO NOTHING;",
            (name, "production"),
        )
        conn.commit()
        cur.execute("SELECT id FROM services WHERE name = %s;", (name,))
        return cur.fetchone()[0]


DEFAULT_LATENCY = {"INFO": 60.0, "WARN": 90.0, "ERROR": 150.0}


def write_log(conn, service_name, level, message, latency_ms=None, request_id=None):
    service_id = get_service_id(conn, service_name)
    if latency_ms is None:
        latency_ms = DEFAULT_LATENCY.get(level.upper(), 80.0)
    if request_id is None:
        request_id = uuid.uuid4().hex[:16]
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO application_logs (service_id, level, message, latency_ms, request_id, timestamp)
            VALUES (%s, %s, %s, %s, %s, now());
            """,
            (service_id, level.upper(), message, latency_ms, request_id),
        )
    conn.commit()
    return service_id


# ---------------------------------------------------------------------------
# Rule Evaluators
# ---------------------------------------------------------------------------

def evaluate_error_rate(buckets):
    usable = [b for b in buckets if b[1] >= ERROR_RATE_MIN_BUCKET_COUNT]
    if len(usable) < ERROR_RATE_CONSEC_MINUTES:
        return False, None
    recent = usable[-ERROR_RATE_CONSEC_MINUTES:]
    baseline_pool = usable[:-ERROR_RATE_CONSEC_MINUTES]
    baseline_rates = [ec / tc for _, tc, ec in baseline_pool] if baseline_pool else []
    baseline_median = statistics.median(baseline_rates) if baseline_rates else 0.0
    threshold = max(ERROR_RATE_FLOOR, ERROR_RATE_BASELINE_MULT * baseline_median)
    recent_rates = [ec / tc for _, tc, ec in recent]
    fired = all(r > threshold for r in recent_rates)
    if not fired:
        return False, None
    return True, {"threshold": threshold, "baseline_median": baseline_median, "recent_rates": recent_rates}


def evaluate_new_error_type(history_fingerprints, recent_rows):
    counts = Counter(fp for fp, _ in recent_rows)
    sample_message = {}
    for fp, msg in recent_rows:
        sample_message.setdefault(fp, msg)
    fired = []
    for fp, count in counts.items():
        if fp in history_fingerprints or count < NEW_ERROR_TYPE_MIN_COUNT:
            continue
        fired.append({"fingerprint": fp, "count": count, "message": sample_message[fp]})
    return fired


def evaluate_latency_spike(buckets):
    usable = [b for b in buckets if b[1] is not None]
    if len(usable) < LATENCY_SPIKE_CONSEC_MINUTES:
        return False, None
    recent = usable[-LATENCY_SPIKE_CONSEC_MINUTES:]
    baseline_pool = usable[:-LATENCY_SPIKE_CONSEC_MINUTES]
    if not baseline_pool:
        return False, None
    baseline_median = statistics.median(p95 for _, p95 in baseline_pool)
    if baseline_median <= 0:
        return False, None
    threshold = LATENCY_SPIKE_MULT * baseline_median
    recent_p95s = [p95 for _, p95 in recent]
    fired = all(p95 > threshold for p95 in recent_p95s)
    if not fired:
        return False, None
    return True, {"threshold": threshold, "baseline_median": baseline_median, "recent_p95s": recent_p95s}


def fetch_error_rate_buckets(conn, service_id):
    sql = """
        SELECT date_trunc('minute', timestamp) AS bucket,
               count(*) AS total,
               count(*) FILTER (WHERE level = 'ERROR') AS errors
        FROM application_logs
        WHERE service_id = %s AND timestamp >= now() - interval '32 minutes'
          AND timestamp < date_trunc('minute', now()) + interval '1 minute'
        GROUP BY bucket ORDER BY bucket;
    """
    with conn.cursor() as cur:
        cur.execute(sql, (service_id,))
        return cur.fetchall()


def fetch_latency_buckets(conn, service_id):
    sql = """
        SELECT date_trunc('minute', timestamp) AS bucket,
               percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95
        FROM application_logs
        WHERE service_id = %s AND timestamp >= now() - interval '33 minutes'
          AND timestamp < date_trunc('minute', now()) + interval '1 minute'
          AND latency_ms IS NOT NULL
        GROUP BY bucket ORDER BY bucket;
    """
    with conn.cursor() as cur:
        cur.execute(sql, (service_id,))
        return cur.fetchall()


def fetch_error_messages(conn, service_id):
    sql = """
        SELECT message, timestamp >= now() - (%s * interval '1 minute') AS is_recent
        FROM application_logs
        WHERE service_id = %s AND level = 'ERROR'
          AND timestamp >= now() - (%s * interval '1 hour');
    """
    with conn.cursor() as cur:
        cur.execute(sql, (NEW_ERROR_TYPE_RECENT_MINUTES, service_id, NEW_ERROR_TYPE_HISTORY_HOURS))
        rows = cur.fetchall()
    history_fps, recent_rows = set(), []
    for message, is_recent in rows:
        fp = fingerprint(message)
        if is_recent:
            recent_rows.append((fp, message))
        else:
            history_fps.add(fp)
    return history_fps, recent_rows


OPEN_INCIDENT_SQL = """
    INSERT INTO incidents (service_id, rule, fingerprint, title, description, severity, status, started_at)
    VALUES (%s, %s, %s, %s, %s, %s, 'open', now())
    ON CONFLICT (service_id, fingerprint) WHERE status = 'open' DO NOTHING
    RETURNING id;
"""

INCIDENT_OPENED_CALLBACKS = []


def register_on_incident_opened(callback):
    INCIDENT_OPENED_CALLBACKS.append(callback)


def try_open_incident(conn, service_id, service_name, rule, fp, title, description):
    severity = SEVERITY_BY_RULE.get(rule, "medium")
    with conn.cursor() as cur:
        cur.execute(OPEN_INCIDENT_SQL, (service_id, rule, fp, title, description, severity))
        row = cur.fetchone()
    conn.commit()

    if row is None:
        print(f"  (already open: an incident for {service_name}/{fp} exists - no duplicate)")
        return None

    incident_id = row[0]
    print(f"  >>> INCIDENT OPENED  id={incident_id}  rule={rule}  severity={severity}  fingerprint={fp}")
    print(f"      {description}")

    signature_text = None
    try:
        signature_text = store_signature(conn, incident_id, service_id, service_name, rule)
        print("      signature saved:")
        for sig_line in signature_text.splitlines():
            print(f"        {sig_line}")
    except Exception as e:
        conn.rollback()
        print(f"  (could not build signature for incident {incident_id}: {e})")

    alert_payload = {
        "incident_id": incident_id,
        "service_name": service_name,
        "rule": rule,
        "fingerprint": fp,
        "title": title,
        "description": description,
        "severity": severity,
        "signature_text": signature_text,
    }

    for callback in INCIDENT_OPENED_CALLBACKS:
        try:
            callback(alert_payload)
        except Exception as e:
            print(f"Error triggering callback for incident {incident_id}: {e}")

    return incident_id


# ---------------------------------------------------------------------------
# SEPARATED DETECTOR ENGINE: Continuous Application Logs Watcher
# ---------------------------------------------------------------------------

def check_service(conn, service_id, service_name, quiet_if_nothing=True):
    """Evaluates application_logs for a specific service against detection rules."""
    fired_any = False

    buckets = fetch_error_rate_buckets(conn, service_id)
    fired, detail = evaluate_error_rate(buckets)
    if fired:
        fired_any = True
        rates_str = ", ".join(f"{r:.1%}" for r in detail["recent_rates"])
        try_open_incident(
            conn, service_id, service_name, "error_rate",
            fingerprint(f"elevated_error_rate:{service_name}"),
            f"Elevated error rate in {service_name}",
            f"Error rate {rates_str}, threshold {detail['threshold']:.1%} "
            f"(baseline {detail['baseline_median']:.1%}).",
        )

    history_fps, recent_rows = fetch_error_messages(conn, service_id)
    for hit in evaluate_new_error_type(history_fps, recent_rows):
        fired_any = True
        try_open_incident(
            conn, service_id, service_name, "new_error_type", hit["fingerprint"],
            f"New error type in {service_name}",
            f'"{hit["message"]}" occurred {hit["count"]} times in the last '
            f"{NEW_ERROR_TYPE_RECENT_MINUTES} minutes, not seen in the prior {NEW_ERROR_TYPE_HISTORY_HOURS}h.",
        )

    buckets = fetch_latency_buckets(conn, service_id)
    fired, detail = evaluate_latency_spike(buckets)
    if fired:
        fired_any = True
        p95_str = ", ".join(f"{p:.0f}ms" for p in detail["recent_p95s"])
        try_open_incident(
            conn, service_id, service_name, "latency_spike",
            fingerprint(f"latency_spike:{service_name}"),
            f"Latency spike in {service_name}",
            f"p95 {p95_str}, more than {LATENCY_SPIKE_MULT}x baseline ({detail['baseline_median']:.0f}ms).",
        )

    if not fired_any and not quiet_if_nothing:
        print(f"  (no rule fired for {service_name})")
    return fired_any


def evaluate_all_services(conn):
    """Evaluates application_logs across all registered services once."""
    with conn.cursor() as cur:
        cur.execute("SELECT id, name FROM services;")
        services = cur.fetchall()
    any_fired = False
    for service_id, service_name in services:
        if check_service(conn, service_id, service_name, quiet_if_nothing=True):
            any_fired = True
    return any_fired


def monitor_application_logs(interval_seconds=30):
    """
    Isolated Continuous Engine Function:
    Continuously monitors the application_logs table across all services.
    If conditions warrant raising an incident, it opens the incident row,
    populates all metadata columns (signature, log_templates, embedding), and
    fires callbacks.
    """
    conn = connect()
    while True:
        try:
            evaluate_all_services(conn)
        except Exception as e:
            conn.rollback()
            print(f"[Log Monitor] Error during detection pass: {e}")
        time.sleep(interval_seconds)


def start_log_monitoring(interval_seconds=30):
    """Spawns the log monitor in a dedicated daemon thread."""
    thread = threading.Thread(
        target=monitor_application_logs, args=(interval_seconds,), daemon=True
    )
    thread.start()
    return thread


# ---------------------------------------------------------------------------
# Resolving / closing
# ---------------------------------------------------------------------------

CLOSE_INCIDENT_SQL = """
    UPDATE incidents
    SET status = 'resolved',
        resolved_at = now(),
        root_cause = %s,
        resolution = %s,
        resolution_confidence = %s
    WHERE id = %s AND status = 'open'
    RETURNING id, title;
"""


def close_incident(conn, incident_id, root_cause, resolution=None, confidence="confirmed"):
    with conn.cursor() as cur:
        cur.execute(CLOSE_INCIDENT_SQL, (root_cause, resolution, confidence, incident_id))
        result = cur.fetchone()
    conn.commit()
    if result is None:
        print(f"  incident {incident_id} isn't open (already resolved, or doesn't exist)")
        return False
    print(f"  >>> INCIDENT RESOLVED  id={result[0]}  \"{result[1]}\"")
    print("      root cause and resolution saved")
    return True


def fetch_open_incidents(conn):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, service_id, rule, fingerprint, started_at
            FROM incidents WHERE status = 'open' ORDER BY started_at;
        """)
        return cur.fetchall()


def is_condition_quiet(conn, service_id, rule, fp, cooldown_minutes):
    if rule == "error_rate":
        buckets = fetch_error_rate_buckets(conn, service_id)
        recent = [b for b in buckets if b[0] >= datetime.datetime.now(datetime.timezone.utc)
                  - datetime.timedelta(minutes=cooldown_minutes)]
        if not recent:
            return False
        rates = [ec / tc for _, tc, ec in recent if tc > 0]
        return bool(rates) and all(r < ERROR_RATE_FLOOR for r in rates)

    if rule == "new_error_type":
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT message FROM application_logs
                WHERE service_id = %s AND level = 'ERROR'
                  AND timestamp >= now() - (%s * interval '1 minute');
                """,
                (service_id, cooldown_minutes),
            )
            recent_messages = [r[0] for r in cur.fetchall()]
        return fp not in {fingerprint(m) for m in recent_messages}

    if rule == "latency_spike":
        buckets = fetch_latency_buckets(conn, service_id)
        recent = [b for b in buckets if b[0] >= datetime.datetime.now(datetime.timezone.utc)
                  - datetime.timedelta(minutes=cooldown_minutes)]
        if not recent:
            return False
        baseline_pool = buckets[:-len(recent)] if len(buckets) > len(recent) else []
        if not baseline_pool:
            return False
        baseline_median = statistics.median(p95 for _, p95 in baseline_pool if p95 is not None)
        if baseline_median <= 0:
            return False
        return all(p95 is not None and p95 < LATENCY_SPIKE_MULT * baseline_median for _, p95 in recent)

    return False


def autoclose(conn, cooldown_minutes=RESOLVE_COOLDOWN_MINUTES):
    open_incidents = fetch_open_incidents(conn)
    if not open_incidents:
        print("  (no open incidents)")
        return
    closed_any = False
    for incident_id, service_id, rule, fp, started_at in open_incidents:
        quiet = is_condition_quiet(conn, service_id, rule, fp, cooldown_minutes)
        if not quiet:
            print(f"  incident {incident_id} ({rule}): still active, leaving open")
            continue
        with conn.cursor() as cur:
            cur.execute("SELECT root_cause, resolution FROM incidents WHERE id = %s;", (incident_id,))
            existing_root_cause, existing_resolution = cur.fetchone()
        root_cause = existing_root_cause or "(auto-closed: condition cleared, no investigation recorded)"
        resolution = existing_resolution or "(condition stopped firing before a fix was recorded)"
        confidence = "unknown" if not existing_root_cause else "inferred"
        if close_incident(conn, incident_id, root_cause, resolution, confidence):
            closed_any = True
    if not closed_any:
        print("  nothing closed this pass")


# ---------------------------------------------------------------------------
# Interactive Console
# ---------------------------------------------------------------------------

HELP = """
Commands:
  error <service> <message...>        write one ERROR log, then check that service
  warn  <service> <message...>        write one WARN log, then check that service
  info  <service> <message...>        write one INFO log, then check that service
  burst <n> <service> <message...>    write N ERROR logs (same message) rapid-fire, then check
  latency <service> <ms>              write one INFO log with a custom latency_ms, then check
  check [service]                     manually run detection (all services, or just one)
  incidents                           list all incidents
  signature <id>                      show saved signature text + template counts of an incident
  templates <service>                 show Drain templates learned for a service
  resolve <id>                        manually close an incident
  autoclose [minutes]                 check open incidents and close quiet ones
  logs <service> [n]                  show last n logs for a service
  services                            list known services
  fp <message...>                     show fingerprint normalization/hash
  mask <message...>                   show old regex masking
  help                                show this again
  quit / exit                         stop
"""


def cmd_incidents(conn):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT i.id, s.name, i.rule, i.fingerprint, i.status, i.severity, i.started_at
            FROM incidents i JOIN services s ON s.id = i.service_id
            ORDER BY i.started_at DESC;
        """)
        rows = cur.fetchall()
    if not rows:
        print("  (no incidents yet)")
        return
    print(f"  {'id':<4} {'service':<10} {'rule':<16} {'fingerprint':<14} {'status':<10} {'severity':<8} started_at")
    for r in rows:
        print(f"  {r[0]:<4} {r[1]:<10} {r[2] or '-':<16} {r[3] or '-':<14} {r[4]:<10} {r[5]:<8} {r[6]}")


def cmd_signature(conn, incident_id):
    with conn.cursor() as cur:
        cur.execute("SELECT signature_text, log_templates FROM incidents WHERE id = %s;", (incident_id,))
        row = cur.fetchone()
    if row is None:
        print(f"  no incident with id {incident_id}")
        return
    signature_text, log_templates = row
    if not signature_text:
        print("  (no signature saved for this incident)")
        return
    print("  signature_text:")
    for line in signature_text.splitlines():
        print(f"    {line}")
    print(f"  log_templates: {len(log_templates or {})} distinct template(s) stored")


def cmd_templates(service_name):
    rows = show_clusters(service_name)
    if not rows:
        print("  (no templates learned yet for this service)")
        return
    for cid, size, template in rows[:20]:
        print(f"  cluster {cid:<4} x{size:<5} {template}")


def cmd_resolve(conn, incident_id):
    with conn.cursor() as cur:
        cur.execute("SELECT status, title FROM incidents WHERE id = %s;", (incident_id,))
        row = cur.fetchone()
    if row is None:
        print(f"  no incident with id {incident_id}")
        return
    status, title = row
    if status != "open":
        print(f"  incident {incident_id} is already '{status}', nothing to resolve")
        return

    print(f"  resolving incident {incident_id}: \"{title}\"")
    root_cause = input("  root cause: ").strip()
    if not root_cause:
        print("  root cause is required - aborted")
        return
    close_incident(conn, incident_id, root_cause)


def cmd_logs(conn, service_name, n=10):
    service_id = get_service_id(conn, service_name)
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT timestamp, level, message, latency_ms FROM application_logs
            WHERE service_id = %s ORDER BY timestamp DESC LIMIT %s;
            """,
            (service_id, n),
        )
        rows = cur.fetchall()
    if not rows:
        print("  (no logs yet for this service)")
        return
    for ts, level, msg, latency in reversed(rows):
        print(f"  {ts}  {level:<5}  {msg}  ({latency}ms)")


def cmd_services(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT id, name, environment FROM services ORDER BY id;")
        for sid, name, env in cur.fetchall():
            print(f"  {sid:<4} {name:<12} {env}")


def repl():
    print("[console] connecting to the database...")
    conn = connect()
    ensure_schema(conn)
    ensure_services(conn)

    register_on_incident_opened(handle_incident_opened)
    start_log_monitoring(interval_seconds=30)
    print("[console] log monitor started (checks application_logs every 30s), agent registered")
    print("[console] connected. Type 'help' for commands, 'quit' to exit.\n")

    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()
        rest = parts[1:]

        try:
            if cmd in ("quit", "exit"):
                break

            elif cmd == "help":
                print(HELP)

            elif cmd in ("error", "warn", "info"):
                if len(rest) < 2:
                    print(f"  usage: {cmd} <service> <message...>")
                    continue
                service_name, message = rest[0], " ".join(rest[1:])
                write_log(conn, service_name, cmd, message)
                print(f"  wrote {cmd.upper()} log for {service_name}: \"{message}\"")
                service_id = get_service_id(conn, service_name)
                check_service(conn, service_id, service_name, quiet_if_nothing=False)

            elif cmd == "burst":
                if len(rest) < 3:
                    print("  usage: burst <n> <service> <message...>")
                    continue
                n = int(rest[0])
                service_name, message = rest[1], " ".join(rest[2:])
                for _ in range(n):
                    write_log(conn, service_name, "ERROR", message)
                print(f"  wrote {n} ERROR logs for {service_name}: \"{message}\"")
                service_id = get_service_id(conn, service_name)
                check_service(conn, service_id, service_name, quiet_if_nothing=False)

            elif cmd == "latency":
                if len(rest) < 2:
                    print("  usage: latency <service> <ms>")
                    continue
                service_name, ms = rest[0], float(rest[1])
                write_log(conn, service_name, "INFO", "request completed", latency_ms=ms)
                print(f"  wrote INFO log for {service_name} with latency_ms={ms}")
                service_id = get_service_id(conn, service_name)
                check_service(conn, service_id, service_name, quiet_if_nothing=False)

            elif cmd == "check":
                if rest:
                    service_name = rest[0]
                    service_id = get_service_id(conn, service_name)
                    check_service(conn, service_id, service_name, quiet_if_nothing=False)
                else:
                    evaluate_all_services(conn)

            elif cmd == "incidents":
                cmd_incidents(conn)

            elif cmd == "signature":
                if not rest:
                    print("  usage: signature <id>")
                    continue
                cmd_signature(conn, int(rest[0]))

            elif cmd == "templates":
                if not rest:
                    print("  usage: templates <service>")
                    continue
                cmd_templates(rest[0])

            elif cmd == "resolve":
                if not rest:
                    print("  usage: resolve <id>")
                    continue
                cmd_resolve(conn, int(rest[0]))

            elif cmd == "autoclose":
                minutes = int(rest[0]) if rest else RESOLVE_COOLDOWN_MINUTES
                autoclose(conn, minutes)

            elif cmd == "logs":
                if not rest:
                    print("  usage: logs <service> [n]")
                    continue
                service_name = rest[0]
                n = int(rest[1]) if len(rest) > 1 else 10
                cmd_logs(conn, service_name, n)

            elif cmd == "services":
                cmd_services(conn)

            elif cmd == "fp":
                if not rest:
                    print("  usage: fp <message...>")
                    continue
                message = " ".join(rest)
                print(f"  normalized: {normalize(message)}")
                print(f"  fingerprint: {fingerprint(message)}")

            elif cmd == "mask":
                if not rest:
                    print("  usage: mask <message...>")
                    continue
                print(f"  masked: {mask_log(' '.join(rest))}")

            else:
                print(f"  unknown command '{cmd}' - type 'help'")

        except Exception as e:
            print(f"  error: {e}")
            conn.rollback()

    conn.close()
    print("[console] closed.")


if __name__ == "__main__":
    repl()