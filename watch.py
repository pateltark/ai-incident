"""
loggs.py

Continuous Detector Engine + read-only console.  (ClickHouse version)

This file never writes logs. Use generate_logs.py + connector_layer.py for that.

LOGS live in ClickHouse (incident_copilot.application_logs).
Postgres keeps only the control plane: services, incidents, metrics,
change_events, certificates.

Rules:
  error_rate           elevated share of ERROR logs vs baseline
  new_error_type       an error fingerprint never seen in the last 24h
  latency_spike        p95 latency far above baseline
  traffic_silence      a service stopped logging
  traffic_drop         log volume far below the same time yesterday
  dependency_failure   connection refused / timeout / throttling ...   (pattern rule)
  resource_exhaustion  OOM / too many connections / disk full ...      (pattern rule)
  queue_backlog        DLQ / queue full / consumer lag ...             (pattern rule)
  auth_failure_spike   many failed logins / unauthorized ...           (pattern rule)
  cpu_high / memory_high / disk_high / restart_loop                    (metric rules)
  queue_age_high / queue_depth_growing / dlq_not_empty                 (metric rules)
  security_ip_spike    one IP with many failed-auth / 4xx / 5xx lines
  certificate_expiry   scheduled check (30 / 14 / 7 days)

Incidents are only CLOSED by a human (`resolve <id>`), which stores the root
cause + resolution and marks them confirmed. The LLM only suggests.
"""

import datetime
import hashlib
import json
import os
import re
import statistics
import sys
from collections import Counter
import threading
import time
import psycopg2
from dotenv import load_dotenv

from drain_templates import cluster_logs, show_clusters
from embedder import embed_incident
from main import handle_incident_opened
from db import (resolve_incident, ch_query, count_recent_pattern_hits,
                LOG_PATTERN_RULES, METRIC_RULES, SECURITY_RE,
                SECURITY_MINUTES, SECURITY_MIN_PER_IP)

LOGS_TABLE = "incident_copilot.application_logs"
ERROR_LEVELS = ("ERROR", "CRITICAL", "FATAL")

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
# Small helpers
# ---------------------------------------------------------------------------

_SERVICE_NAMES = {}


def service_name_of(conn, service_id):
    """service_id (Postgres) -> service name (used as the key in ClickHouse logs)."""
    if service_id not in _SERVICE_NAMES:
        with conn.cursor() as cur:
            cur.execute("SELECT name FROM services WHERE id = %s;", (service_id,))
            row = cur.fetchone()
        if row is None:
            raise ValueError(f"unknown service_id {service_id}")
        _SERVICE_NAMES[service_id] = row[0]
    return _SERVICE_NAMES[service_id]


def _aware(dt):
    """ClickHouse may return naive datetimes; treat them as UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt


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
    result = ch_query(
        f"""
        SELECT message, level FROM {LOGS_TABLE}
        WHERE service_id = %(service_id)s
          AND timestamp >= now() - INTERVAL %(mins)s MINUTE
          AND UPPER(level) IN ('ERROR', 'WARN')
        ORDER BY timestamp
        LIMIT %(limit)s;
        """,
        parameters={"service_id": service_id, "mins": window_minutes, "limit": SIGNATURE_MAX_LOGS},
    )
    rows = [tuple(r) for r in result.result_rows]
    if rows:
        return rows

    result = ch_query(
        f"""
        SELECT message, level FROM {LOGS_TABLE}
        WHERE service_id = %(service_id)s
          AND timestamp >= now() - INTERVAL %(mins)s MINUTE
        ORDER BY timestamp
        LIMIT %(limit)s;
        """,
        parameters={"service_id": service_id, "mins": window_minutes, "limit": SIGNATURE_MAX_LOGS},
    )
    return [tuple(r) for r in result.result_rows]

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

TRAFFIC_SILENCE_MINUTES = 5

TRAFFIC_DROP_MINUTES = 5
TRAFFIC_DROP_RATIO = 0.3          # fire if current volume < 30% of same time yesterday
TRAFFIC_DROP_MIN_BASELINE = 50    # ignore quiet services (yesterday < 50 logs in the window)
CERT_THRESHOLD_DAYS = (30, 14, 7)

SEVERITY_BY_RULE = {
    "error_rate": "high",
    "new_error_type": "medium",
    "latency_spike": "medium",
    "traffic_silence": "high",
    "traffic_drop": "medium",
    "security_ip_spike": "high",
    "certificate_expiry": "medium",    # raise to "high" at 7 days left
    "resource_saturation": "high",
}
SEVERITY_BY_RULE.update({rule: cfg["severity"] for rule, cfg in LOG_PATTERN_RULES.items()})
SEVERITY_BY_RULE.update({rule: cfg["severity"] for rule, cfg in METRIC_RULES.items()})

RESOLVE_COOLDOWN_MINUTES = 10


# ---------------------------------------------------------------------------
# DB Config & Core Utilities (Postgres = control plane only)
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
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS evidence text;")
        cur.execute("UPDATE incidents SET error_type = rule WHERE error_type IS NULL AND rule IS NOT NULL;")

        # --- FIX: Added partial unique index for open incidents deduplication ---
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_open_incident 
            ON incidents (service_id, fingerprint) 
            WHERE (status = 'open');
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS metrics (
                id bigserial PRIMARY KEY,
                service_id int REFERENCES services(id),
                metric text NOT NULL,
                value double precision NOT NULL,
                timestamp timestamptz NOT NULL DEFAULT now()
            );""")
        cur.execute("CREATE INDEX IF NOT EXISTS metrics_lookup ON metrics (metric, timestamp);")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS change_events (
                id bigserial PRIMARY KEY,
                service_id int REFERENCES services(id),
                kind text NOT NULL,
                description text,
                timestamp timestamptz NOT NULL DEFAULT now()
            );""")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                name text PRIMARY KEY,
                expires_at timestamptz NOT NULL,
                services text
            );""")
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


def evaluate_traffic_silence(last_timestamp):
    if not last_timestamp:
        return False, None

    now = datetime.datetime.now(datetime.timezone.utc)
    last_timestamp = _aware(last_timestamp)

    delta_minutes = (now - last_timestamp).total_seconds() / 60

    if delta_minutes >= TRAFFIC_SILENCE_MINUTES:
        return True, {"last_seen": last_timestamp, "silent_minutes": int(delta_minutes)}

    return False, None


def evaluate_pattern_rule(count, min_count):
    return count >= min_count


def evaluate_traffic_drop(current, yesterday):
    if yesterday < TRAFFIC_DROP_MIN_BASELINE:
        return False, None
    if current >= TRAFFIC_DROP_RATIO * yesterday:
        return False, None
    return True, {"current": current, "yesterday": yesterday}


def evaluate_metric_rule(values, cfg):
    if len(values) < cfg["min_samples"]:
        return False, None
    thr, kind = cfg["threshold"], cfg["kind"]
    if kind == "above":
        fired = all(v > thr for v in values)
    elif kind == "increase":
        fired = values[-1] - values[0] >= thr
    elif kind == "growing":
        half = len(values) // 2
        older, recent = values[:half], values[half:]
        fired = bool(older) and values[-1] >= thr and statistics.mean(recent) >= 1.5 * statistics.mean(older)
    else:
        fired = False
    if not fired:
        return False, None
    return True, {"first": values[0], "last": values[-1], "threshold": thr, "samples": len(values)}


def evaluate_security(messages):
    ips = Counter()
    for msg in messages:
        if SECURITY_RE.search(msg):
            m = _IP_RE.search(msg)
            if m:
                ips[m.group(0)] += 1
    return [(ip, c) for ip, c in ips.most_common() if c >= SECURITY_MIN_PER_IP]


# ---------------------------------------------------------------------------
# Data fetchers for the rules
# ---------------------------------------------------------------------------

def fetch_error_rate_buckets(conn, service_id):
    result = ch_query(
        f"""
        SELECT toStartOfMinute(timestamp) AS bucket,
               count() AS total,
               countIf(UPPER(level) IN %(levels)s) AS errors
        FROM {LOGS_TABLE}
        WHERE service_id = %(service_id)s
          AND timestamp >= now() - INTERVAL 32 MINUTE
        GROUP BY bucket
        ORDER BY bucket;
        """,
        parameters={"service_id": service_id, "levels": ERROR_LEVELS},
    )
    return [(_aware(b), int(t), int(e)) for b, t, e in result.result_rows]


def fetch_latency_buckets(conn, service_id):
    result = ch_query(
        f"""
        SELECT toStartOfMinute(timestamp) AS bucket,
               quantile(0.95)(latency_ms) AS p95
        FROM {LOGS_TABLE}
        WHERE service_id = %(service_id)s
          AND timestamp >= now() - INTERVAL 33 MINUTE
          AND latency_ms IS NOT NULL
        GROUP BY bucket
        ORDER BY bucket;
        """,
        parameters={"service_id": service_id},
    )
    out = []
    for b, p95 in result.result_rows:
        p95 = None if p95 is None or p95 != p95 else float(p95)
        out.append((_aware(b), p95))
    return out


def fetch_error_messages(conn, service_id):
    result = ch_query(
        f"""
        SELECT message,
               timestamp >= now() - INTERVAL %(recent)s MINUTE AS is_recent
        FROM {LOGS_TABLE}
        WHERE service_id = %(service_id)s
          AND UPPER(level) IN %(levels)s
          AND timestamp >= now() - INTERVAL %(hours)s HOUR;
        """,
        parameters={
            "service_id": service_id, "levels": ERROR_LEVELS,
            "recent": NEW_ERROR_TYPE_RECENT_MINUTES,
            "hours": NEW_ERROR_TYPE_HISTORY_HOURS,
        },
    )
    history_fps, recent_rows = set(), []
    for message, is_recent in result.result_rows:
        fp = fingerprint(message)
        if is_recent:
            recent_rows.append((fp, message))
        else:
            history_fps.add(fp)
    return history_fps, recent_rows


def fetch_last_log_timestamp(conn, service_id):
    result = ch_query(
        f"SELECT count(), max(timestamp) FROM {LOGS_TABLE} WHERE service_id = %(service_id)s;",
        parameters={"service_id": service_id},
    )
    n, last = result.result_rows[0]
    if not n:
        return None
    return _aware(last)


def fetch_pattern_hits(conn, service_id, regex, levels, minutes):
    name = service_name_of(conn, service_id)
    return count_recent_pattern_hits(name, regex, levels, minutes)


def fetch_traffic_counts(conn, service_id, minutes):
    name = service_name_of(conn, service_id)
    result = ch_query(
        f"""
        SELECT countIf(timestamp >= now() - INTERVAL %(m)s MINUTE),
               countIf(timestamp >= now() - INTERVAL 1 DAY - INTERVAL %(m)s MINUTE
                       AND timestamp <  now() - INTERVAL 1 DAY)
        FROM {LOGS_TABLE}
        WHERE service_name = %(service)s
          AND timestamp >= now() - INTERVAL 1 DAY - INTERVAL %(m)s MINUTE;
        """,
        parameters={"service": name, "m": minutes},
    )
    cur_n, yest_n = result.result_rows[0]
    return int(cur_n), int(yest_n)


def fetch_security_messages(conn, service_id, minutes):
    name = service_name_of(conn, service_id)
    result = ch_query(
        f"""
        SELECT message FROM {LOGS_TABLE}
        WHERE service_name = %(service)s
          AND timestamp >= now() - INTERVAL %(m)s MINUTE
        LIMIT 5000;
        """,
        parameters={"service": name, "m": minutes},
    )
    return [r[0] for r in result.result_rows]


def fetch_metric_values(conn, service_id, metric, minutes):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT value FROM metrics
            WHERE service_id = %s AND metric = %s
              AND timestamp >= now() - (%s * interval '1 minute')
            ORDER BY timestamp;
            """,
            (service_id, metric, minutes),
        )
        return [float(r[0]) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Opening incidents
# ---------------------------------------------------------------------------

OPEN_INCIDENT_SQL = """
    INSERT INTO incidents (service_id, rule, fingerprint, title, description, severity, status, started_at)
    VALUES (%s, %s, %s, %s, %s, %s, 'open', now())
    ON CONFLICT (service_id, fingerprint) WHERE status = 'open' DO NOTHING
    RETURNING id;
"""

INCIDENT_OPENED_CALLBACKS = []


def register_on_incident_opened(callback):
    INCIDENT_OPENED_CALLBACKS.append(callback)


def recent_incident_exists(conn, service_id, fp, minutes=15):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id FROM incidents 
            WHERE service_id = %s 
              AND fingerprint = %s 
              AND started_at >= now() - interval '%s minutes';
            """,
            (service_id, fp, minutes)
        )
        return cur.fetchone() is not None


def try_open_incident(conn, service_id, service_name, rule, fp, title, description):
    if recent_incident_exists(conn, service_id, fp, minutes=15):
        return None  # Suppress duplicate alert/incident

    severity = SEVERITY_BY_RULE.get(rule, "medium")
    with conn.cursor() as cur:
        cur.execute(OPEN_INCIDENT_SQL, (service_id, rule, fp, title, description, severity))
        row = cur.fetchone()
    conn.commit()

    if row is None:
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


def check_extra_rules(conn, service_id, service_name):
    fired_any = False

    current, yesterday = fetch_traffic_counts(conn, service_id, TRAFFIC_DROP_MINUTES)
    fired, detail = evaluate_traffic_drop(current, yesterday)
    if fired:
        fired_any = True
        try_open_incident(
            conn, service_id, service_name, "traffic_drop",
            fingerprint(f"traffic_drop:{service_name}"),
            f"Traffic drop in {service_name}",
            f"{detail['current']} logs in the last {TRAFFIC_DROP_MINUTES} min vs "
            f"{detail['yesterday']} at the same time yesterday.",
        )

    for rule, cfg in METRIC_RULES.items():
        values = fetch_metric_values(conn, service_id, cfg["metric"], cfg["minutes"])
        fired, detail = evaluate_metric_rule(values, cfg)
        if fired:
            fired_any = True
            try_open_incident(
                conn, service_id, service_name, rule,
                fingerprint(f"{rule}:{service_name}"),
                f"{rule.replace('_', ' ').capitalize()} in {service_name}",
                f"{cfg['metric']} went {detail['first']:.1f} -> {detail['last']:.1f} "
                f"(threshold {detail['threshold']}, {detail['samples']} samples in {cfg['minutes']} min).",
            )

    for ip, count in evaluate_security(fetch_security_messages(conn, service_id, SECURITY_MINUTES)):
        fired_any = True
        try_open_incident(
            conn, service_id, service_name, "security_ip_spike",
            fingerprint(f"security_ip_spike:{service_name}:{ip}"),
            f"Suspicious traffic from {ip} on {service_name}",
            f"{count} failed-auth or 4xx/5xx requests from {ip} in the last {SECURITY_MINUTES} minutes.",
        )

    return fired_any


def check_certificates(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT name, expires_at, services FROM certificates;")
        certs = cur.fetchall()
    now = datetime.datetime.now(datetime.timezone.utc)
    for name, expires_at, services in certs:
        expires_at = _aware(expires_at)
        days_left = (expires_at - now).days
        bucket = next((d for d in sorted(CERT_THRESHOLD_DAYS) if days_left <= d), None)
        if bucket is None:
            continue
        service_name = (services or "platform").split(",")[0].strip()
        service_id = get_service_id(conn, service_name)
        try_open_incident(
            conn, service_id, service_name, "certificate_expiry",
            fingerprint(f"certificate_expiry:{name}:{bucket}"),
            f"Certificate {name} expires in {days_left} days",
            f"Certificate '{name}' expires on {expires_at:%Y-%m-%d} ({days_left} days left). "
            f"Used by: {services or 'unknown'}.",
        )


# ---------------------------------------------------------------------------
# DETECTOR ENGINE: Continuous Application Logs Watcher
# ---------------------------------------------------------------------------

def check_service(conn, service_id, service_name, quiet_if_nothing=True):
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

    fired, detail = evaluate_traffic_silence(fetch_last_log_timestamp(conn, service_id))
    if fired:
        fired_any = True
        try_open_incident(
            conn, service_id, service_name, "traffic_silence",
            fingerprint(f"traffic_silence:{service_name}"),
            f"No logs from {service_name}",
            f"No logs for {detail['silent_minutes']} minutes "
            f"(last log at {detail['last_seen']:%H:%M:%S}).",
        )

    for rule, cfg in LOG_PATTERN_RULES.items():
        count, sample = fetch_pattern_hits(
            conn, service_id, cfg["regex"], cfg["levels"], cfg["minutes"]
        )
        if evaluate_pattern_rule(count, cfg["min_count"]):
            fired_any = True
            try_open_incident(
                conn, service_id, service_name, rule,
                fingerprint(f"{rule}:{service_name}"),
                f"{rule.replace('_', ' ').capitalize()} in {service_name}",
                f'{count} matching logs in the last {cfg["minutes"]} minutes. Example: "{sample}"',
            )

    if check_extra_rules(conn, service_id, service_name):
        fired_any = True

    if not fired_any and not quiet_if_nothing:
        print(f"  (no rule fired for {service_name})")
    return fired_any


def evaluate_all_services(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT id, name FROM services;")
        services = cur.fetchall()
    any_fired = False
    for service_id, service_name in services:
        if check_service(conn, service_id, service_name, quiet_if_nothing=True):
            any_fired = True

    try:
        check_certificates(conn)
    except Exception as e:
        conn.rollback()
        print(f"[Log Monitor] certificate check failed: {e}")

    return any_fired


def monitor_application_logs(poll_interval=5.0):
    conn = connect()
    print("[Log Monitor] Started real-time live log tailer...")

    # Per-service time cursor so we never skip or re-read logs.
    service_checkpoints = {}

    while True:
        try:
            if conn is None or conn.closed:
                conn = connect()

            with conn.cursor() as cur:
                cur.execute("SELECT id, name FROM services;")
                services = cur.fetchall()

            for service_id, service_name in services:
                if service_id not in service_checkpoints:
                    # Use ClickHouse's own clock to avoid timezone/clock skew issues
                    res_time = ch_query("SELECT now()").result_rows[0][0]
                    service_checkpoints[service_id] = _aware(res_time)

                last_ts = service_checkpoints[service_id]

                # FIX 1: send the checkpoint as a full-precision string.
                # clickhouse_connect formats a plain datetime parameter without
                # fractional seconds, so "timestamp > 12:04:10" kept matching a
                # row stamped 12:04:10.114 on every single poll.
                last_ts_str = last_ts.strftime("%Y-%m-%d %H:%M:%S.%f")

                result = ch_query(
                    f"""
                    SELECT timestamp, level, message, latency_ms
                    FROM {LOGS_TABLE}
                    WHERE service_id = %(service_id)s
                      AND timestamp > toDateTime64(%(last_ts)s, 6)
                    ORDER BY timestamp ASC
                    LIMIT 100;
                    """,
                    parameters={
                        "service_id": service_id,
                        "last_ts": last_ts_str,
                    },
                )

                rows = result.result_rows
                for ts, level, message, latency in rows:
                    ts_aware = _aware(ts)

                    # FIX 2 (safety net): never process a row at or before the
                    # checkpoint, even if the DB hands it back again.
                    if ts_aware <= service_checkpoints[service_id]:
                        continue
                    service_checkpoints[service_id] = ts_aware

                    print(f"[LIVE LOG] {ts} [{service_name}] {level}: {message}")

                    if level in ERROR_LEVELS:
                        clean_message = message
                        matched_rule = "new_error_type"

                        for rule, cfg in LOG_PATTERN_RULES.items():
                            if re.search(cfg["regex"], clean_message, re.IGNORECASE):
                                matched_rule = rule
                                break

                        try_open_incident(
                            conn, service_id, service_name, matched_rule,
                            fingerprint(clean_message),
                            f"{matched_rule.replace('_', ' ').capitalize()} in {service_name}",
                            f'"{clean_message}"'
                        )

        except (psycopg2.OperationalError, psycopg2.InterfaceError):
            print("[Log Monitor] Database connection lost. Reconnecting in 5s...")
            time.sleep(5)
            try:
                conn = connect()
            except Exception:
                pass
        except Exception as e:
            if conn and not conn.closed:
                conn.rollback()
            print(f"[Log Monitor] Error in live tailer: {e}")

        time.sleep(poll_interval)


def start_log_monitoring(interval_seconds=30):
    thread = threading.Thread(
        target=monitor_application_logs, args=(interval_seconds,), daemon=True
    )
    thread.start()
    return thread


# ---------------------------------------------------------------------------
# Recovery check
# ---------------------------------------------------------------------------

def fetch_open_incidents(conn):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, service_id, rule, fingerprint, started_at
            FROM incidents WHERE status = 'open' ORDER BY started_at;
        """)
        return cur.fetchall()


def is_extra_rule_quiet(conn, service_id, rule, cooldown_minutes):
    if rule in METRIC_RULES:
        cfg = METRIC_RULES[rule]
        values = fetch_metric_values(conn, service_id, cfg["metric"], cooldown_minutes)
        fired, _ = evaluate_metric_rule(values, {**cfg, "min_samples": 1})
        return bool(values) and not fired
    if rule == "traffic_drop":
        current, yesterday = fetch_traffic_counts(conn, service_id, TRAFFIC_DROP_MINUTES)
        return not evaluate_traffic_drop(current, yesterday)[0]
    if rule == "security_ip_spike":
        return not evaluate_security(fetch_security_messages(conn, service_id, cooldown_minutes))
    if rule == "certificate_expiry":
        return False
    return None


def is_condition_quiet(conn, service_id, rule, fp, cooldown_minutes):
    extra = is_extra_rule_quiet(conn, service_id, rule, cooldown_minutes)
    if extra is not None:
        return extra

    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=cooldown_minutes)

    if rule == "error_rate":
        buckets = fetch_error_rate_buckets(conn, service_id)
        recent = [b for b in buckets if b[0] >= cutoff]
        if not recent:
            return False
        rates = [ec / tc for _, tc, ec in recent if tc > 0]
        return bool(rates) and all(r < ERROR_RATE_FLOOR for r in rates)

    if rule == "new_error_type":
        name = service_name_of(conn, service_id)
        result = ch_query(
            f"""
            SELECT message FROM {LOGS_TABLE}
            WHERE service_name = %(service)s AND UPPER(level) IN %(levels)s
              AND timestamp >= now() - INTERVAL %(m)s MINUTE;
            """,
            parameters={"service": name, "levels": ERROR_LEVELS, "m": cooldown_minutes},
        )
        return fp not in {fingerprint(r[0]) for r in result.result_rows}

    if rule == "latency_spike":
        buckets = fetch_latency_buckets(conn, service_id)
        recent = [b for b in buckets if b[0] >= cutoff]
        if not recent:
            return False
        baseline_pool = buckets[:-len(recent)] if len(buckets) > len(recent) else []
        baseline_vals = [p95 for _, p95 in baseline_pool if p95 is not None]
        if not baseline_vals:
            return False
        baseline_median = statistics.median(baseline_vals)
        if baseline_median <= 0:
            return False
        return all(p95 is not None and p95 < LATENCY_SPIKE_MULT * baseline_median for _, p95 in recent)

    if rule == "traffic_silence":
        last = fetch_last_log_timestamp(conn, service_id)
        fired, _ = evaluate_traffic_silence(last)
        return last is not None and not fired

    if rule in LOG_PATTERN_RULES:
        cfg = LOG_PATTERN_RULES[rule]
        count, _ = fetch_pattern_hits(conn, service_id, cfg["regex"], cfg["levels"], cooldown_minutes)
        return count == 0

    return False


def autoclose(conn, cooldown_minutes=RESOLVE_COOLDOWN_MINUTES):
    open_incidents = fetch_open_incidents(conn)
    if not open_incidents:
        print("  (no open incidents)")
        return
    for incident_id, service_id, rule, fp, started_at in open_incidents:
        if is_condition_quiet(conn, service_id, rule, fp, cooldown_minutes):
            print(f"  incident {incident_id} ({rule}): condition cleared. "
                  f"Run 'resolve {incident_id}' to record the root cause and fix.")
        else:
            print(f"  incident {incident_id} ({rule}): still active")


# ---------------------------------------------------------------------------
# Interactive Console
# ---------------------------------------------------------------------------

HELP = """
This console only WATCHES. It never writes logs.
Logs come from:  generate_logs.py -> app.log -> connector_layer.py -> ClickHouse

Commands:
  check [service]                     manually run detection (all services, or just one)
  rules                               list all detection rules
  incidents                           list all incidents
  signature <id>                      show saved signature text + template counts of an incident
  templates <service>                 show Drain templates learned for a service
  resolve <id>                        close an incident: you type root cause + resolution
  autoclose [minutes]                 report open incidents whose condition has cleared
  logs <service> [n]                  show last n logs for a service (from ClickHouse)
  services                            list known services
  fp <message...>                     show fingerprint normalization/hash
  mask <message...>                   show old regex masking
  help                                show this again
  quit / exit                         stop
"""


def cmd_rules():
    print("  built-in rules:")
    print(f"    error_rate       errors > max({ERROR_RATE_FLOOR:.0%}, {ERROR_RATE_BASELINE_MULT}x baseline) for {ERROR_RATE_CONSEC_MINUTES} min")
    print(f"    new_error_type   new fingerprint, >= {NEW_ERROR_TYPE_MIN_COUNT} times in {NEW_ERROR_TYPE_RECENT_MINUTES} min")
    print(f"    latency_spike    p95 > {LATENCY_SPIKE_MULT}x baseline for {LATENCY_SPIKE_CONSEC_MINUTES} min")
    print(f"    traffic_silence  no logs for {TRAFFIC_SILENCE_MINUTES} min")
    print(f"    traffic_drop     < {TRAFFIC_DROP_RATIO:.0%} of yesterday's volume over {TRAFFIC_DROP_MINUTES} min")
    print("  pattern rules:")
    for rule, cfg in LOG_PATTERN_RULES.items():
        print(f"    {rule:<20} >= {cfg['min_count']} matches in {cfg['minutes']} min  /{cfg['regex']}/")
    print("  metric rules:")
    for rule, cfg in METRIC_RULES.items():
        print(f"    {rule:<20} {cfg['metric']} {cfg['kind']} {cfg['threshold']} over {cfg['minutes']} min")
    print(f"  security_ip_spike    >= {SECURITY_MIN_PER_IP} failed-auth/4xx/5xx lines from one IP in {SECURITY_MINUTES} min")
    print(f"  certificate_expiry   certificate expires within {', '.join(str(d) for d in CERT_THRESHOLD_DAYS)} days")


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
    print(f"  {'id':<4} {'service':<10} {'rule':<20} {'fingerprint':<14} {'status':<10} {'severity':<8} started_at")
    for r in rows:
        print(f"  {r[0]:<4} {r[1]:<10} {r[2] or '-':<20} {r[3] or '-':<14} {r[4]:<10} {r[5]:<8} {r[6]}")


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
        cur.execute("SELECT status, title, description FROM incidents WHERE id = %s;", (incident_id,))
        row = cur.fetchone()
    if row is None:
        print(f"  no incident with id {incident_id}")
        return
    status, title, description = row
    if status == "resolved":
        print(f"  incident {incident_id} is already resolved, nothing to do")
        return

    print(f"  resolving incident {incident_id}: \"{title}\"")
    if description:
        print(f"  symptoms: {description}")
    root_cause = input("  root cause (what was wrong): ").strip()
    resolution = input("  resolution (what fixed it): ").strip()
    try:
        ok = resolve_incident(incident_id, root_cause, resolution)
    except ValueError as e:
        print(f"  not saved: {e}")
        return
    print("  >>> INCIDENT RESOLVED, root cause and resolution saved (confirmed)" if ok
          else "  nothing updated (already resolved?)")


def cmd_logs(conn, service_name, n=10):
    result = ch_query(
        f"""
        SELECT timestamp, level, message, latency_ms FROM {LOGS_TABLE}
        WHERE service_name = %(service)s
        ORDER BY timestamp DESC LIMIT %(limit)s;
        """,
        parameters={"service": service_name, "limit": n},
    )
    rows = result.result_rows
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
    print("[console] log monitor started (checks ClickHouse application_logs every 30s), agent registered")
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

            elif cmd == "check":
                if rest:
                    service_name = rest[0]
                    service_id = get_service_id(conn, service_name)
                    check_service(conn, service_id, service_name, quiet_if_nothing=False)
                else:
                    evaluate_all_services(conn)

            elif cmd == "rules":
                cmd_rules()

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