"""
console.py

Everything in one file, under your manual control: you type a command,
it writes exactly the log line you asked for straight into the database
(no log files, no ingestor, no background generator), then immediately
runs the same detection rules and fingerprinting logic we built earlier
against that data - so you see, right away, whether it opened an
incident.

This version adds the CLOSE side: a manual `resolve` command (you type
the root cause / fix, it saves them and closes the row) and an
`autoclose` command that checks every open incident's condition and
closes the ones that have gone quiet - the same "did the signal stop"
logic your V4 resolution watcher will eventually run on a schedule.

NEW in this version: SIGNATURE TEXT.
When an incident opens, we automatically build a "signature" from the
logs (no human description, no LLM needed):
    service: payment
    error_type: DBConnectionTimeout
    top_log_templates:
      - Timeout connecting to payment-db after <NUM>ms (x120)
      - ...
    first_error: Timeout connecting to payment-db...
and save it on the incident (`signature_text`) together with the raw
template counts (`log_templates`, jsonb). This is what you will embed
and search on later to find similar, already-solved incidents.

EMBEDDING: right after the signature is saved, the incident's templates
are turned into a clean embed text (build_embed_text) and embedded with
sentence-transformers; the vector goes into `incidents.embedding`.
Set EMBED_MODEL in .env to use another model (default all-MiniLM-L6-v2,
384 dimensions - your `embedding` column must match that size).
    pip install sentence-transformers

Setup:
    pip install psycopg2-binary python-dotenv sentence-transformers
    (uses the same .env as before: DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD)

Run:
    python console.py

Then type commands at the prompt. Type `help` to see all of them.
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

import psycopg2
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Fingerprinting - identical logic to fingerprint.py, inlined so this file
# has no dependency on the others.
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
# Signature text - NEW
#
# Turns the raw logs around an incident into a clean, human-readable
# "signature" (masked templates + counts + first error). Same function is
# used for every incident, old or new, so signatures stay comparable.
# ---------------------------------------------------------------------------

SIGNATURE_WINDOW_MINUTES = 15      # how far back from "incident opened" we look for logs
SIGNATURE_TOP_TEMPLATES = 5        # how many templates go into the signature text
SIGNATURE_STORE_TEMPLATES = 50     # how many templates (with counts) go into the jsonb column
SIGNATURE_MAX_LOGS = 5000          # safety cap on rows pulled per incident
FIRST_ERROR_MAX_CHARS = 200

# These differ from normalize() above on purpose: they keep the original
# casing (readable text) and use <NUM>/<ID>/<IP>/<TS> placeholders.
# Look-arounds are used instead of \b so ids glued to '_' or '=' still match
# (e.g. txn_8f3a9c01d2, req_id=a81f...).
_SIG_TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)
_SIG_UUID_RE = re.compile(
    r"(?<![0-9A-Za-z])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9A-Za-z])",
    re.IGNORECASE,
)
_SIG_IP_RE = re.compile(r"(?<![0-9A-Za-z])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Za-z])")
# long hex-looking tokens that mix digits and letters (request ids, txn ids)
_SIG_HEX_RE = re.compile(
    r"(?<![0-9A-Za-z])(?=[0-9a-f]*\d)(?=[0-9a-f]*[a-f])[0-9a-f]{8,}(?![0-9A-Za-z])",
    re.IGNORECASE,
)
# numbers not glued to a preceding letter (so 'p95' and 'db2' stay, '5003ms' -> '<NUM>ms')
_SIG_NUM_RE = re.compile(r"(?<![A-Za-z])\d+(?:\.\d+)?")


def mask_log(message: str) -> str:
    """Replace the parts of a log line that change every time with placeholders."""
    text = message.strip()
    text = _SIG_TS_RE.sub("<TS>", text)
    text = _SIG_UUID_RE.sub("<ID>", text)
    text = _SIG_IP_RE.sub("<IP>", text)
    text = _SIG_HEX_RE.sub("<ID>", text)
    text = _SIG_NUM_RE.sub("<NUM>", text)
    text = _WS_RE.sub(" ", text)
    return text


def build_signature(service_name, error_type, rows, top_n=SIGNATURE_TOP_TEMPLATES):
    """
    rows: list of (message, level), oldest first.
    Returns (signature_text, templates_dict).

    NOTE: this console has no separate "error type" yet, so the caller passes
    the detector rule name (error_rate / new_error_type / latency_spike) as
    error_type. If you later get a real error type (e.g. DBConnectionTimeout),
    just pass that instead - nothing else changes.
    """
    if not rows:
        text = (
            f"service: {service_name}\n"
            f"error_type: {error_type}\n"
            f"top_log_templates:\n"
            f"  (no logs found in the last {SIGNATURE_WINDOW_MINUTES} minutes)\n"
            f"first_error: (none)"
        )
        return text, {}

    templates = Counter(mask_log(msg) for msg, _ in rows)
    top = templates.most_common(top_n)

    # first error = earliest ERROR line; fall back to the earliest line of any level
    first_raw = next((msg for msg, level in rows if level == "ERROR"), rows[0][0]).strip()
    if len(first_raw) > FIRST_ERROR_MAX_CHARS:
        first_raw = first_raw[:FIRST_ERROR_MAX_CHARS] + "..."

    lines = [f"service: {service_name}", f"error_type: {error_type}", "top_log_templates:"]
    for template, count in top:
        lines.append(f"  - {template} (x{count})")
    lines.append(f"first_error: {first_raw}")

    return "\n".join(lines), dict(templates.most_common(SIGNATURE_STORE_TEMPLATES))


def build_embed_text(service_name, error_type, templates):
    """
    The cleaner text you should actually EMBED later: no counts, no field
    labels, no service_id (use service_id as a SQL filter instead).
    `templates` is the dict stored in incidents.log_templates.
    """
    top = sorted(templates, key=templates.get, reverse=True)[:SIGNATURE_TOP_TEMPLATES]
    return f"{error_type} {service_name}\n" + "\n".join(top)


def fetch_signature_logs(conn, service_id, window_minutes=SIGNATURE_WINDOW_MINUTES):
    """Logs for this service in the window before the incident opened. ERROR/WARN first."""
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

    # e.g. a latency_spike with no errors: fall back to every level so the
    # signature still says something (usually "request completed (xN)")
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


# --- embeddings -------------------------------------------------------------
# The model runs right here in this file - nothing to put in .env.
# The first time it is used, sentence-transformers downloads it automatically
# (about 90 MB, one time only) and caches it on your machine.
# This model gives 384 numbers per vector, so incidents.embedding must be vector(384).
# If you change the model, change the column size to match
# (all-mpnet-base-v2 = 768).
EMBED_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
_EMBEDDER = None


def get_embedder():
    """Loads the model once (first use is slow, later calls are instant)."""
    global _EMBEDDER
    if _EMBEDDER is None:
        from sentence_transformers import SentenceTransformer
        print(f"  (loading embedding model {EMBED_MODEL_NAME} ...)")
        _EMBEDDER = SentenceTransformer(EMBED_MODEL_NAME)
    return _EMBEDDER


def embed_text(text):
    """Text -> list of floats. Normalized so cosine distance (<=>) works well."""
    vec = get_embedder().encode(text, normalize_embeddings=True)
    return [float(x) for x in vec]


def save_embedding(conn, incident_id, service_name, rule, templates):
    """
    Embeds the CLEAN text (build_embed_text: no counts, no labels, no service_id),
    not the full signature_text, and saves it in incidents.embedding.
    """
    text = build_embed_text(service_name, rule, templates)
    vec = embed_text(text)
    vec_literal = "[" + ",".join(f"{x:.6f}" for x in vec) + "]"  # pgvector text format
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE incidents SET embedding = %s::vector WHERE id = %s;",
            (vec_literal, incident_id),
        )
    conn.commit()
    return len(vec)


def store_signature(conn, incident_id, service_id, service_name, rule):
    """Build the signature for a freshly opened incident and save it on the row."""
    rows = fetch_signature_logs(conn, service_id)
    signature_text, templates = build_signature(service_name, rule, rows)
    with conn.cursor() as cur:
        # error_type: this console has no real error type yet, so the detector
        # rule is used (same value that appears in the signature text).
        cur.execute(
            SAVE_SIGNATURE_SQL,
            (signature_text, json.dumps(templates), rule[:100], incident_id),
        )
    conn.commit()

    # Embedding is a separate step: if the model or the column dimension is
    # wrong, the signature above is already saved and the incident still opens.
    try:
        dims = save_embedding(conn, incident_id, service_name, rule, templates)
        print(f"      embedding saved ({dims} dims)")
    except Exception as e:
        conn.rollback()
        print(f"  (could not save embedding for incident {incident_id}: {e})")

    return signature_text


# ---------------------------------------------------------------------------
# Detection thresholds - same starting values as detector.py
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

# --- resolution / closing thresholds -----------------------------------
# How long a condition has to stay quiet before we consider an incident
# resolved. Same idea as a "flap" window in real incident tooling - short
# enough that you're not waiting forever in a demo, long enough that one
# quiet minute doesn't falsely close something that's still flapping.
RESOLVE_COOLDOWN_MINUTES = 10


# ---------------------------------------------------------------------------
# DB
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
    """Adds the two new columns if they aren't there yet (safe to run every start)."""
    with conn.cursor() as cur:
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS signature_text text;")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS log_templates jsonb;")
        cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS error_type varchar(100);")
        # old incidents (opened before this feature) have error_type NULL: fill from rule
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


# ---------------------------------------------------------------------------
# Writing a log line - this is the "trigger"
# ---------------------------------------------------------------------------

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
# Detection - same rule logic as detector.py, inlined
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


# Add a global callback list or trigger function
INCIDENT_OPENED_CALLBACKS = []

def register_on_incident_opened(callback):
    """Register a listener/agent runner when an incident opens."""
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

    # NEW: build the signature text from the logs and save it on the incident.
    # Done BEFORE the callbacks so agents already get it in the alert payload.
    # If it fails, the incident stays open - the signature is an add-on, not a blocker.
    signature_text = None
    try:
        signature_text = store_signature(conn, incident_id, service_id, service_name, rule)
        print("      signature saved:")
        for sig_line in signature_text.splitlines():
            print(f"        {sig_line}")
    except Exception as e:
        conn.rollback()
        print(f"  (could not build signature for incident {incident_id}: {e})")

    # Build alert payload
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

    # Automatically notify agents in-memory without relying on DB status updates
    for callback in INCIDENT_OPENED_CALLBACKS:
        try:
            callback(alert_payload)
        except Exception as e:
            print(f"Error triggering callback for incident {incident_id}: {e}")

    return incident_id


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

    if not fired_any and not quiet_if_nothing:
        print(f"  (no rule fired for {service_name})")
    return fired_any


def check_all(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT id, name FROM services;")
        services = cur.fetchall()
    any_fired = False
    for service_id, service_name in services:
        if check_service(conn, service_id, service_name, quiet_if_nothing=True):
            any_fired = True
    if not any_fired:
        print("  no incidents opened (quiet across all services)")


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
    print("      root cause and resolution saved - embedding can be added later once you wire that up")
    return True


def fetch_open_incidents(conn):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, service_id, rule, fingerprint, started_at
            FROM incidents WHERE status = 'open' ORDER BY started_at;
        """)
        return cur.fetchall()


def is_condition_quiet(conn, service_id, rule, fp, cooldown_minutes):
    """
    Checks whether the condition that opened this incident has stopped
    happening for at least `cooldown_minutes`. Rule-specific because each
    rule type means something different by "quiet":
      - error_rate:     recent error rate has dropped back under the floor
      - new_error_type: that exact fingerprint hasn't shown up in the window
      - latency_spike:  recent p95 has dropped back under the spike threshold
    """
    if rule == "error_rate":
        buckets = fetch_error_rate_buckets(conn, service_id)
        recent = [b for b in buckets if b[0] >= datetime.datetime.now(datetime.timezone.utc)
                  - datetime.timedelta(minutes=cooldown_minutes)]
        if not recent:
            return False  # no data at all in the window - don't guess, stay open
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

    # unknown rule type - don't auto-close something we don't understand
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
        # No investigation agent wired up yet in this console, so if nobody
        # has filled in root_cause/resolution (e.g. via `resolve`), close with
        # a clear placeholder rather than silently leaving those columns null.
        with conn.cursor() as cur:
            cur.execute("SELECT root_cause, resolution FROM incidents WHERE id = %s;", (incident_id,))
            existing_root_cause, existing_resolution = cur.fetchone()
        root_cause = existing_root_cause or "(auto-closed: condition cleared, no investigation recorded)"
        resolution = existing_resolution or "(condition stopped firing before a fix was recorded)"
        # No human confirmed this closure, and there's no agent hypothesis to
        # fall back on either at this stage - 'unknown' is the honest label
        # matching the schema's vocabulary (confirmed/inferred/unknown).
        confidence = "unknown" if not existing_root_cause else "inferred"
        if close_incident(conn, incident_id, root_cause, resolution, confidence):
            closed_any = True
    if not closed_any:
        print("  nothing closed this pass")


# ---------------------------------------------------------------------------
# Interactive console
# ---------------------------------------------------------------------------

HELP = """
Commands:
  error <service> <message...>        write one ERROR log, then check that service
  warn  <service> <message...>        write one WARN log, then check that service
  info  <service> <message...>        write one INFO log, then check that service
  burst <n> <service> <message...>    write N ERROR logs (same message) rapid-fire, then check
                                       (5+ in 2 min with a never-seen message -> new_error_type fires)
  latency <service> <ms>              write one INFO log with a custom latency_ms, then check
  check [service]                     manually run detection (all services, or just one)
  incidents                           list all incidents
  signature <id>                      show the saved signature text + template counts of an incident
  resolve <id>                        manually close an incident - asks you for the root cause,
                                       then sets status=resolved
  autoclose [minutes]                 check every open incident's condition; close the ones that
                                       have been quiet for at least [minutes] (default 10)
  logs <service> [n]                  show the last n logs for a service (default 10)
  services                            list known services
  fp <message...>                     show what fingerprint a message normalizes/hashes to
  mask <message...>                   show what the signature masking turns a message into
  help                                show this again
  quit / exit                         stop

Services: checkout, payment, auth, inventory (auto-created if you type a new name)

Examples:
  error checkout database error: sorry, too many clients already
  burst 6 auth token signature verification failed: certificate expired
  latency inventory 900
  check
  incidents
  signature 3
  resolve 3
  autoclose
  autoclose 5
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
        print("  (no signature saved for this incident - it was opened before this feature existed)")
        return
    print("  signature_text:")
    for line in signature_text.splitlines():
        print(f"    {line}")
    print(f"  log_templates: {len(log_templates or {})} distinct template(s) stored")


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
                    check_all(conn)

            elif cmd == "incidents":
                cmd_incidents(conn)

            elif cmd == "signature":
                if not rest:
                    print("  usage: signature <id>")
                    continue
                cmd_signature(conn, int(rest[0]))

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