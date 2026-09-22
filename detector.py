"""
detector.py

The core of V1: runs on a loop, queries `application_logs`, and decides
whether something deserves an incident - with no LLM involved. Every
30-60 seconds it checks each service against three rules:

    1. error_rate      - elevated errors for 2 consecutive minutes
    2. new_error_type   - a fingerprint never seen in 24h, 5+ times in 2 min
    3. latency_spike    - p95 latency 2x baseline for 3 consecutive minutes

When a rule fires, it computes a fingerprint for the representative error
message and tries to open an incident. Deduplication is enforced by the
partial unique index on incidents(service_id, fingerprint) WHERE status =
'open' - a matching open incident already existing means the INSERT is
silently skipped (via ON CONFLICT DO NOTHING), so the same underlying
problem never opens a second incident or sends a second alert.

The rule-evaluation logic is factored into small pure functions
(evaluate_error_rate, evaluate_new_error_type, evaluate_latency_spike)
that take already-fetched data and return a decision - these are unit
tested in test_detector.py with no database needed. The surrounding
fetch_* functions just run the SQL and shape rows into what those
functions expect.

Usage:
    python detector.py
    python detector.py --interval 45
    python detector.py --once            # single pass, useful for testing

Requires the same .env as ingestor.py, plus:
    ALTER TABLE incidents ADD COLUMN rule varchar(30);
(if you haven't already run this - it's a small addition on top of the
earlier incidents ALTER TABLE.)

Stop with Ctrl+C.
"""

import argparse
import statistics
import time
from collections import Counter

import psycopg2

from fingerprint import fingerprint
from ingestor import connect, load_db_config

# ---------------------------------------------------------------------------
# Tunable thresholds - starting values from the plan, tune with real data
# ---------------------------------------------------------------------------

ERROR_RATE_FLOOR = 0.05          # never alert below a flat 5% error rate
ERROR_RATE_BASELINE_MULT = 3.0   # ...or 3x the rolling 30-min median
ERROR_RATE_MIN_BUCKET_COUNT = 5  # ignore buckets with too little traffic to be meaningful
ERROR_RATE_CONSEC_MINUTES = 2

NEW_ERROR_TYPE_MIN_COUNT = 5
NEW_ERROR_TYPE_RECENT_MINUTES = 2
NEW_ERROR_TYPE_HISTORY_HOURS = 24

LATENCY_SPIKE_MULT = 2.0
LATENCY_SPIKE_CONSEC_MINUTES = 3
LATENCY_BASELINE_LOOKBACK_MIN = 30


# ---------------------------------------------------------------------------
# Pure decision logic - no DB, fully unit-testable
# ---------------------------------------------------------------------------

def evaluate_error_rate(buckets):
    """buckets: list of (bucket_ts, total_count, error_count), oldest first,
    covering the trailing ~32 complete minutes. Returns (fired: bool, detail: dict|None)."""
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
    return True, {
        "threshold": threshold,
        "baseline_median": baseline_median,
        "recent_rates": recent_rates,
        "consecutive_minutes": len(recent),
    }


def evaluate_new_error_type(history_fingerprints, recent_rows):
    """history_fingerprints: set of fingerprints seen in the last 24h
    (excluding the recent window). recent_rows: list of (fingerprint, message)
    for ERROR-level logs in the last 2 minutes. Returns a list of dicts, one
    per NEW fingerprint that appeared >= NEW_ERROR_TYPE_MIN_COUNT times."""
    counts = Counter(fp for fp, _ in recent_rows)
    sample_message = {}
    for fp, msg in recent_rows:
        sample_message.setdefault(fp, msg)

    fired = []
    for fp, count in counts.items():
        if fp in history_fingerprints:
            continue
        if count < NEW_ERROR_TYPE_MIN_COUNT:
            continue
        fired.append({"fingerprint": fp, "count": count, "message": sample_message[fp]})
    return fired


def evaluate_latency_spike(buckets):
    """buckets: list of (bucket_ts, p95_ms), oldest first, covering the
    trailing ~33 complete minutes. Returns (fired: bool, detail: dict|None)."""
    usable = [b for b in buckets if b[1] is not None]
    if len(usable) < LATENCY_SPIKE_CONSEC_MINUTES:
        return False, None

    recent = usable[-LATENCY_SPIKE_CONSEC_MINUTES:]
    baseline_pool = usable[:-LATENCY_SPIKE_CONSEC_MINUTES]
    if not baseline_pool:
        return False, None  # not enough history yet to have a baseline

    baseline_median = statistics.median(p95 for _, p95 in baseline_pool)
    if baseline_median <= 0:
        return False, None

    threshold = LATENCY_SPIKE_MULT * baseline_median
    recent_p95s = [p95 for _, p95 in recent]
    fired = all(p95 > threshold for p95 in recent_p95s)

    if not fired:
        return False, None
    return True, {
        "threshold": threshold,
        "baseline_median": baseline_median,
        "recent_p95s": recent_p95s,
        "consecutive_minutes": len(recent),
    }


# ---------------------------------------------------------------------------
# DB access - fetch rows and shape them for the pure functions above
# ---------------------------------------------------------------------------

def fetch_error_rate_buckets(conn, service_id):
    sql = """
        SELECT date_trunc('minute', timestamp) AS bucket,
               count(*) AS total,
               count(*) FILTER (WHERE level = 'ERROR') AS errors
        FROM application_logs
        WHERE service_id = %s
          AND timestamp >= now() - interval '32 minutes'
          AND timestamp < date_trunc('minute', now())
        GROUP BY bucket
        ORDER BY bucket;
    """
    with conn.cursor() as cur:
        cur.execute(sql, (service_id,))
        return cur.fetchall()


def fetch_latency_buckets(conn, service_id):
    sql = """
        SELECT date_trunc('minute', timestamp) AS bucket,
               percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95
        FROM application_logs
        WHERE service_id = %s
          AND timestamp >= now() - interval '33 minutes'
          AND timestamp < date_trunc('minute', now())
          AND latency_ms IS NOT NULL
        GROUP BY bucket
        ORDER BY bucket;
    """
    with conn.cursor() as cur:
        cur.execute(sql, (service_id,))
        return cur.fetchall()


def fetch_error_messages(conn, service_id):
    """Returns (history_fingerprints, recent_rows) for the new-error-type rule."""
    # Parameterized properly (numeric args via %s, multiplied against a
    # literal interval) rather than string-formatting the SQL - avoids
    # mixing Python %-formatting with psycopg2's own %s placeholders.
    sql = """
        SELECT message, timestamp >= now() - (%s * interval '1 minute') AS is_recent
        FROM application_logs
        WHERE service_id = %s
          AND level = 'ERROR'
          AND timestamp >= now() - (%s * interval '1 hour');
    """
    with conn.cursor() as cur:
        cur.execute(sql, (NEW_ERROR_TYPE_RECENT_MINUTES, service_id, NEW_ERROR_TYPE_HISTORY_HOURS))
        rows = cur.fetchall()

    history_fingerprints = set()
    recent_rows = []
    for message, is_recent in rows:
        fp = fingerprint(message)
        if is_recent:
            recent_rows.append((fp, message))
        else:
            history_fingerprints.add(fp)
    return history_fingerprints, recent_rows


def fetch_services(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT id, name FROM services;")
        return cur.fetchall()


# ---------------------------------------------------------------------------
# Opening incidents, with dedup via the partial unique index
# ---------------------------------------------------------------------------

OPEN_INCIDENT_SQL = """
    INSERT INTO incidents (service_id, rule, fingerprint, title, description, severity, status, started_at)
    VALUES (%s, %s, %s, %s, %s, %s, 'open', now())
    ON CONFLICT (service_id, fingerprint) WHERE status = 'open' DO NOTHING
    RETURNING id;
"""

SEVERITY_BY_RULE = {
    "error_rate": "high",
    "new_error_type": "medium",
    "latency_spike": "medium",
}


def try_open_incident(conn, service_id, service_name, rule, fp, title, description):
    severity = SEVERITY_BY_RULE.get(rule, "medium")
    with conn.cursor() as cur:
        cur.execute(OPEN_INCIDENT_SQL, (service_id, rule, fp, title, description, severity))
        row = cur.fetchone()
    conn.commit()

    if row is None:
        # an incident with this service+fingerprint is already open - no duplicate alert
        return None

    incident_id = row[0]
    print(f"[ALERT] service={service_name} rule={rule} fingerprint={fp} "
          f"severity={severity} incident_id={incident_id}")
    print(f"        {description}")
    return incident_id


# ---------------------------------------------------------------------------
# One full check pass across all services
# ---------------------------------------------------------------------------

def check_service(conn, service_id, service_name):
    # --- error rate ---
    try:
        buckets = fetch_error_rate_buckets(conn, service_id)
        fired, detail = evaluate_error_rate(buckets)
        if fired:
            rates_str = ", ".join(f"{r:.1%}" for r in detail["recent_rates"])
            try_open_incident(
                conn, service_id, service_name, "error_rate",
                fingerprint(f"elevated_error_rate:{service_name}"),
                f"Elevated error rate in {service_name}",
                f"Error rate {rates_str} over the last {detail['consecutive_minutes']} minute(s), "
                f"threshold {detail['threshold']:.1%} (baseline median {detail['baseline_median']:.1%}).",
            )
    except Exception as e:
        print(f"[detector] error_rate check failed for {service_name}: {e}")

    # --- new error type ---
    try:
        history_fps, recent_rows = fetch_error_messages(conn, service_id)
        for hit in evaluate_new_error_type(history_fps, recent_rows):
            try_open_incident(
                conn, service_id, service_name, "new_error_type", hit["fingerprint"],
                f"New error type in {service_name}",
                f'"{hit["message"]}" occurred {hit["count"]} times in the last '
                f"{NEW_ERROR_TYPE_RECENT_MINUTES} minutes, not seen in the prior "
                f"{NEW_ERROR_TYPE_HISTORY_HOURS}h.",
            )
    except Exception as e:
        print(f"[detector] new_error_type check failed for {service_name}: {e}")

    # --- latency spike ---
    try:
        buckets = fetch_latency_buckets(conn, service_id)
        fired, detail = evaluate_latency_spike(buckets)
        if fired:
            p95_str = ", ".join(f"{p:.0f}ms" for p in detail["recent_p95s"])
            try_open_incident(
                conn, service_id, service_name, "latency_spike",
                fingerprint(f"latency_spike:{service_name}"),
                f"Latency spike in {service_name}",
                f"p95 latency {p95_str} over the last {detail['consecutive_minutes']} minute(s), "
                f"more than {LATENCY_SPIKE_MULT}x baseline ({detail['baseline_median']:.0f}ms).",
            )
    except Exception as e:
        print(f"[detector] latency_spike check failed for {service_name}: {e}")


def run_once(conn):
    services = fetch_services(conn)
    if not services:
        print("[detector] no rows in `services` table yet - nothing to check.")
        return
    for service_id, service_name in services:
        check_service(conn, service_id, service_name)


def run(interval, once):
    config = load_db_config()
    conn = connect(config)
    print(f"[detector] checking every {interval}s. Ctrl+C to stop." if not once else "[detector] single pass.")
    try:
        if once:
            run_once(conn)
            return
        while True:
            run_once(conn)
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    finally:
        conn.close()
        if not once:
            print("\n[detector] stopped.")


def main():
    parser = argparse.ArgumentParser(description="Rule-based incident detector (no LLM).")
    parser.add_argument("--interval", type=float, default=45.0,
                         help="seconds between checks (default: 45)")
    parser.add_argument("--once", action="store_true",
                         help="run a single check pass and exit (useful for testing/cron)")
    args = parser.parse_args()
    run(args.interval, args.once)


if __name__ == "__main__":
    main()