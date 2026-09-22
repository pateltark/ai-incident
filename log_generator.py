"""
log_generator.py

Simulates a real multi-service application deployed on AWS: each service
(checkout, payment, auth, inventory) runs as a container (e.g. ECS/Fargate)
that logs structured JSON to stdout - which is exactly what the `awslogs`
driver ships to CloudWatch Logs as-is, one log event per line. Each service
also talks to its own Postgres database (RDS), which writes its own server
log in Postgres's native format.

This script writes BOTH, to disk, so they look like what you'd actually
pull down from CloudWatch and from an RDS Postgres log:

    logs/cloudwatch/<service>-<date>.log   - one JSON object per line (app logs)
    logs/postgres/postgresql-<date>.log    - one shared Postgres server log

Nothing here touches your `application_logs` table. A separate ingestor
(built next) will tail these files and parse them into structured rows -
same as a real log pipeline (Agent/Fluentd/Vector) would.

--------------------------------------------------------------------------
1) CloudWatch-style app log line (what ECS ships to CloudWatch as-is):

{"timestamp": "2026-09-22T10:41:03.221Z", "level": "INFO", "service": "checkout",
 "environment": "production", "message": "order created successfully",
 "request_id": "8f3a1c2d9b3e", "http": {"method": "POST", "path": "/api/checkout",
 "status_code": 200}, "latency_ms": 142, "aws": {"region": "us-east-1",
 "log_group": "/ecs/checkout-service", "log_stream": "ecs/checkout/a1b2c3d4",
 "container_id": "a1b2c3d4e5f6"}}

2) Postgres/RDS server log line (default RDS log_line_prefix '%t:%r:%u@%d:[%p]:'):

2026-09-22 10:41:03 UTC:10.0.1.15(52341):svc_checkout@checkout_db:[14021]:LOG:  duration: 182.331 ms  statement: SELECT * FROM orders WHERE id = $1
--------------------------------------------------------------------------

Usage:
    python log_generator.py
    python log_generator.py --rate 8 --out logs
    python log_generator.py --error-rate 0.02 --slow-query-ms 50

Stop with Ctrl+C. Rotates both log files at local midnight.
"""

import argparse
import datetime
import ipaddress
import json
import os
import random
import time
import uuid

REGION = "us-east-1"

SERVICES = {
    "checkout": {
        "db_name": "checkout_db",
        "db_user": "svc_checkout",
        "endpoints": [
            {
                "method": "POST", "path": "/api/checkout", "weight": 60,
                "latency": (120, 0.35), "db_latency_frac": 0.55,
                "success_msg": "order created successfully",
                "sql": "INSERT INTO orders (id, user_id, total_cents, status) VALUES ($1, $2, $3, $4)",
                "app_errors": [
                    ("invalid payment method for order", 402),
                    ("inventory check failed for sku", 409),
                ],
                "db_errors": [
                    ("ERROR", 'duplicate key value violates unique constraint "orders_pkey"'),
                    ("ERROR", "deadlock detected"),
                ],
            },
            {
                "method": "GET", "path": "/api/cart", "weight": 30,
                "latency": (45, 0.30), "db_latency_frac": 0.4,
                "success_msg": "cart retrieved",
                "sql": "SELECT * FROM cart_items WHERE cart_id = $1",
                "app_errors": [("cart session expired", 400)],
                "db_errors": [],
            },
            {
                "method": "POST", "path": "/api/cart/add", "weight": 10,
                "latency": (60, 0.30), "db_latency_frac": 0.5,
                "success_msg": "item added to cart",
                "sql": "UPDATE cart_items SET quantity = quantity + $1 WHERE cart_id = $2 AND sku = $3",
                "app_errors": [],
                "db_errors": [("ERROR", "could not serialize access due to concurrent update")],
            },
        ],
    },
    "payment": {
        "db_name": "payment_db",
        "db_user": "svc_payment",
        "endpoints": [
            {
                "method": "POST", "path": "/api/payment/charge", "weight": 50,
                "latency": (180, 0.40), "db_latency_frac": 0.35,
                "success_msg": "charge succeeded",
                "sql": "INSERT INTO payments (id, order_id, amount_cents, status) VALUES ($1, $2, $3, $4)",
                "app_errors": [
                    ("card declined by issuer", 402),
                    ("gateway returned malformed response", 502),
                ],
                "db_errors": [("ERROR", 'duplicate key value violates unique constraint "payments_pkey"')],
            },
            {
                "method": "GET", "path": "/api/payment/status", "weight": 40,
                "latency": (35, 0.25), "db_latency_frac": 0.5,
                "success_msg": "payment status retrieved",
                "sql": "SELECT status FROM payments WHERE order_id = $1",
                "app_errors": [],
                "db_errors": [],
            },
            {
                "method": "POST", "path": "/api/payment/refund", "weight": 10,
                "latency": (150, 0.35), "db_latency_frac": 0.4,
                "success_msg": "refund processed",
                "sql": "UPDATE payments SET status = 'refunded' WHERE id = $1",
                "app_errors": [("duplicate charge detected", 409)],
                "db_errors": [],
            },
        ],
    },
    "auth": {
        "db_name": "auth_db",
        "db_user": "svc_auth",
        "endpoints": [
            {
                "method": "POST", "path": "/api/login", "weight": 55,
                "latency": (90, 0.30), "db_latency_frac": 0.3,
                "success_msg": "login succeeded",
                "sql": "SELECT id, password_hash FROM users WHERE email = $1",
                "app_errors": [
                    ("invalid credentials", 401),
                    ("rate limit exceeded for ip", 429),
                ],
                "db_errors": [],
            },
            {
                "method": "POST", "path": "/api/token/refresh", "weight": 35,
                "latency": (40, 0.25), "db_latency_frac": 0.25,
                "success_msg": "token refreshed",
                "sql": "UPDATE sessions SET expires_at = $1 WHERE refresh_token = $2",
                "app_errors": [("token expired", 401)],
                "db_errors": [],
            },
            {
                "method": "POST", "path": "/api/logout", "weight": 10,
                "latency": (20, 0.20), "db_latency_frac": 0.3,
                "success_msg": "user logged out",
                "sql": "DELETE FROM sessions WHERE id = $1",
                "app_errors": [],
                "db_errors": [],
            },
        ],
    },
    "inventory": {
        "db_name": "inventory_db",
        "db_user": "svc_inventory",
        "endpoints": [
            {
                "method": "GET", "path": "/api/inventory/check", "weight": 65,
                "latency": (55, 0.30), "db_latency_frac": 0.6,
                "success_msg": "stock available",
                "sql": "SELECT quantity FROM inventory WHERE sku = $1",
                "app_errors": [("sku not found", 404)],
                "db_errors": [],
            },
            {
                "method": "POST", "path": "/api/inventory/reserve", "weight": 25,
                "latency": (80, 0.35), "db_latency_frac": 0.65,
                "success_msg": "stock reserved",
                "sql": "UPDATE inventory SET quantity = quantity - $1 WHERE sku = $2 AND quantity >= $1",
                "app_errors": [("stock reservation conflict", 409)],
                "db_errors": [("ERROR", "deadlock detected")],
            },
            {
                "method": "POST", "path": "/api/inventory/release", "weight": 10,
                "latency": (40, 0.25), "db_latency_frac": 0.5,
                "success_msg": "reservation released",
                "sql": "UPDATE inventory SET quantity = quantity + $1 WHERE sku = $2",
                "app_errors": [],
                "db_errors": [],
            },
        ],
    },
}

BASELINE_ERROR_RATE = 0.012   # fraction of requests that fail naturally
SLOW_QUERY_MS = 40            # Postgres only logs queries slower than this,
                               # matching a real log_min_duration_statement
                               # setting - errors are always logged regardless.


def now_dt():
    return datetime.datetime.now(datetime.timezone.utc)


def iso_ms(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def pg_ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S") + " UTC"


def random_client_ip():
    return str(ipaddress.IPv4Address(random.randint(
        int(ipaddress.IPv4Address("10.0.0.0")),
        int(ipaddress.IPv4Address("10.0.5.255")))))


def sample_latency(mean_ms, sigma):
    latency = random.lognormvariate(mu=0, sigma=sigma) * mean_ms
    if random.random() < 0.01:
        latency *= random.uniform(2.5, 5.0)
    return max(1, round(latency, 2))


def pick_endpoint(service_cfg):
    endpoints = service_cfg["endpoints"]
    weights = [e["weight"] for e in endpoints]
    return random.choices(endpoints, weights=weights, k=1)[0]


class RotatingWriter:
    """Appends lines to a file, rotating to a new one at local midnight."""

    def __init__(self, out_dir, filename_fn):
        self.out_dir = out_dir
        self.filename_fn = filename_fn
        os.makedirs(out_dir, exist_ok=True)
        self.path = None
        self.f = None
        self._open_current()

    def _open_current(self):
        new_path = os.path.join(self.out_dir, self.filename_fn())
        if new_path != self.path:
            if self.f:
                self.f.close()
            self.path = new_path
            self.f = open(self.path, "a", encoding="utf-8")

    def write(self, line):
        self._open_current()
        self.f.write(line + "\n")

    def flush(self):
        if self.f:
            self.f.flush()
            os.fsync(self.f.fileno())

    def close(self):
        if self.f:
            self.f.flush()
            self.f.close()


def build_app_log(dt, service, level, message, request_id, method, path, status_code, latency_ms):
    return json.dumps({
        "timestamp": iso_ms(dt),
        "level": level,
        "service": service,
        "environment": "production",
        "message": message,
        "request_id": request_id,
        "http": {"method": method, "path": path, "status_code": status_code},
        "latency_ms": latency_ms,
        "aws": {
            "region": REGION,
            "log_group": f"/ecs/{service}-service",
            "log_stream": f"ecs/{service}/{request_id[:8]}",
            "container_id": uuid.uuid4().hex[:12],
        },
    }, separators=(",", ":"))


def build_pg_log(dt, db_name, db_user, pid, client_ip, level, message):
    return f"{pg_ts(dt)}:{client_ip}({random.randint(30000, 65000)}):{db_user}@{db_name}:[{pid}]:{level}:  {message}"


def emit_request(service, cfg, app_writer, pg_writer, error_rate, slow_query_ms):
    ep = pick_endpoint(cfg)
    dt = now_dt()
    request_id = uuid.uuid4().hex[:16]
    pid = random.randint(10000, 32000)
    client_ip = random_client_ip()

    total_latency = sample_latency(*ep["latency"])
    db_latency = round(total_latency * ep["db_latency_frac"] * random.uniform(0.7, 1.3), 3)

    roll = random.random()

    # DB-caused error: a Postgres ERROR surfaces, app returns 5xx
    if ep["db_errors"] and roll < error_rate * 0.4:
        pg_level, pg_msg = random.choice(ep["db_errors"])
        pg_writer.write(build_pg_log(dt, cfg["db_name"], cfg["db_user"], pid, client_ip, pg_level, pg_msg))
        pg_writer.write(build_pg_log(dt, cfg["db_name"], cfg["db_user"], pid, client_ip, "STATEMENT", ep["sql"]))
        app_writer.write(build_app_log(
            dt, service, "ERROR", f"database error: {pg_msg}", request_id,
            ep["method"], ep["path"], 500, total_latency,
        ))
        return

    # App-level error (validation, business logic) - DB call still happens fine
    if ep["app_errors"] and roll < error_rate:
        if random.random() < 0.6 and db_latency >= slow_query_ms:
            pg_writer.write(build_pg_log(
                dt, cfg["db_name"], cfg["db_user"], pid, client_ip, "LOG",
                f"duration: {db_latency:.3f} ms  statement: {ep['sql']}",
            ))
        msg, status = random.choice(ep["app_errors"])
        app_writer.write(build_app_log(
            dt, service, "ERROR", msg, request_id,
            ep["method"], ep["path"], status, total_latency,
        ))
        return

    # Normal successful request
    if db_latency >= slow_query_ms:
        pg_writer.write(build_pg_log(
            dt, cfg["db_name"], cfg["db_user"], pid, client_ip, "LOG",
            f"duration: {db_latency:.3f} ms  statement: {ep['sql']}",
        ))
    app_writer.write(build_app_log(
        dt, service, "INFO", ep["success_msg"], request_id,
        ep["method"], ep["path"], 200, total_latency,
    ))


def run(rate_per_sec, out_dir, error_rate, slow_query_ms, seed):
    if seed is not None:
        random.seed(seed)

    cw_dir = os.path.join(out_dir, "cloudwatch")
    pg_dir = os.path.join(out_dir, "postgres")
    os.makedirs(cw_dir, exist_ok=True)
    os.makedirs(pg_dir, exist_ok=True)

    app_writers = {
        svc: RotatingWriter(cw_dir, lambda s=svc: f"{s}-{datetime.date.today().isoformat()}.log")
        for svc in SERVICES
    }
    pg_writer = RotatingWriter(pg_dir, lambda: f"postgresql-{datetime.date.today().isoformat()}.log")

    print(f"[log_generator] CloudWatch-style app logs -> {cw_dir}/<service>-<date>.log")
    print(f"[log_generator] Postgres-style DB logs      -> {pg_dir}/postgresql-<date>.log")
    print(f"[log_generator] ~{rate_per_sec} requests/sec, baseline error rate {error_rate:.1%}, "
          f"DB queries under {slow_query_ms}ms are not logged (matches log_min_duration_statement). "
          f"Ctrl+C to stop.")

    interval = 1.0 / rate_per_sec
    tick = 0
    try:
        while True:
            service = random.choice(list(SERVICES.keys()))
            cfg = SERVICES[service]
            emit_request(service, cfg, app_writers[service], pg_writer, error_rate, slow_query_ms)

            tick += 1
            if tick >= 20:
                for w in app_writers.values():
                    w.flush()
                pg_writer.flush()
                tick = 0

            time.sleep(interval * random.uniform(0.5, 1.5))
    except KeyboardInterrupt:
        pass
    finally:
        for w in app_writers.values():
            w.close()
        pg_writer.close()
        print("\n[log_generator] stopped.")


def main():
    parser = argparse.ArgumentParser(description="Generate AWS CloudWatch-style app logs and Postgres-style DB logs.")
    parser.add_argument("--rate", type=float, default=5.0,
                         help="approximate total requests per second across all services (default: 5)")
    parser.add_argument("--out", type=str, default="logs",
                         help="output directory (default: ./logs)")
    parser.add_argument("--error-rate", type=float, default=BASELINE_ERROR_RATE,
                         help="baseline fraction of requests that fail naturally (default: 0.012)")
    parser.add_argument("--slow-query-ms", type=float, default=SLOW_QUERY_MS,
                         help="Postgres only logs queries slower than this, like log_min_duration_statement (default: 40)")
    parser.add_argument("--seed", type=int, default=None,
                         help="random seed, for reproducible demo runs")
    args = parser.parse_args()
    run(args.rate, args.out, args.error_rate, args.slow_query_ms, args.seed)


if __name__ == "__main__":
    main()