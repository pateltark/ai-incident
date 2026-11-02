# connector_layer.py (ClickHouse Version)

import os
import re
import time
import boto3
import psycopg2
import clickhouse_connect
from dotenv import load_dotenv
from datetime import datetime, timezone
import json

load_dotenv()

SOURCE = os.getenv("LOG_SOURCE", "local").lower()
SERVICE_NAME = os.getenv("SERVICE_NAME", "my-service")
LOCAL_LOG_FILE = os.getenv("LOCAL_LOG_FILE", "app.log")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "3"))

AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
LOG_GROUP = os.getenv("CLOUDWATCH_LOG_GROUP", "")
LOOKBACK_MINUTES = int(os.getenv("LOOKBACK_MINUTES", "5"))

# Initialize ClickHouse Client
ch_client = clickhouse_connect.get_client(
    host=os.getenv("CH_HOST", "localhost"),
    port=int(os.getenv("CH_PORT", "8123")),
    username=os.getenv("CH_USER", "default"),
    password=os.getenv("CH_PASSWORD", ""),
    database=os.getenv("CH_DATABASE", "incident_copilot")
)


def get_db_connection():
    """PostgreSQL connection used ONLY for control-plane lookups (services table)."""
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
    )


def get_service_id(conn):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id FROM services WHERE name = %s",
            (SERVICE_NAME,),
        )
        row = cur.fetchone()

        if row:
            return row[0]

        cur.execute(
            """
            INSERT INTO services (name, environment)
            VALUES (%s, %s)
            RETURNING id
            """,
            (SERVICE_NAME, "production"),
        )
        conn.commit()
        return cur.fetchone()[0]


def get_level(message):
    match = re.search(r"\b(ERROR|WARN(?:ING)?|INFO|DEBUG|CRITICAL)\b",
                      message, re.IGNORECASE)

    if not match:
        return "INFO"

    level = match.group(1).upper()
    return "WARN" if level == "WARNING" else level




def get_service_id_by_name(conn, name):
    """Helper to look up or insert a service dynamically by name."""
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM services WHERE name = %s", (name,))
        row = cur.fetchone()
        if row:
            return row[0]

        cur.execute(
            """
            INSERT INTO services (name, environment)
            VALUES (%s, %s)
            RETURNING id
            """,
            (name, "production"),
        )
        conn.commit()
        return cur.fetchone()[0]


import json

def parse_log_line(message):
    """
    Universal log parser that handles JSON, bracketed formats, key-value logs, 
    and unstructured text streams automatically.
    """
    level = "INFO"
    target_service = SERVICE_NAME
    latency_ms = None
    request_id = ""

    clean_msg = message.strip()

    # --- Strategy 1: JSON-Structured Logs (Lambda Powertools, CloudTrail, Docker JSON) ---
    if clean_msg.startswith("{") and clean_msg.endswith("}"):
        try:
            data = json.loads(clean_msg)
            
            # Extract Level
            raw_level = data.get("level") or data.get("severity") or data.get("logLevel")
            if raw_level:
                level = get_level(str(raw_level))

            # Extract Service Name from common JSON keys
            target_service = (
                data.get("service") or 
                data.get("service_name") or 
                data.get("serviceName") or 
                data.get("function_name") or 
                data.get("functionName")
            )
            if not target_service and "eventSource" in data:
                target_service = data["eventSource"].split(".")[0]

            # Extract Request ID if present
            request_id = str(data.get("request_id") or data.get("requestId") or data.get("function_request_id") or "")
            
            # Extract Latency if present
            if "latency_ms" in data:
                try: latency_ms = float(data["latency_ms"])
                except: pass

            return level, target_service or SERVICE_NAME, message, latency_ms, request_id
        except json.JSONDecodeError:
            pass  # Fall back to text parsing if JSON is malformed

    # --- Strategy 2: Text / Bracketed Logs (CloudWatch, Python/Java apps, ALB, Custom) ---
    
    # 1. Detect Log Level anywhere in the string
    level = get_level(message)

    # 2. Extract Service Name from brackets [service-name], ignoring levels like [ERROR]
    brackets = re.findall(r"\[(.*?)\]", message)
    if brackets:
        valid_candidates = []
        for b in brackets:
            b_upper = b.upper()
            # Skip common non-service bracket items
            if b_upper in ("INFO", "WARN", "WARNING", "ERROR", "DEBUG", "CRITICAL", "FATAL", "MAIN-THREAD") or "THREAD" in b_upper:
                continue
            valid_candidates.append(b)
        
        if valid_candidates:
            target_service = valid_candidates[0] # Takes the first non-level bracket (e.g. [ecs-cluster])

    # 3. If no service found via brackets, look for key-value formats like service=foo or srv=foo
    if target_service == SERVICE_NAME:
        kv_match = re.search(r'\b(?:service|app|service_name)=([a-zA-Z0-9\-_]+)', message, re.IGNORECASE)
        if kv_match:
            target_service = kv_match.group(1)

    # 4. Extract Latency if formatted like latency_ms=123 or latency=45ms
    lat_match = re.search(r'\blatency(?:_ms)?\s*[:=]\s*([0-9.]+)', message, re.IGNORECASE)
    if lat_match:
        try:
            latency_ms = float(lat_match.group(1))
        except ValueError:
            pass

    # 5. Clean up AWS service extension suffixes if present (e.g. s3.amazonaws.com -> s3)
    if target_service and target_service.endswith(".amazonaws.com"):
        target_service = target_service.split(".")[0]

    return level, target_service or SERVICE_NAME, message, latency_ms, request_id


def save_logs(logs):
    if not logs:
        return

    conn = get_db_connection()
    try:
        ch_rows = []
        for message, timestamp in logs:
            log_id = int(time.time_ns() // 1000)
            
            # Pass through the universal parser
            level, target_service, clean_message, latency_ms, request_id = parse_log_line(message)
            
            # Dynamically resolve or create the service ID in Postgres[cite: 3]
            service_id = get_service_id_by_name(conn, target_service)

            ch_rows.append((
                log_id,
                service_id,
                target_service, 
                level,
                clean_message,
                latency_ms,
                request_id,
                timestamp
            ))

        ch_client.insert(
            "application_logs",
            ch_rows,
            column_names=[
                "id", "service_id", "service_name", "level", "message", 
                "latency_ms", "request_id", "timestamp"
            ]
        )
        print(f"Pushed {len(logs)} universally parsed log(s) to ClickHouse.")

    except Exception as e:
        print(f"Error saving logs to ClickHouse: {e}")
        raise
    finally:
        conn.close()



def tail_local_logs(file_handle):
    logs = []
    while True:
        line = file_handle.readline()
        if not line:
            break
        
        message = line.rstrip("\r\n")
        if message:
            timestamp = datetime.now(timezone.utc)
            try:
                candidate = message[:26].strip().replace("Z", "+00:00")
                timestamp = datetime.fromisoformat(candidate)

                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)

            except ValueError:
                pass

            logs.append((message, timestamp))
            
    return logs


def fetch_cloudwatch_logs(last_timestamp_ms):
    if not LOG_GROUP:
        raise ValueError("Set CLOUDWATCH_LOG_GROUP in your .env file.")

    client = boto3.client("logs", region_name=AWS_REGION)

    end_ms = int(time.time() * 1000)
    start_ms = last_timestamp_ms if last_timestamp_ms else (end_ms - LOOKBACK_MINUTES * 60 * 1000)

    paginator = client.get_paginator("filter_log_events")
    logs = []
    max_ts = last_timestamp_ms

    for page in paginator.paginate(
        logGroupName=LOG_GROUP,
        startTime=start_ms,
        endTime=end_ms,
    ):
        for event in page.get("events", []):
            evt_time = event["timestamp"]
            if last_timestamp_ms and evt_time <= last_timestamp_ms:
                continue

            timestamp = datetime.fromtimestamp(
                evt_time / 1000,
                tz=timezone.utc,
            )

            logs.append((event["message"], timestamp))
            if not max_ts or evt_time > max_ts:
                max_ts = evt_time

    return logs, max_ts


if __name__ == "__main__":
    print(f"Starting continuous log ingestion script for source: [{SOURCE}]...")
    
    try:
        if SOURCE == "local":
            if not os.path.exists(LOCAL_LOG_FILE):
                open(LOCAL_LOG_FILE, "a").close()

            with open(LOCAL_LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, os.SEEK_END)
                print(f"Tailing '{LOCAL_LOG_FILE}'. Press Ctrl+C to stop.")

                last_size = f.tell()

                while True:
                    # Check if file was truncated or cleared (e.g. Clear-Content app.log)
                    try:
                        current_size = os.path.getsize(LOCAL_LOG_FILE)
                        if current_size < last_size:
                            print("[Tailer] Log file truncation detected. Resetting pointer to end.")
                            f.seek(0, os.SEEK_END)
                            last_size = f.tell()
                        else:
                            last_size = current_size
                    except OSError:
                        pass

                    new_logs = tail_local_logs(f)
                    if new_logs:
                        save_logs(new_logs)
                    time.sleep(POLL_INTERVAL)

        elif SOURCE == "cloudwatch":
            print(f"Polling CloudWatch log group '{LOG_GROUP}'. Press Ctrl+C to stop.")
            last_ts = int((time.time() - LOOKBACK_MINUTES * 60) * 1000)
            
            while True:
                new_logs, last_ts = fetch_cloudwatch_logs(last_ts)
                if new_logs:
                    save_logs(new_logs)
                time.sleep(POLL_INTERVAL)

        else:
            raise ValueError("LOG_SOURCE must be 'local' or 'cloudwatch'.")

    except KeyboardInterrupt:
        print("\nLog ingestion stopped gracefully by user (Ctrl+C).")   