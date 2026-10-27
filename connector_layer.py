# connector_layer.py (ClickHouse Version)

import os
import re
import time
import boto3
import psycopg2
import clickhouse_connect
from dotenv import load_dotenv
from datetime import datetime, timezone

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


def save_logs(logs):
    if not logs:
        return

    # 1. Get service_id from PostgreSQL (Control Plane)
    conn = get_db_connection()
    try:
        service_id = get_service_id(conn)
    finally:
        conn.close()

    try:
        # 2. Prepare batch rows matching your exact ClickHouse table schema:
        # (id, service_id, level, message, latency_ms, request_id, timestamp)
        ch_rows = []
        for message, timestamp in logs:
            log_id = int(time.time_ns() // 1000)  # Unique pseudo-ID
            level = get_level(message)
            latency_ms = None  # Default null if not parsed
            request_id = ""    # Default empty string if not parsed
            
            ch_rows.append((
                log_id,
                service_id,
                level,
                message,
                latency_ms,
                request_id,
                timestamp
            ))

        # 3. High-performance batch insert into ClickHouse (Log Engine)
        ch_client.insert(
            "application_logs",
            ch_rows,
            column_names=[
                "id", "service_id", "level", "message", 
                "latency_ms", "request_id", "timestamp"
            ]
        )
        print(f"Pushed {len(logs)} new log(s) to ClickHouse application_logs.")

    except Exception as e:
        print(f"Error saving logs to ClickHouse: {e}")
        raise


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

                while True:
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