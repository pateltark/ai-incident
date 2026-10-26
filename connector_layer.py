
# ingestion.py

import os
import re
import time
import boto3
import psycopg2
from dotenv import load_dotenv
from datetime import datetime, timezone

load_dotenv()

SOURCE = os.getenv("LOG_SOURCE", "local").lower()
SERVICE_NAME = os.getenv("SERVICE_NAME", "my-service")
LOCAL_LOG_FILE = os.getenv("LOCAL_LOG_FILE", "app.log")

AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
LOG_GROUP = os.getenv("CLOUDWATCH_LOG_GROUP", "")
LOOKBACK_MINUTES = int(os.getenv("LOOKBACK_MINUTES", "60"))


def get_db_connection():
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
        print("No logs found.")
        return

    conn = get_db_connection()

    try:
        service_id = get_service_id(conn)

        with conn.cursor() as cur:
            for message, timestamp in logs:
                cur.execute(
                    """
                    INSERT INTO application_logs
                        (service_id, level, message, timestamp)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        service_id,
                        get_level(message),
                        message,
                        timestamp,
                    ),
                )

        conn.commit()
        print(f"Saved {len(logs)} logs to application_logs.")

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def fetch_local_logs():
    logs = []

    with open(LOCAL_LOG_FILE, "r", encoding="utf-8", errors="replace") as file:
        for line in file:
            message = line.rstrip("\r\n")

            if message:
                # Use current time if the log's timestamp cannot be parsed.
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


def fetch_cloudwatch_logs():
    if not LOG_GROUP:
        raise ValueError("Set CLOUDWATCH_LOG_GROUP in your .env file.")

    client = boto3.client("logs", region_name=AWS_REGION)

    end_ms = int(time.time() * 1000)
    start_ms = end_ms - LOOKBACK_MINUTES * 60 * 1000

    paginator = client.get_paginator("filter_log_events")

    logs = []

    for page in paginator.paginate(
        logGroupName=LOG_GROUP,
        startTime=start_ms,
        endTime=end_ms,
    ):
        for event in page.get("events", []):
            timestamp = datetime.fromtimestamp(
                event["timestamp"] / 1000,
                tz=timezone.utc,
            )

            # Save the original CloudWatch message.
            logs.append((event["message"], timestamp))

    return logs


if __name__ == "__main__":
    if SOURCE == "local":
        raw_logs = fetch_local_logs()

    elif SOURCE == "cloudwatch":
        raw_logs = fetch_cloudwatch_logs()

    else:
        raise ValueError("LOG_SOURCE must be 'local' or 'cloudwatch'.")

    save_logs(raw_logs)
