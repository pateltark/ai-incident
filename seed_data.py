"""
setup_db.py

Run this once (or any time you want to recreate the schema from scratch)
to create every table console.py depends on: services, application_logs,
incidents - plus the indexes and constraints that console.py's queries
actually rely on (the partial unique index that makes duplicate-incident
prevention work, and the confidence check constraint).

Safe to re-run: everything uses IF NOT EXISTS, so running this against a
database that already has these tables just does nothing extra.

Setup:
    pip install psycopg2-binary python-dotenv
    Same .env as console.py: DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
    (or a single DATABASE_URL)

Run:
    python setup_db.py
"""

import os
import psycopg2
from dotenv import load_dotenv

SCHEMA_SQL = """
-- Needed for the incidents.embedding column (used later once you wire up
-- retrieval - harmless to have now even if nothing writes to it yet).
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS services (
    id           SERIAL PRIMARY KEY,
    name         VARCHAR(100) NOT NULL UNIQUE,
    environment  VARCHAR(50)  NOT NULL DEFAULT 'production'
);

CREATE TABLE IF NOT EXISTS application_logs (
    id          SERIAL PRIMARY KEY,
    service_id  INTEGER NOT NULL REFERENCES services(id),
    level       VARCHAR(20) NOT NULL,
    message     TEXT NOT NULL,
    latency_ms  REAL,
    request_id  VARCHAR(64),
    timestamp   TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT now()
);

-- console.py's bucket queries filter by service_id + timestamp range on
-- every check - this index is what keeps that fast as the table grows.
CREATE INDEX IF NOT EXISTS idx_application_logs_service_timestamp
    ON application_logs (service_id, timestamp);

CREATE TABLE IF NOT EXISTS incidents (
    id                      SERIAL PRIMARY KEY,
    service_id              INTEGER NOT NULL REFERENCES services(id),
    rule                    VARCHAR(30),
    fingerprint             VARCHAR(64),
    title                   VARCHAR(255) NOT NULL,
    description             TEXT,
    severity                VARCHAR(20) NOT NULL DEFAULT 'medium',
    status                  VARCHAR(20) NOT NULL DEFAULT 'open',
    started_at              TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT now(),
    resolved_at             TIMESTAMP WITHOUT TIME ZONE,
    created_at              TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT now(),
    root_cause              TEXT,
    resolution              TEXT,
    resolution_confidence   VARCHAR(20),
    embedding               vector(1536),

    CONSTRAINT incidents_resolution_confidence_check
        CHECK (resolution_confidence IS NULL
               OR resolution_confidence IN ('confirmed', 'inferred', 'unknown'))
);

-- This is what makes "ON CONFLICT (service_id, fingerprint) WHERE status =
-- 'open' DO NOTHING" in console.py actually work - a normal unique
-- constraint can't be scoped to only open incidents, a partial unique
-- index can. Without this exact index, try_open_incident() will error.
CREATE UNIQUE INDEX IF NOT EXISTS incidents_open_service_fingerprint_idx
    ON incidents (service_id, fingerprint)
    WHERE status = 'open';

CREATE INDEX IF NOT EXISTS idx_incidents_status
    ON incidents (status);
"""


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
        return psycopg2.connect(cfg["dsn"])
    return psycopg2.connect(
        host=cfg["host"], port=cfg["port"], dbname=cfg["dbname"],
        user=cfg["user"], password=cfg["password"],
    )


def main():
    print("[setup_db] connecting...")
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
        conn.commit()
        print("[setup_db] done - services, application_logs, incidents are ready.")
    except Exception as e:
        conn.rollback()
        print(f"[setup_db] failed: {e}")
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()