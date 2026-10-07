"""
create_tables.py

Rebuilds the ai-incident database structure from scratch.
Safe to run any number of times: everything uses IF NOT EXISTS, so running it
on an existing database changes nothing (and adds any column that is missing).

Run:
    python create_tables.py

Uses the same .env as the rest of the project:
    DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD

What it does, in order:
    1. creates the database itself if it does not exist
    2. enables the pgvector extension (needed for incidents.embedding)
    3. creates the tables: services, application_logs, incidents
    4. adds the newer incident columns if they are missing
    5. creates the indexes
    6. inserts the four default services

NOT included: the `events` table. Its columns were never shared, so it is
left out on purpose rather than guessed. See the note at the bottom of SCHEMA_SQL.

Requirements:
    - pgvector must be installed on the Postgres server
      (CREATE EXTENSION vector fails without it)
    - the DB user must be allowed to create a database and an extension
      (the default `postgres` user can)
"""

import os
import sys

import psycopg2
from psycopg2 import sql
from dotenv import load_dotenv

load_dotenv()

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "ai_incident")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD")

# Must match the model in console.py (all-MiniLM-L6-v2 gives 384 numbers).
# If you switch the embedding model, change this number too.
EMBEDDING_DIMENSIONS = 384


SCHEMA_SQL = f"""
-- ---------------------------------------------------------------
-- extension
-- ---------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS vector;


-- ---------------------------------------------------------------
-- services
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS services (
    id           serial       PRIMARY KEY,
    name         varchar(100) NOT NULL UNIQUE,
    environment  varchar(50)  NOT NULL DEFAULT 'production',
    created_at   timestamp    NOT NULL DEFAULT now()
);


-- ---------------------------------------------------------------
-- application_logs
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS application_logs (
    id          serial        PRIMARY KEY,
    service_id  integer       NOT NULL REFERENCES services(id),
    level       varchar(20)   NOT NULL,
    message     text          NOT NULL,
    latency_ms  numeric(12,2),
    request_id  varchar(64),
    timestamp   timestamp     NOT NULL DEFAULT now()
);


-- ---------------------------------------------------------------
-- incidents
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id                     serial        PRIMARY KEY,
    service_id             integer       NOT NULL REFERENCES services(id),
    title                  varchar(255)  NOT NULL,
    description            text,
    severity               varchar(20)   NOT NULL DEFAULT 'medium',
    status                 varchar(20)   NOT NULL DEFAULT 'open',
    started_at             timestamp     NOT NULL DEFAULT now(),
    resolved_at            timestamp,
    created_at             timestamp     NOT NULL DEFAULT now(),
    fingerprint            varchar(64),
    root_cause             text,
    resolution             text,
    resolution_confidence  varchar(20),
    embedding              vector({EMBEDDING_DIMENSIONS}),
    rule                   varchar(30)
);

-- columns added later (also makes this script upgrade an older incidents table)
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS signature_text text;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS log_templates  jsonb;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS error_type     varchar(100);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS evidence       text;


-- ---------------------------------------------------------------
-- indexes
-- ---------------------------------------------------------------

-- Only ONE open incident per (service, fingerprint).
-- console.py relies on this: INSERT ... ON CONFLICT (service_id, fingerprint) WHERE status = 'open'
CREATE UNIQUE INDEX IF NOT EXISTS uq_incidents_open_service_fingerprint
    ON incidents (service_id, fingerprint)
    WHERE status = 'open';

CREATE INDEX IF NOT EXISTS idx_incidents_status_started
    ON incidents (status, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_logs_service_timestamp
    ON application_logs (service_id, timestamp);

CREATE INDEX IF NOT EXISTS idx_logs_request_id
    ON application_logs (request_id);

-- Optional: speeds up similarity search once you have thousands of incidents.
-- Not needed for a small project, so it is left off.
-- CREATE INDEX IF NOT EXISTS idx_incidents_embedding
--     ON incidents USING hnsw (embedding vector_cosine_ops);


-- ---------------------------------------------------------------
-- default services (same list as KNOWN_SERVICES in console.py)
-- ---------------------------------------------------------------
INSERT INTO services (name, environment) VALUES
    ('checkout',  'production'),
    ('payment',   'production'),
    ('auth',      'production'),
    ('inventory', 'production')
ON CONFLICT (name) DO NOTHING;


-- ---------------------------------------------------------------
-- NOTE: `events` table is not created here. Its columns were not shared.
-- Add its CREATE TABLE statement here once you have it
-- (run \\d events in psql, or send the column list to Claude).
-- ---------------------------------------------------------------
"""


def create_database_if_missing():
    """Connects to the built-in 'postgres' database and creates DB_NAME if needed."""
    conn = psycopg2.connect(
        host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, dbname="postgres"
    )
    conn.autocommit = True  # CREATE DATABASE cannot run inside a transaction
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname = %s;", (DB_NAME,))
            if cur.fetchone():
                print(f"[db] database '{DB_NAME}' already exists")
            else:
                cur.execute(sql.SQL("CREATE DATABASE {};").format(sql.Identifier(DB_NAME)))
                print(f"[db] created database '{DB_NAME}'")
    finally:
        conn.close()


def create_schema():
    conn = psycopg2.connect(
        host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, dbname=DB_NAME
    )
    try:
        with conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
        conn.commit()
        print("[db] tables, columns and indexes are in place")

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT table_name, count(*) AS columns
                FROM information_schema.columns
                WHERE table_schema = 'public'
                GROUP BY table_name ORDER BY table_name;
                """
            )
            print("\n  table                columns")
            for table_name, n in cur.fetchall():
                print(f"  {table_name:<20} {n}")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def main():
    try:
        create_database_if_missing()
        create_schema()
    except psycopg2.errors.FeatureNotSupported as e:
        sys.exit(f"\n[db] pgvector is not available on this Postgres server: {e}")
    except psycopg2.Error as e:
        sys.exit(f"\n[db] failed: {e}")
    print("\n[db] done.")


if __name__ == "__main__":
    main()