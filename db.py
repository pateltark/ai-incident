import psycopg2.pool
import os
from dotenv import load_dotenv

load_dotenv()


connection_pool = psycopg2.pool.ThreadedConnectionPool(
    minconn=1,
    maxconn=int(os.getenv("DB_POOL_MAX", "10")),
    database=os.getenv("DB_NAME", "ai_incident"),
    user=os.getenv("DB_USER", "postgres"),
    password=os.getenv("DB_PASSWORD"),
    host=os.getenv("DB_HOST", "localhost"),
    port=int(os.getenv("DB_PORT", "5432")),
)


def get_db():
    conn = connection_pool.getconn()
    conn.autocommit = True
    cursor = conn.cursor()
    try:
        yield cursor
    finally:
        cursor.close()
        connection_pool.putconn(conn)
