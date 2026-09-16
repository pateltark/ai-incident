
import psycopg2
import random
import uuid

from datetime import datetime, timedelta


# ==========================================
# DATABASE CONFIGURATION
# ==========================================

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "database": "ai_incident",
    "user": "postgres",
    "password": "Login@100"
}


# ==========================================
# FAKE SERVICES
# ==========================================

SERVICES = [
    ("rag-api", "production"),
    ("vector-db", "production"),
    ("llm-service", "production"),
    ("payment-service", "production"),
    ("auth-service", "production"),
]


# ==========================================
# LOG MESSAGE TEMPLATES
# ==========================================

LOG_TEMPLATES = {

    "rag-api": {
        "INFO": [
            "RAG request completed successfully",
            "User query processed",
            "Response generated successfully",
        ],
        "WARNING": [
            "RAG request latency above threshold",
            "Slow document retrieval detected",
        ],
        "ERROR": [
            "Vector database timeout",
            "Failed to retrieve documents",
            "RAG pipeline request failed",
        ],
    },

    "vector-db": {
        "INFO": [
            "Vector search completed",
            "Embedding query processed",
        ],
        "WARNING": [
            "Vector search latency above threshold",
            "High vector database CPU usage",
        ],
        "ERROR": [
            "Vector database connection timeout",
            "Vector search failed",
        ],
    },

    "llm-service": {
        "INFO": [
            "LLM response generated",
            "LLM request completed",
        ],
        "WARNING": [
            "LLM response latency high",
            "Token usage above expected limit",
        ],
        "ERROR": [
            "LLM request timeout",
            "LLM provider API error",
            "Failed to generate response",
        ],
    },

    "payment-service": {
        "INFO": [
            "Payment completed successfully",
            "Payment request processed",
        ],
        "WARNING": [
            "Payment gateway response slow",
        ],
        "ERROR": [
            "Payment gateway timeout",
            "Payment processing failed",
        ],
    },

    "auth-service": {
        "INFO": [
            "User authenticated successfully",
            "Token validated",
        ],
        "WARNING": [
            "Authentication latency above threshold",
        ],
        "ERROR": [
            "Authentication service unavailable",
            "Token validation failed",
        ],
    },
}


# ==========================================
# INCIDENT TEMPLATES
# ==========================================

INCIDENT_TEMPLATES = [
    (
        "RAG chatbot latency increased",
        "High latency observed in RAG API requests.",
        "high",
        "open",
        "rag-api"
    ),

    (
        "Vector database timeout spike",
        "Vector search requests are timing out.",
        "critical",
        "investigating",
        "vector-db"
    ),

    (
        "LLM response latency increased",
        "LLM responses are taking longer than usual.",
        "high",
        "open",
        "llm-service"
    ),

    (
        "Payment gateway failures",
        "Multiple payment requests failed.",
        "critical",
        "investigating",
        "payment-service"
    ),

    (
        "Authentication failures",
        "Users are experiencing authentication failures.",
        "medium",
        "resolved",
        "auth-service"
    ),

    (
        "RAG document retrieval failures",
        "Some RAG requests failed during document retrieval.",
        "high",
        "open",
        "rag-api"
    ),

    (
        "LLM provider timeout",
        "LLM provider requests are timing out.",
        "critical",
        "resolved",
        "llm-service"
    ),

    (
        "Payment processing latency",
        "Payment processing is slower than expected.",
        "medium",
        "open",
        "payment-service"
    ),

    (
        "Vector search performance degradation",
        "Vector search latency increased significantly.",
        "high",
        "investigating",
        "vector-db"
    ),

    (
        "Authentication service instability",
        "Authentication service returned intermittent errors.",
        "high",
        "resolved",
        "auth-service"
    ),
]


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_connection():

    return psycopg2.connect(**DB_CONFIG)


# ==========================================
# INSERT SERVICES
# ==========================================

def insert_services(cursor):

    query = """
        INSERT INTO services (name, environment)
        VALUES (%s, %s)
        ON CONFLICT (name) DO NOTHING
        RETURNING id, name;
    """

    cursor.executemany(
        """
        INSERT INTO services (name, environment)
        VALUES (%s, %s)
        ON CONFLICT (name) DO NOTHING;
        """,
        SERVICES
    )

    print("Services inserted successfully")


# ==========================================
# FETCH SERVICE IDS
# ==========================================

def get_service_ids(cursor):

    cursor.execute("""
        SELECT id, name
        FROM services;
    """)

    rows = cursor.fetchall()

    return {
        name: service_id
        for service_id, name in rows
    }


# ==========================================
# INSERT INCIDENTS
# ==========================================

def insert_incidents(cursor, service_ids):

    query = """
        INSERT INTO incidents (
            service_id,
            title,
            description,
            severity,
            status,
            started_at,
            resolved_at
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s);
    """

    now = datetime.now()

    incidents = []

    for title, description, severity, status, service in INCIDENT_TEMPLATES:

        started_at = now - timedelta(
            hours=random.randint(1, 72)
        )

        resolved_at = None

        if status == "resolved":
            resolved_at = started_at + timedelta(
                minutes=random.randint(15, 180)
            )

        incidents.append((
            service_ids[service],
            title,
            description,
            severity,
            status,
            started_at,
            resolved_at
        ))

    cursor.executemany(query, incidents)

    print("Incidents inserted successfully")


# ==========================================
# INSERT APPLICATION LOGS
# ==========================================

def insert_logs(cursor, service_ids):

    query = """
        INSERT INTO application_logs (
            service_id,
            level,
            message,
            latency_ms,
            request_id,
            timestamp
        )
        VALUES (%s, %s, %s, %s, %s, %s);
    """

    logs = []

    now = datetime.now()

    service_names = list(LOG_TEMPLATES.keys())

    for _ in range(100):

        service = random.choice(service_names)

        # Mostly INFO logs, fewer errors
        level = random.choices(
            ["INFO", "WARNING", "ERROR"],
            weights=[70, 20, 10]
        )[0]

        message = random.choice(
            LOG_TEMPLATES[service][level]
        )

        # Generate realistic latency
        if level == "ERROR":
            latency_ms = random.randint(5000, 20000)

        elif level == "WARNING":
            latency_ms = random.randint(2000, 8000)

        else:
            latency_ms = random.randint(100, 2500)

        timestamp = now - timedelta(
            minutes=random.randint(0, 1440)
        )

        logs.append((
            service_ids[service],
            level,
            message,
            latency_ms,
            str(uuid.uuid4()),
            timestamp
        ))

    cursor.executemany(query, logs)

    print("100 application logs inserted successfully")


# ==========================================
# MAIN FUNCTION
# ==========================================

def main():

    connection = None

    try:

        connection = get_connection()

        cursor = connection.cursor()

        print("Connected to PostgreSQL")

        insert_services(cursor)

        service_ids = get_service_ids(cursor)

        insert_incidents(cursor, service_ids)

        insert_logs(cursor, service_ids)

        connection.commit()

        print("\nAll fake data inserted successfully!")

    except Exception as e:

        if connection:
            connection.rollback()

        print("Error:", e)

    finally:

        if connection:
            connection.close()

            print("Database connection closed")


if __name__ == "__main__":

    main()