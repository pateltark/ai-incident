from db import (
    query_logs,
    get_incidents,
    query_slow_requests,
)


# -----------------------------
# Tool functions
# -----------------------------

def query_logs_tool(
    service_name=None,
    level=None,
    start_time=None,
    end_time=None
):
    return query_logs(
        service_name=service_name,
        level=level,
        start_time=start_time,
        end_time=end_time
    )


def find_incident_tool(
    service_name=None,
    status=None,
    severity=None
):
    return get_incidents(
        service_name=service_name,
        status=status,
        severity=severity
    )


def query_slow_requests_tool(
    service_name=None,
    min_latency_ms=5000
):
    return query_slow_requests(
        service_name=service_name,
        min_latency_ms=min_latency_ms
    )


# -----------------------------
# Tool definitions for LLM
# -----------------------------

# -----------------------------
# Tool definitions for LLM
# -----------------------------

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "query_logs_tool",
            "description": (
                "Query application logs from PostgreSQL. "
                "Use this when investigating errors, warnings, "
                "or other log events for a service."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "service_name": {"type": "string", "description": "Name of the service to investigate."},
                    "level": {"type": "string", "description": "Log level such as ERROR, WARN, or INFO."},
                    "start_time": {"type": "string", "description": "Optional start timestamp."},
                    "end_time": {"type": "string", "description": "Optional end timestamp."},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_incident_tool",
            "description": "Find incidents for a service, optionally filtered by status and severity.",
            "parameters": {
                "type": "object",
                "properties": {
                    "service_name": {"type": "string", "description": "Name of the service."},
                    "status": {"type": "string", "description": "Optional incident status such as OPEN, RESOLVED, or CLOSED."},
                    "severity": {"type": "string", "description": "Optional severity such as LOW, MEDIUM, HIGH, or CRITICAL."},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_slow_requests_tool",
            "description": "Find requests with high latency for a service.",
            "parameters": {
                "type": "object",
                "properties": {
                    "service_name": {"type": "string", "description": "Name of the service."},
                    "min_latency_ms": {"type": "integer", "description": "Minimum latency threshold in milliseconds."},
                },
            },
        },
    },
]