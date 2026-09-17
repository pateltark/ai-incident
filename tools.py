from db import query_logs, get_incidents


def query_logs_tool (
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

def find_incident_tool (service_name, status, severity):

    return get_incidents(service_name, status, severity)

    

TOOL = [
    {
        "type": "function",
        "function": {
            "name": "query_logs_tool",
            "description": (
                "Query application logs from PostgreSQL. "
                "Use this when you need to investigate errors, "
                "warnings, latency, or other log events for a service."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "service_name": {
                        "type": "string",
                        "description": "Name of the service to investigate."
                    },
                    "level": {
                        "type": "string",
                        "description": (
                            "Log level to filter by, such as ERROR, "
                            "WARN, or INFO."
                        )
                    },
                    "start_time": {
                        "type": "string",
                        "description": (
                            "Optional start timestamp for the log search."
                        )
                    },
                    "end_time": {
                        "type": "string",
                        "description": (
                            "Optional end timestamp for the log search."
                        )
                    }
                }
            }
        }
    },  
    {
        "type": "function",
        "function": {
            "name": "find_incident_tool",
            "description": "Find incidents for a specific service, optionally filtered by incident status and severity.",
            "parameters": {  
                "type": "object",
                "properties": {
                    "service_name": {
                        "type": "string",
                        "description": "Name of the service for which incidents should be searched."
                    },
                    "status": {
                        "type": "string",  
                        "description": "Optional incident status to filter by, such as OPEN, RESOLVED, or CLOSED."
                    },
                    "severity": {
                        "type": "string",
                        "description": "Optional incident severity to filter by, such as LOW, MEDIUM, HIGH, or CRITICAL."
                    }
                }
            }
        }
    }
]
