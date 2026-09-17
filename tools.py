from db import query_logs


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



QUERY_LOGS_TOOL = {
    "type": "function",
    "function": {
        "name": "query_logs",
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
}