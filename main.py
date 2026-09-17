from db import query_logs

logs = query_logs(
    service_name="payment-service",
    level="ERROR"
)

for log in logs:
    print(log)