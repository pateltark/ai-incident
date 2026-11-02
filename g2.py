# generate_aws_logs.py

import os
import random
import json
import time
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

LOG_FILE = os.getenv("LOCAL_LOG_FILE", "app.log")

# ------------------------------------------------------------------------------
# Core Writer Matching Real-Time App Appending
# ------------------------------------------------------------------------------

def write_log(line_content):
    """Appends a raw log entry with an exact production timestamp to the tracking file."""
    timestamp = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    
    # Standardizing format: [TIMESTAMP] [LOG_FORMAT_SPECIFIC_PAYLOAD]
    log_line = f"{timestamp} {line_content}\n"
    
    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(log_line)
        
    print(log_line, end="")

# ------------------------------------------------------------------------------
# Exact Production Format Generators
# ------------------------------------------------------------------------------

def generate_cloudwatch_app_log(level="INFO", service="payment-service", message="Transaction completed successfully"):
    """
    Matches production AWS CloudWatch / Container stdout log format:
    YYYY-MM-DD HH:MM:SS,mmm LEVEL [service_name] [thread_id] message
    """
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
    thread_id = f"Thread-{random.randint(10, 99)}"
    log_body = f"[{level.upper()}] [{service}] [{thread_id}] {message}"
    write_log(log_body)


def generate_alb_log(status_code=200, path="/api/v1/checkout"):
    """
    Matches exact AWS Application Load Balancer (ALB) access log specification:
    type timestamp elb client:port target:port request_processing_time target_processing_time 
    response_processing_time status_code target_status_code received_bytes sent_bytes "request" "user_agent" ...
    """
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    elb_id = "app/prod-ingress-alb/50dc6c495c0c9188"
    client_ip = f"192.0.2.{random.randint(1, 255)}"
    client_port = random.randint(1024, 65535)
    target_ip = f"10.0.1.{random.randint(1, 255)}"
    target_port = 8080
    
    req_t = f"{random.uniform(0.000, 0.005):.3f}"
    target_t = f"{random.uniform(0.002, 0.150):.3f}"
    resp_t = f"{random.uniform(0.000, 0.002):.3f}"
    
    rcv_bytes = random.randint(150, 1024)
    sent_bytes = random.randint(500, 15000)
    
    log_body = (
        f'http {ts} {elb_id} {client_ip}:{client_port} {target_ip}:{target_port} '
        f'{req_t} {target_t} {resp_t} {status_code} {status_code} {rcv_bytes} {sent_bytes} '
        f'"POST https://api.production.internal:443{path} HTTP/1.1" '
        f'"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2'
    )
    write_log(log_body)


def generate_vpc_flow_log(action="ACCEPT"):
    """
    Matches exact AWS VPC Flow Logs format (Default version 2):
    version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
    """
    version = 2
    account_id = "123456789012"
    eni_id = f"eni-{random.randint(10000000, 99999999):x}"
    src_ip = f"10.0.{random.randint(0, 3)}.{random.randint(1, 255)}"
    dst_ip = f"10.0.{random.randint(4, 7)}.{random.randint(1, 255)}"
    src_port = random.randint(32768, 61000)
    dst_port = random.choice([443, 5432, 6379, 8080])
    protocol = 6  # TCP
    packets = random.randint(2, 50)
    bytes_val = packets * random.randint(100, 1400)
    start_time = int(time.time()) - 60
    end_time = int(time.time())
    
    log_body = f"{version} {account_id} {eni_id} {src_ip} {dst_ip} {src_port} {dst_port} {protocol} {packets} {bytes_val} {start_time} {end_time} {action} OK"
    write_log(log_body)


def generate_cloudtrail_log(service="s3", event_name="GetObject", error=False):
    """
    Matches exact AWS CloudTrail JSON record structure streamed via EventBridge / CloudWatch.
    """
    event = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMRole",
            "principalId": "AROAEXAMPLEID:app-runtime-node",
            "arn": "arn:aws:iam::123456789012:role/ProductionAppExecutionRole",
            "accountId": "123456789012"
        },
        "eventTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": f"{service}.amazonaws.com",
        "eventName": event_name,
        "awsRegion": "us-east-1",
        "sourceIPAddress": f"54.210.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "userAgent": "aws-sdk-python/1.34.0 Linux/5.15.0-1050-aws",
        "requestParameters": {"bucketName": "prod-customer-artifacts-bucket", "key": "configs/app.env"},
        "responseElements": None if error else {"X-Amz-Request-ID": "ABCDEF1234567890"},
        "errorCode": "AccessDenied" if error else None,
        "errorMessage": "User not authorized to perform: s3:GetObject" if error else None
    }
    write_log(json.dumps(event))


def generate_lambda_powertools_log(level="INFO", message="Event payload processed successfully"):
    """
    Matches AWS Lambda Powertools structured JSON format.
    """
    event = {
        "level": level.upper(),
        "location": "order_handler.py:lambda_handler:58",
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "order-fulfillment-lambda",
        "cold_start": False,
        "function_name": "prod-order-fulfillment",
        "function_memory_size": "1024",
        "function_request_id": f"b54c8e71-{random.randint(1000,9999)}-4fbc-92d1-{random.randint(100000000000,999999999999)}"
    }
    write_log(json.dumps(event))

# ------------------------------------------------------------------------------
# Interactive Command Suite
# ------------------------------------------------------------------------------

HELP = """
AWS Real-Time App Log Generator Commands:

  cloudwatch <INFO|WARN|ERROR> <service_name> <message>
      Writes a real-time app console text log line.

  alb <status_code> <endpoint_path>
      Writes a real-time Application Load Balancer access log line.

  vpc <ACCEPT|REJECT>
      Writes a real-time VPC Flow Log packet entry.

  cloudtrail <service> <event_name> [error]
      Writes a real-time CloudTrail JSON event record.

  lambda <INFO|WARN|ERROR> <message>
      Writes a structured Lambda Powertools JSON log entry.

  burst <count> <type> <message>
      Simulates a sudden stream of error logs (types: cloudwatch, alb, vpc, cloudtrail, lambda).

  random <count>
      Generates a continuous realistic blend of all production log types.

  quit / exit
      Stops the generator.
"""

def main():
    print(f"[*] Production AWS Log Stream Generator Started.")
    print(f"[*] Appending to live tracking file: {LOG_FILE}")
    print("Type 'help' to see commands or 'quit' to exit.\n")

    open(LOG_FILE, "a", encoding="utf-8").close()

    while True:
        try:
            command = input("live-logs> ").strip()
            if not command:
                continue

            parts = command.split()
            action = parts[0].lower()
            args = parts[1:]

            if action in ("quit", "exit"):
                break
            elif action == "help":
                print(HELP)

            elif action == "cloudwatch":
                lvl = args[0] if len(args) > 0 else "INFO"
                srv = args[1] if len(args) > 1 else "auth-service"
                msg = " ".join(args[2:]) if len(args) > 2 else "Token validation completed"
                generate_cloudwatch_app_log(lvl, srv, msg)

            elif action == "alb":
                code = int(args[0]) if len(args) > 0 else 200
                path = args[1] if len(args) > 1 else "/api/v1/checkout"
                generate_alb_log(code, path)

            elif action == "vpc":
                act = args[0].upper() if len(args) > 0 else "ACCEPT"
                generate_vpc_flow_log(act)

            elif action == "cloudtrail":
                srv = args[0] if len(args) > 0 else "s3"
                evt = args[1] if len(args) > 1 else "GetObject"
                is_err = True if len(args) > 2 and args[2].lower() == "error" else False
                generate_cloudtrail_log(srv, evt, is_err)

            elif action == "lambda":
                lvl = args[0] if len(args) > 0 else "INFO"
                msg = " ".join(args[1:]) if len(args) > 1 else "Order state committed"
                generate_lambda_powertools_log(lvl, msg)

            elif action == "burst":
                if len(args) < 2:
                    print("Usage: burst <count> <cloudwatch|alb|vpc|cloudtrail|lambda> <message>")
                    continue
                count = int(args[0])
                l_type = args[1].lower()
                msg = " ".join(args[2:]) if len(args) > 2 else "Database connection pool timeout failure"
                
                print(f"[!] Generating burst of {count} {l_type} logs...")
                for _ in range(count):
                    if l_type == "cloudwatch":
                        generate_cloudwatch_app_log("ERROR", "db-cluster", msg)
                    elif l_type == "alb":
                        generate_alb_log(502, "/api/v1/payment/checkout")
                    elif l_type == "vpc":
                        generate_vpc_flow_log("REJECT")
                    elif l_type == "cloudtrail":
                        generate_cloudtrail_log("rds", "DeleteDBInstance", error=True)
                    elif l_type == "lambda":
                        generate_lambda_powertools_log("ERROR", msg)
                    time.sleep(0.05)

            elif action == "random":
                count = int(args[0]) if len(args) > 0 else 10
                generators = [
                    lambda: generate_cloudwatch_app_log("INFO", "user-service", "Session validated"),
                    lambda: generate_alb_log(200, "/healthz"),
                    lambda: generate_vpc_flow_log("ACCEPT"),
                    lambda: generate_cloudtrail_log("s3", "PutObject"),
                    lambda: generate_lambda_powertools_log("INFO", "Item added to cart")
                ]
                for _ in range(count):
                    random.choice(generators)()
                    time.sleep(0.1)

            else:
                print("Unknown command. Type 'help'.")

        except Exception as e:
            print(f"Error processing command: {e}")

    print("Log generator stopped.")

if __name__ == "__main__":
    main()