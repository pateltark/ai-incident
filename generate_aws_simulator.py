import time
import random
import datetime
import os

LOG_FILE = "app.log"

SERVICES = ["checkout", "payment", "auth", "inventory"]

# Realistic log message weights and distributions
LOG_TEMPLATES = {
    "INFO": [
        "Incoming HTTP GET /api/v1/health 200 OK",
        "User session authenticated successfully via JWT",
        "Database connection pool acquired connection in 2ms",
        "Cache hit for key user_profile_cache",
        "Successfully processed background job batch_sync",
        "HTTP POST /api/v1/cart/items completed with status 201"
    ],
    "WARN": [
        "High CPU utilization detected on node worker-03 (82%)",
        "Database query execution took longer than threshold: 450ms",
        "Rate limit approaching for client IP 192.168.1.45",
        "Deprecated API endpoint /v0/legacy called by client",
        "Connection retry attempt 1/3 established for external payment gateway"
    ],
    "ERROR": [
        "out of memory killed process",
        "Connection refused while communicating with downstream dependency redis-cluster",
        "NullPointerException in order fulfillment processing pipeline",
        "Failed to write transaction ledger: deadlock detected",
        "Unauthorized access attempt detected with malformed signature"
    ],
    "CRITICAL": [
        "Disk partition /var/log reached 98% capacity saturation",
        "Primary database failover triggered: lost heartbeat from master node",
        "Kernel panic risk: system running out of low memory buffers"
    ]
}

def generate_log_line():
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00"
    service = random.choice(SERVICES)
    
    # Weighted level distribution: 70% INFO, 15% WARN, 12% ERROR, 3% CRITICAL
    level = random.choices(
        ["INFO", "WARN", "ERROR", "CRITICAL"], 
        weights=[70, 15, 12, 3], 
        k=1
    )[0]
    
    message = random.choice(LOG_TEMPLATES[level])
    
    # Add simulated latency metrics for tracing
    latency = random.randint(15, 850) if level != "CRITICAL" else random.randint(2000, 5000)
    
    # Format matching your ClickHouse / application log pattern
    log_line = f"{timestamp} {level} [{service}] {message} (latency={latency}ms)\n"
    return log_line

def main():
    print(f"==================================================")
    print(f" AWS CloudWatch Application Log Stream Simulator")
    print(f" Output Target: {os.path.abspath(LOG_FILE)}")
    print(f" Status: Streaming continuous logs... (Press Ctrl+C to stop)")
    print(f"==================================================")
    
    # Ensure log file exists or initialize it
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "a").close()

    try:
        while True:
            log_entry = generate_log_line()
            
            # Append cleanly to app.log
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(log_entry)
            
            # Print to local console so you can see it streaming live instantly
            print(log_entry.strip())
            
            # Random jitter interval to simulate realistic web traffic flow (0.3 to 1.5 seconds)
            time.sleep(random.uniform(0.3, 1.5))
            
    except KeyboardInterrupt:
        print("\n[Simulator] Log generation stopped gracefully by user.")

if __name__ == "__main__":
    main()