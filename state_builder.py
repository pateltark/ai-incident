import json, os, datetime, statistics

LOG_FILE = "logs/app.jsonl"
STATE_FILE = "state/current_state.json"

def append_log(service, level, message, latency_ms, request_id):
    os.makedirs("logs", exist_ok=True)
    rec = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "service": service, "level": level.upper(), "message": message,
        "latency_ms": latency_ms, "request_id": request_id,
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(rec) + "\n")

def read_logs(service, minutes=30):
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=minutes)
    out = []
    if not os.path.exists(LOG_FILE):
        return out
    with open(LOG_FILE) as f:
        for line in f:
            rec = json.loads(line)
            if rec["service"] == service and datetime.datetime.fromisoformat(rec["ts"]) >= cutoff:
                out.append(rec)
    return out

def build_state(incident: dict) -> dict:
    """incident = {incident_id, service, rule, fingerprint}"""
    logs = read_logs(incident["service"], minutes=30)
    errors = [l for l in logs if l["level"] == "ERROR"]
    lats = sorted(l["latency_ms"] for l in logs if l["latency_ms"] is not None)
    median = statistics.median(lats) if lats else 0
    p95 = lats[int(0.95 * (len(lats) - 1))] if lats else None

    state = {
        "alert": {
            **incident,
            "error_rate": (len(errors) / len(logs)) if logs else None,
            "p95_latency_ms": p95,
        },
        "logs": errors[-50:],
        "incidents": [],   # historical matches come later (retriever)
        "slow_requests": [l for l in logs if median and l["latency_ms"] and l["latency_ms"] > 2 * median][-50:],
        "analysis": None,
    }
    os.makedirs("state", exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, STATE_FILE)   # atomic, so the agent never reads a half-written file
    return state