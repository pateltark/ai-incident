from db import get_incident, resolve_incident


def ask_required(label, default=None):
    while True:
        hint = " [Enter = keep AI suggestion]" if default else ""
        value = input(f"{label}{hint}: ").strip()
        if not value and default:
            return default
        if value:
            return value
        print("  This field is required.")


def resolve_flow(incident_id: int):
    inc = get_incident(incident_id)
    if not inc:
        print(f"Incident {incident_id} not found.")
        return
    if inc["status"] == "resolved":
        print(f"Incident {incident_id} is already resolved.")
        return

    print(f"\nIncident #{inc['id']} | {inc['service']} | {inc['rule']} | {inc['severity']}")
    print(f"Started: {inc['started_at']}")
    print(f"Symptoms: {inc['description']}\n")

    if inc["root_cause"]:
        print(f"AI suggested root cause: {inc['root_cause']}")
    if inc["resolution"]:
        print(f"AI suggested solution:   {inc['resolution']}\n")

    root_cause = ask_required("What was the main issue (root cause)?", inc["root_cause"])
    resolution = ask_required("How did you solve it?", inc["resolution"])

    if input("\nMark as resolved? (y/n): ").strip().lower() != "y":
        print("Cancelled.")
        return

    if resolve_incident(incident_id, root_cause, resolution):
        print(f"Incident {incident_id} resolved.")
    else:
        print("Could not resolve (already closed?).")


if __name__ == "__main__":
    import sys
    resolve_flow(int(sys.argv[1]))      # python resolve.py 33