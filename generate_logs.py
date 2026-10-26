
# generate_logs.py

import os
import random
import time
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

LOG_FILE = os.getenv("LOCAL_LOG_FILE", "app.log")

DEFAULT_SERVICES = ["checkout", "payment", "auth", "inventory"]

SAMPLE_MESSAGES = {
    "INFO": [
        "request completed successfully",
        "database connection established",
        "health check passed",
        "payment processed successfully",
    ],
    "WARN": [
        "database response time is increasing",
        "retrying payment gateway request",
        "connection pool usage is high",
    ],
    "ERROR": [
        "database connection timeout",
        "payment gateway timeout",
        "payment processing failed",
        "token signature verification failed: certificate expired",
        "connection pool exhausted",
    ],
}


def write_log(level, service, message, latency_ms=None):
    """Write one log line to the local file. No database operations."""

    timestamp = datetime.now(timezone.utc).isoformat(
        timespec="microseconds"
    )

    if latency_ms is not None:
        message = f"{message} latency_ms={latency_ms}"

    log_line = (
        f"{timestamp} {level.upper()} "
        f"[{service}] {message}\n"
    )

    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(log_line)

    print(log_line, end="")


def generate_burst(count, service, message):
    """Write multiple ERROR logs rapidly."""

    for _ in range(count):
        write_log("ERROR", service, message)

    print(f"\nGenerated {count} ERROR logs for {service}.")


def generate_random_logs(count, service):
    """Generate a mixture of realistic INFO, WARN and ERROR logs."""

    for _ in range(count):
        level = random.choices(
            ["INFO", "WARN", "ERROR"],
            weights=[70, 15, 15],
            k=1,
        )[0]

        message = random.choice(SAMPLE_MESSAGES[level])
        write_log(level, service, message)

    print(f"\nGenerated {count} logs for {service}.")


def generate_latency_logs(count, service, latency_ms):
    """Generate INFO logs with latency values in their messages."""

    for _ in range(count):
        write_log(
            "INFO",
            service,
            "request completed",
            latency_ms=latency_ms,
        )

    print(
        f"\nGenerated {count} logs for {service} "
        f"with latency_ms={latency_ms}."
    )


HELP = """
Commands:

  error <service> <message...>
      Write one ERROR log.

  warn <service> <message...>
      Write one WARN log.

  info <service> <message...>
      Write one INFO log.

  burst <count> <service> <message...>
      Write multiple ERROR logs rapidly.

  random <count> <service>
      Generate random INFO, WARN and ERROR logs.

  latency <count> <service> <milliseconds>
      Write INFO logs with latency values in their messages.

  help
      Show commands.

  quit
      Exit the generator.

Examples:

  error payment database connection timeout

  burst 10 auth token signature verification failed: certificate expired

  random 20 checkout

  latency 10 payment 9000
"""


def main():
    print(f"Log generator started. Output file: {LOG_FILE}")
    print("Logs will be appended to the file, not sent to PostgreSQL.")
    print("Type 'help' for commands or 'quit' to exit.\n")

    # Create the file if it doesn't already exist.
    open(LOG_FILE, "a", encoding="utf-8").close()

    while True:
        try:
            command = input("> ").strip()

            if not command:
                continue

            parts = command.split()
            action = parts[0].lower()
            args = parts[1:]

            if action in ("quit", "exit"):
                break

            elif action == "help":
                print(HELP)

            elif action in ("error", "warn", "info"):
                if len(args) < 2:
                    print(f"Usage: {action} <service> <message...>")
                    continue

                service = args[0]
                message = " ".join(args[1:])
                write_log(action.upper(), service, message)

            elif action == "burst":
                if len(args) < 3:
                    print("Usage: burst <count> <service> <message...>")
                    continue

                count = int(args[0])
                service = args[1]
                message = " ".join(args[2:])

                if count < 1:
                    print("Count must be at least 1.")
                    continue

                generate_burst(count, service, message)

            elif action == "random":
                if len(args) != 2:
                    print("Usage: random <count> <service>")
                    continue

                count = int(args[0])
                service = args[1]

                if count < 1:
                    print("Count must be at least 1.")
                    continue

                generate_random_logs(count, service)

            elif action == "latency":
                if len(args) != 3:
                    print("Usage: latency <count> <service> <milliseconds>")
                    continue

                count = int(args[0])
                service = args[1]
                latency_ms = float(args[2])

                if count < 1 or latency_ms < 0:
                    print("Count must be positive; latency cannot be negative.")
                    continue

                generate_latency_logs(count, service, latency_ms)

            else:
                print("Unknown command. Type 'help'.")

        except (ValueError, OverflowError) as error:
            print(f"Invalid input: {error}")

        except OSError as error:
            print(f"Could not write log file: {error}")

    print("Log generator stopped.")


if __name__ == "__main__":
    main()
