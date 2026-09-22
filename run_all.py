"""
run_all.py

Runs log_generator.py, ingestor.py, and detector.py together as one
process, so you don't need three separate terminal windows. Each child's
output is streamed back with a [generator]/[ingestor]/[detector] prefix
so you can tell them apart, and Ctrl+C stops all three cleanly.

This is purely a convenience wrapper for local development/demos - it
doesn't change what any of the three scripts do. For anything closer to
how these would really run (each as its own container/service), keep
them separate; V5's docker-compose setup will do exactly that.

Usage:
    python run_all.py
    python run_all.py --rate 8 --error-rate 0.02 --detector-interval 30
    python run_all.py --skip-detector          # e.g. while DB isn't set up yet
"""

import argparse
import subprocess
import sys
import threading


def stream_output(proc, name, color):
    """Reads a child process's stdout line by line and reprints it with a
    prefix, so all three processes' output can share one terminal."""
    reset = "\033[0m"
    for line in iter(proc.stdout.readline, ""):
        if line:
            print(f"{color}[{name}]{reset} {line.rstrip()}")
    proc.stdout.close()


def main():
    parser = argparse.ArgumentParser(description="Run the generator, ingestor, and detector together.")
    parser.add_argument("--rate", type=float, default=5.0, help="log_generator: requests/sec (default: 5)")
    parser.add_argument("--error-rate", type=float, default=0.012, help="log_generator: baseline error rate")
    parser.add_argument("--slow-query-ms", type=float, default=40.0, help="log_generator: slow query threshold")
    parser.add_argument("--out", type=str, default="logs", help="log_generator: output directory (default: logs)")
    parser.add_argument("--poll-interval", type=float, default=2.0, help="ingestor: seconds between polls")
    parser.add_argument("--detector-interval", type=float, default=45.0, help="detector: seconds between checks")
    parser.add_argument("--seed", type=int, default=None, help="log_generator: random seed")
    parser.add_argument("--skip-ingestor", action="store_true", help="don't start the ingestor")
    parser.add_argument("--skip-detector", action="store_true", help="don't start the detector")
    args = parser.parse_args()

    commands = [
        ("generator", "\033[36m", [
            sys.executable, "log_generator.py",
            "--rate", str(args.rate), "--out", args.out,
            "--error-rate", str(args.error_rate), "--slow-query-ms", str(args.slow_query_ms),
        ] + (["--seed", str(args.seed)] if args.seed is not None else [])),
    ]
    if not args.skip_ingestor:
        commands.append(("ingestor", "\033[33m", [
            sys.executable, "ingestor.py",
            "--logs", f"{args.out}/cloudwatch", "--poll-interval", str(args.poll_interval),
        ]))
    if not args.skip_detector:
        commands.append(("detector", "\033[35m", [
            sys.executable, "detector.py", "--interval", str(args.detector_interval),
        ]))

    print(f"[run_all] starting {len(commands)} process(es): {', '.join(n for n, _, _ in commands)}")
    print("[run_all] Ctrl+C to stop all of them.\n")

    procs = []
    threads = []
    try:
        for name, color, cmd in commands:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            procs.append((name, proc))
            t = threading.Thread(target=stream_output, args=(proc, name, color), daemon=True)
            t.start()
            threads.append(t)

        # wait until any child exits on its own (a crash) or the user hits Ctrl+C
        while True:
            for name, proc in procs:
                ret = proc.poll()
                if ret is not None:
                    print(f"\n[run_all] '{name}' exited on its own (code {ret}) - stopping the rest.")
                    raise SystemExit
            for t in threads:
                t.join(timeout=0.5)
                if not t.is_alive():
                    continue
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        print("\n[run_all] stopping all processes...")
        for name, proc in procs:
            if proc.poll() is None:
                proc.terminate()
        for name, proc in procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        # Wait for the reader threads to notice their process's stdout closed
        # and exit on their own, BEFORE the interpreter starts shutting down.
        # Skipping this is what caused the "Fatal Python error:
        # _enter_buffered_busy ... at interpreter shutdown" - a daemon thread
        # still mid-print() when the main thread exits.
        for t in threads:
            t.join(timeout=2)
        print("[run_all] all stopped.")


if __name__ == "__main__":
    main()