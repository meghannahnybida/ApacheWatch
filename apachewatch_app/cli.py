"""Command-line startup for the dashboard, worker, and email check."""

import argparse
import os
import sqlite3
import notifications

from .monitoring import MonitoringWorker


def main(app, argv=None):
    config = app.config["APACHEWATCH"]
    parser = argparse.ArgumentParser(description="ApacheWatch web dashboard and monitoring worker")
    parser.add_argument("--monitor-only", action="store_true", help="Run background monitoring without the web server")
    parser.add_argument("--test-email", action="store_true", help="Send one test to the configured recipients")
    parser.add_argument("--debug", action="store_true", help="Enable development reloading")
    args = parser.parse_args(argv)
    if args.test_email:
        try:
            job_id = notifications.queue_test(config)
            notifications.deliver_pending(config, limit=1, job_id=job_id)
            with sqlite3.connect(config["database"]) as conn:
                status = conn.execute("SELECT status FROM email_outbox WHERE id = ?", (job_id,)).fetchone()[0]
            if status != "sent":
                parser.exit(1, "Test email could not be delivered. Check the sender connection.\n")
            print("Test email delivered to the configured recipients.")
        except ValueError as error:
            parser.exit(1, str(error) + "\n")
        raise SystemExit(0)

    worker = MonitoringWorker(config, logger=app.logger)
    if args.monitor_only:
        try:
            worker.run()
        except KeyboardInterrupt:
            worker.stopped.set()
        raise SystemExit(0)

    print(f"Starting ApacheWatch...")
    print(f"Server: {config['server_name']}")
    print(f"Dashboard: http://localhost:{config['web']['port']}")
    print(f"Error log: {config['apache']['error_log']}")

    # Check that log files exist and are readable before starting
    for label, path in [
        ("Error log",  config["apache"].get("error_log", "")),
        ("Access log", config["apache"].get("access_log", "")),
    ]:
        if not path:
            continue
        if not os.path.exists(path):
            print(f"  WARNING: {label} not found: {path}")
        elif not os.access(path, os.R_OK):
            print(f"  WARNING: {label} not readable (permission denied): {path}")
            print( "    Try: sudo python apachewatch.py  or  sudo chmod o+r " + path)
        else:
            size_mb = os.path.getsize(path) / (1024 * 1024)
            print(f"  {label}: {path} ({size_mb:.1f} MB) - OK")

    if config["monitoring"].get("enabled", True) and (not args.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true"):
        worker.start()
    try:
        app.run(host=config["web"]["host"], port=config["web"]["port"], debug=args.debug)
    finally:
        worker.stop()
