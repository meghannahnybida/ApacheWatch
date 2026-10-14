"""Background collection that runs independently of web requests."""

import logging
import threading
import notifications

from .actions import build_action_candidates, get_action_items, sync_action_items
from .history import add_metrics_snapshot, aggregate_access_logs, save_alerts
from .logs import parse_access_log, parse_error_log
from .metrics import collect_metrics


def run_monitoring_cycle(config):
    """Collect history, refresh findings, and deliver email without a page request."""
    metrics = collect_metrics()
    access_entries = parse_access_log(config["apache"].get("access_log", ""), max_lines=10000)
    error_entries = parse_error_log(config["apache"].get("error_log", ""), max_lines=2000)
    candidates = build_action_candidates(config, metrics, access_entries, error_entries)
    add_metrics_snapshot(config["database"], metrics)
    if config["apache"].get("access_log"):
        aggregate_access_logs(config["database"], config["apache"]["access_log"])
    alerts = []
    for candidate in candidates:
        if candidate["source"] == "alert":
            evidence = candidate["evidence"]
            alerts.append({"severity": candidate["severity"], "message": candidate["summary"], **evidence})
    save_alerts(config["database"], alerts, config["alerts"].get("cooldown_minutes", 30))
    sync_action_items(config["database"], candidates)
    items, _ = get_action_items(config["database"], status="open", limit=500)
    notifications.queue_alerts(config, items)
    notifications.record_monitor_check(config)
    return notifications.deliver_pending(config)


class MonitoringWorker:
    def __init__(self, config_data, logger=None):
        self.config = config_data
        self.logger = logger if logger is not None else logging.getLogger(__name__)
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.run, name="apachewatch-monitor", daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stopped.set()
        if self.thread.is_alive():
            self.thread.join(timeout=2)

    def run(self):
        try:
            interval = max(10, min(3600, int(self.config.get("monitoring", {}).get("interval_seconds", 60))))
        except (TypeError, ValueError):
            interval = 60
        while not self.stopped.is_set():
            try:
                run_monitoring_cycle(self.config)
            except Exception:
                self.logger.exception("Background monitoring check failed")
                try:
                    notifications.record_monitor_check(self.config, "Background check failed. Check server logs.")
                except Exception:
                    self.logger.error("Unable to record monitoring status")
            self.stopped.wait(interval)
