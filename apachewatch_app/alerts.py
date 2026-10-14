"""Threshold evaluation and current-alert collection."""

from .history import save_alerts
from .logs import parse_access_log
from .metrics import collect_metrics
from .traffic import analyze_access_logs


def get_numeric_value(data, path):
    """Safely read a nested numeric value from a dictionary."""
    current = data
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]

    try:
        return float(current)
    except (TypeError, ValueError):
        return None


def get_threshold(thresholds, name):
    """Safely read an alert threshold as a number."""
    try:
        return float(thresholds.get(name))
    except (TypeError, ValueError):
        return None


def sum_status_codes(status_codes, start, end):
    """Count status codes in a range, accepting string or integer keys."""
    total = 0
    if not isinstance(status_codes, dict):
        return total

    for code, count in status_codes.items():
        try:
            numeric_code = int(code)
            numeric_count = int(count)
        except (TypeError, ValueError):
            continue

        if start <= numeric_code <= end:
            total += numeric_count

    return total


def evaluate_alerts(metrics, access_stats, config_data):
    """Evaluate current metrics and access-log stats against alert thresholds."""
    alerts_config = config_data.get("alerts", {})
    if not alerts_config.get("enabled", True):
        return []

    thresholds = alerts_config.get("thresholds", {})
    alerts = []

    disk_percent = get_numeric_value(metrics, ["disk", "percent"])
    disk_threshold = get_threshold(thresholds, "disk_percent")
    if disk_percent is not None and disk_threshold is not None and disk_percent >= disk_threshold:
        alerts.append({
            "severity": "critical",
            "alert_type": "disk_percent",
            "message": f"Disk usage is {disk_percent:g}%, threshold is {disk_threshold:g}%",
            "value": disk_percent,
            "threshold": disk_threshold
        })

    status_codes = access_stats.get("status_codes", {}) if isinstance(access_stats, dict) else {}

    server_errors = sum_status_codes(status_codes, 500, 599)
    server_threshold = get_threshold(thresholds, "server_errors_5xx")
    if server_threshold is not None and server_errors >= server_threshold:
        alerts.append({
            "severity": "critical",
            "alert_type": "server_errors_5xx",
            "message": f"Access log has {server_errors} server errors, threshold is {server_threshold:g}",
            "value": server_errors,
            "threshold": server_threshold
        })

    client_errors = sum_status_codes(status_codes, 400, 499)
    client_threshold = get_threshold(thresholds, "client_errors_4xx")
    if client_threshold is not None and client_errors >= client_threshold:
        alerts.append({
            "severity": "warning",
            "alert_type": "client_errors_4xx",
            "message": f"Access log has {client_errors} client errors, threshold is {client_threshold:g}",
            "value": client_errors,
            "threshold": client_threshold
        })

    top_ips = access_stats.get("top_ips", []) if isinstance(access_stats, dict) else []
    ip_threshold = get_threshold(thresholds, "requests_per_ip")
    if ip_threshold is not None and top_ips:
        top_ip = max(top_ips, key=lambda item: item.get("requests", 0))
        top_ip_requests = top_ip.get("requests", 0)
        if top_ip_requests >= ip_threshold:
            alerts.append({
                "severity": "warning",
                "alert_type": "requests_per_ip",
                "message": f"{top_ip.get('ip', 'Unknown IP')} has {top_ip_requests} requests, threshold is {ip_threshold:g}",
                "value": top_ip_requests,
                "threshold": ip_threshold
            })

    bot_percentage = get_numeric_value(access_stats, ["bot_stats", "bot_percentage"])
    bot_threshold = get_threshold(thresholds, "bot_percentage")
    if bot_percentage is not None and bot_threshold is not None and bot_percentage >= bot_threshold:
        alerts.append({
            "severity": "warning",
            "alert_type": "bot_percentage",
            "message": f"Bot traffic is {bot_percentage:g}%, threshold is {bot_threshold:g}%",
            "value": bot_percentage,
            "threshold": bot_threshold
        })

    return alerts


def evaluate_and_save_current_alerts(config_data, metrics=None, access_stats=None):
    """Evaluate current alert state and save any new alert rows."""
    if metrics is None:
        metrics = collect_metrics()

    if access_stats is None:
        access_entries = parse_access_log(config_data["apache"].get("access_log", ""), max_lines=1000)
        access_stats = analyze_access_logs(access_entries)

    alerts = evaluate_alerts(metrics, access_stats, config_data)
    cooldown_minutes = config_data.get("alerts", {}).get("cooldown_minutes", 30)
    save_alerts(config_data["database"], alerts, cooldown_minutes=cooldown_minutes)
    return alerts
