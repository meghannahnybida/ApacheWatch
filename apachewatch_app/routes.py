"""Dashboard and HTTP API routes."""

from datetime import datetime
from pathlib import Path
from flask import Blueprint, current_app, jsonify, render_template, request
import notifications

from .actions import (
    build_action_candidates, get_action_items, sync_action_items, update_action_item,
    update_action_note,
)
from .alerts import evaluate_and_save_current_alerts
from .history import (
    add_metrics_snapshot, aggregate_access_logs, get_metrics_history,
    get_recent_alerts, get_traffic_chart_data,
)
from .logs import _tail_file, group_error_incidents, parse_access_log, parse_error_log
from .metrics import collect_metrics, collect_monitoring_health
from .traffic import analyze_access_logs, analyze_block_recommendations

web = Blueprint("web", __name__)


@web.route("/api/notifications/email", methods=["GET", "PATCH"])
def api_email_notifications():
    config = current_app.config["APACHEWATCH"]
    if request.method == "PATCH":
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "a JSON request body is required"}), 400
        try:
            notifications.update_preferences(config, payload.get("enabled"), payload.get("severity"))
        except ValueError as error:
            return jsonify({"error": str(error)}), 400
    return jsonify(notifications.public_status(config))


@web.route("/api/notifications/email/test", methods=["POST"])
def api_test_email():
    config = current_app.config["APACHEWATCH"]
    if not request.is_json:
        return jsonify({"error": "a JSON request body is required"}), 400
    if not notifications.public_status(config)["monitoring_active"]:
        return jsonify({"error": "Start the background monitoring worker before sending a test email."}), 409
    try:
        job_id = notifications.queue_test(config)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    return jsonify({"queued": True, "id": job_id}), 202


@web.route("/")
def dashboard():
    """Render the dashboard."""
    config = current_app.config["APACHEWATCH"]
    metrics = collect_metrics()
    level_filter = request.args.get('level')  # Get level filter from query params
    limit = int(request.args.get('limit', 20))  # Get limit from query params, default 20
    logs = parse_error_log(config["apache"]["error_log"], max_lines=100, level_filter=level_filter)[-limit:]

    # Save metrics snapshot
    add_metrics_snapshot(config["database"], metrics)

    # Aggregate access logs for traffic charts
    if config["apache"].get("access_log"):
        aggregate_access_logs(config["database"], config["apache"]["access_log"])

    evaluate_and_save_current_alerts(config, metrics=metrics)
    recent_alerts = get_recent_alerts(config["database"], limit=5)

    return render_template(
        "dashboard.html",
        server_name=config["server_name"],
        metrics=metrics,
        logs=logs,
        current_filter=level_filter,
        recent_alerts=recent_alerts
    )


@web.route("/api/metrics")
def api_metrics():
    """Get current metrics as JSON."""
    return jsonify(collect_metrics())


@web.route("/api/monitoring-health")
def api_monitoring_health():
    """Get Apache process visibility and configured log-source health."""
    config = current_app.config["APACHEWATCH"]
    return jsonify(collect_monitoring_health(config))


@web.route("/api/logs")
def api_logs():
    """Get recent log entries as JSON."""
    config = current_app.config["APACHEWATCH"]
    level_filter = request.args.get('level')  # Get level filter from query params
    limit = int(request.args.get('limit', 100))  # Get limit from query params, default 100
    # Read more lines than limit to ensure enough entries after filtering
    logs = parse_error_log(config["apache"]["error_log"], max_lines=max(limit * 2, 100), level_filter=level_filter)
    return jsonify(logs[-limit:])


@web.route("/api/log-tail")
def api_log_tail():
    """Return unchanged recent lines from a configured log, in file order."""
    config = current_app.config["APACHEWATCH"]
    source = request.args.get("source", "error")
    if source not in {"error", "access"}:
        return jsonify({"error": "source must be error or access"}), 400
    try:
        limit = min(max(int(request.args.get("limit", 100)), 1), 1000)
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400

    path = config["apache"].get(f"{source}_log")
    if not path:
        return jsonify({"error": f"No {source} log file is configured."}), 503
    try:
        lines = _tail_file(path, limit)
    except FileNotFoundError:
        return jsonify({"error": f"The {source} log file was not found."}), 404
    except PermissionError:
        return jsonify({"error": f"ApacheWatch cannot read the {source} log file. Check its file permissions."}), 403
    except OSError:
        return jsonify({"error": f"Unable to read the {source} log file."}), 503
    return jsonify({"source": source, "filename": Path(path).name, "lines": lines})


@web.route("/api/incidents")
def api_incidents():
    """Get recent error-log entries grouped into incidents."""
    config = current_app.config["APACHEWATCH"]
    level_filter = request.args.get("level")
    try:
        limit = min(max(int(request.args.get("limit", 20)), 1), 100)
        scan = min(max(int(request.args.get("scan", 2000)), limit), 10000)
    except ValueError:
        return jsonify({"error": "limit and scan must be integers"}), 400
    logs = parse_error_log(config["apache"]["error_log"], max_lines=scan, level_filter=level_filter)
    incidents = group_error_incidents(logs, limit=limit)
    return jsonify({"incidents": incidents, "count": len(incidents), "entries_scanned": len(logs)})


@web.route("/api/history")
def api_history():
    """Get metrics history."""
    config = current_app.config["APACHEWATCH"]
    history = get_metrics_history(config["database"], limit=1000)
    return jsonify({
        "metrics_history": history,
        "count": len(history)
    })


@web.route("/api/access-stats")
def api_access_stats():
    """Get access log analytics."""
    config = current_app.config["APACHEWATCH"]
    # Parse access log
    entries = parse_access_log(config["apache"].get("access_log", ""), max_lines=1000)

    # Analyze the entries
    stats = analyze_access_logs(entries)
    evaluate_and_save_current_alerts(config, access_stats=stats)

    return jsonify(stats)


@web.route("/api/access-logs")
def api_access_logs():
    """Return recent parsed access-log requests for interactive inspection."""
    config = current_app.config["APACHEWATCH"]
    try:
        limit = min(max(int(request.args.get("limit", 100)), 1), 500)
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400

    entries = parse_access_log(config["apache"].get("access_log", ""), max_lines=limit)
    entries.reverse()  # Newest requests first for log exploration.

    summary = {
        "total": len(entries),
        "success": sum(1 for entry in entries if 200 <= entry["status"] <= 299),
        "redirects": sum(1 for entry in entries if 300 <= entry["status"] <= 399),
        "client_errors": sum(1 for entry in entries if 400 <= entry["status"] <= 499),
        "server_errors": sum(1 for entry in entries if 500 <= entry["status"] <= 599),
        "unique_ips": len({entry["ip"] for entry in entries}),
        "total_bytes": sum(entry["size"] for entry in entries),
    }

    return jsonify({
        "entries": entries,
        "count": len(entries),
        "summary": summary,
    })


@web.route("/api/block-recommendations")
def api_block_recommendations():
    """Return evidence-backed IP and network blocking recommendations."""
    config = current_app.config["APACHEWATCH"]
    try:
        scan = min(max(int(request.args.get("scan", 10000)), 100), 50000)
    except ValueError:
        return jsonify({"error": "scan must be an integer"}), 400
    entries = parse_access_log(config["apache"].get("access_log", ""), max_lines=scan)
    recommendations = analyze_block_recommendations(entries, config.get("security"))
    return jsonify({
        "recommendations": recommendations,
        "count": len(recommendations),
        "entries_scanned": len(entries),
        "advisory_only": True,
    })


@web.route("/api/alerts")
def api_alerts():
    """Get recent alerts as JSON."""
    config = current_app.config["APACHEWATCH"]
    evaluate_and_save_current_alerts(config)
    alerts = get_recent_alerts(config["database"], limit=50)

    return jsonify({
        "alerts": alerts,
        "count": len(alerts)
    })


@web.route("/api/action-items")
def api_action_items():
    """Return the unified operator inbox and refresh its current evidence."""
    config = current_app.config["APACHEWATCH"]
    status = request.args.get("status", "open")
    try:
        limit = min(max(int(request.args.get("limit", 100)), 1), 500)
        candidates = build_action_candidates(config)
        sync_action_items(config["database"], candidates)
        items, summary = get_action_items(config["database"], status=status, limit=limit)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    return jsonify({
        "items": items,
        "count": len(items),
        "summary": summary,
        "refreshed_at": datetime.now().isoformat(),
    })


@web.route("/api/action-items/<int:item_id>", methods=["PATCH"])
def api_update_action_item(item_id):
    """Save a note independently or update a finding's workflow state."""
    config = current_app.config["APACHEWATCH"]
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "a JSON request body is required"}), 400
    status = payload.get("status")
    if "status" not in payload and "note" not in payload:
        return jsonify({"error": "status or note is required"}), 400
    try:
        if "status" in payload:
            changed = update_action_item(
                config["database"],
                item_id,
                status,
                note=payload.get("note"),
                snooze_minutes=payload.get("snooze_minutes", 60),
            )
        else:
            changed = update_action_note(config["database"], item_id, payload["note"])
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    if not changed:
        return jsonify({"error": "action item not found"}), 404
    result = {"ok": True, "id": item_id}
    if "status" in payload:
        result["status"] = status
    return jsonify(result)


@web.route("/api/traffic-chart")
def api_traffic_chart():
    """Get traffic data for charts."""
    config = current_app.config["APACHEWATCH"]
    hours = int(request.args.get('hours', 24))
    data, resolution = get_traffic_chart_data(config["database"], hours=hours)

    return jsonify({
        'data': data,
        'resolution': resolution,
        'count': len(data)
    })
