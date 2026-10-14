"""Action Center findings and durable operator workflow."""

import json
import sqlite3
from datetime import datetime, timedelta

from .alerts import evaluate_alerts
from .database import init_database
from .logs import group_error_incidents, parse_access_log, parse_error_log
from .metrics import collect_metrics
from .traffic import analyze_access_logs, analyze_block_recommendations


ACTION_ITEM_STATUSES = {"new", "acknowledged", "snoozed", "resolved", "dismissed"}


def build_action_candidates(config_data, metrics=None, access_entries=None, error_entries=None):
    """Build a unified set of actionable findings from current observations."""
    if metrics is None:
        metrics = collect_metrics()
    if access_entries is None:
        access_entries = parse_access_log(
            config_data["apache"].get("access_log", ""), max_lines=10000
        )
    if error_entries is None:
        error_entries = parse_error_log(
            config_data["apache"].get("error_log", ""), max_lines=2000
        )

    access_stats = analyze_access_logs(access_entries)
    alerts = evaluate_alerts(metrics, access_stats, config_data)
    incidents = group_error_incidents(error_entries, limit=50)
    recommendations = analyze_block_recommendations(access_entries, config_data.get("security"))
    candidates = []

    alert_titles = {
        "disk_percent": "Disk usage is above threshold",
        "server_errors_5xx": "Server errors are above threshold",
        "client_errors_4xx": "Client errors are above threshold",
        "requests_per_ip": "One client is generating heavy traffic",
        "bot_percentage": "Bot traffic is above threshold",
    }
    alert_views = {
        "disk_percent": "overview",
        "server_errors_5xx": "logs",
        "client_errors_4xx": "logs",
        "requests_per_ip": "security",
        "bot_percentage": "analytics",
    }
    for alert in alerts:
        alert_type = alert["alert_type"]
        candidates.append({
            "source": "alert",
            "source_key": f"alert:{alert_type}",
            "severity": alert["severity"],
            "title": alert_titles.get(alert_type, "Monitoring threshold exceeded"),
            "summary": alert["message"],
            "evidence": {
                "alert_type": alert_type,
                "value": alert.get("value"),
                "threshold": alert.get("threshold"),
            },
            "related_view": alert_views.get(alert_type, "overview"),
            "related_query": "",
            "occurrence_count": 1,
        })

    actionable_levels = {"emerg", "alert", "crit", "critical", "error", "warn", "warning"}
    for incident in incidents:
        level = incident.get("level", "unknown").lower()
        # One-off log lines remain available in Log Explorer. The inbox only
        # promotes recurring problems so it does not become a second raw log.
        if level not in actionable_levels or incident.get("count", 0) < 2:
            continue
        severity = "critical" if level in {"emerg", "alert", "crit", "critical", "error"} else "warning"
        candidates.append({
            "source": "error",
            "source_key": f"error:{incident['id']}",
            "severity": severity,
            "title": "Repeated Apache error" if severity == "critical" else "Repeated Apache warning",
            "summary": incident["message"],
            "evidence": incident,
            "related_view": "logs",
            "related_query": (incident.get("affected_urls") or [""])[0],
            "occurrence_count": incident.get("count", 1),
        })

    for recommendation in recommendations:
        action = recommendation.get("action")
        target = recommendation.get("target", "Unknown client")
        score = recommendation.get("score", 0)
        severity = "critical" if action == "block_ip" and score >= 70 else "warning"
        title = {
            "block_ip": f"Review block candidate {target}",
            "consider_range": f"Review suspicious range {target}",
            "watch": f"Watch suspicious client {target}",
        }.get(action, f"Review suspicious traffic from {target}")
        reasons = recommendation.get("reasons") or []
        candidates.append({
            "source": "security",
            "source_key": f"security:{action}:{target}",
            "severity": severity,
            "title": title,
            "summary": reasons[0] if reasons else "Suspicious access-log activity was detected.",
            "evidence": recommendation,
            "related_view": "security",
            "related_query": target if recommendation.get("target_type") == "ip" else "",
            "occurrence_count": recommendation.get("requests", 1),
        })

    return candidates


def sync_action_items(db_path, candidates):
    """Refresh observed findings while preserving their workflow state."""
    init_database(db_path)
    now = datetime.now().isoformat()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT source_key, status, currently_observed FROM action_items")
    previous = {row["source_key"]: dict(row) for row in cursor.fetchall()}

    # A finding can remain in the inbox even after it stops appearing in the
    # current scan, but the UI should make that distinction visible.
    cursor.execute("UPDATE action_items SET currently_observed = 0")

    for candidate in candidates:
        previous_item = previous.get(candidate["source_key"])
        reappeared_after_resolution = bool(
            previous_item
            and previous_item["status"] == "resolved"
            and not previous_item["currently_observed"]
        )
        cursor.execute('''
            INSERT INTO action_items (
                source, source_key, severity, title, summary, evidence_json,
                related_view, related_query, status, note, created_at,
                updated_at, last_seen, occurrence_count, currently_observed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new', '', ?, ?, ?, ?, 1)
            ON CONFLICT(source_key) DO UPDATE SET
                severity = excluded.severity,
                title = excluded.title,
                summary = excluded.summary,
                evidence_json = excluded.evidence_json,
                related_view = excluded.related_view,
                related_query = excluded.related_query,
                last_seen = excluded.last_seen,
                occurrence_count = excluded.occurrence_count,
                currently_observed = 1
        ''', (
            candidate["source"],
            candidate["source_key"],
            candidate["severity"],
            candidate["title"],
            candidate["summary"],
            json.dumps(candidate.get("evidence", {}), default=str),
            candidate.get("related_view"),
            candidate.get("related_query", ""),
            now,
            now,
            now,
            max(1, int(candidate.get("occurrence_count", 1))),
        ))
        if reappeared_after_resolution:
            cursor.execute('''
                UPDATE action_items
                SET status = 'new', snoozed_until = NULL, updated_at = ?
                WHERE source_key = ?
            ''', (now, candidate["source_key"]))

    conn.commit()
    conn.close()


def get_action_items(db_path, status="open", limit=100):
    """Return action items and workflow summary, reopening expired snoozes."""
    init_database(db_path)
    now = datetime.now().isoformat()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE action_items
        SET status = 'new', snoozed_until = NULL, updated_at = ?
        WHERE status = 'snoozed' AND snoozed_until IS NOT NULL AND snoozed_until <= ?
    ''', (now, now))

    clauses = []
    params = []
    if status == "open":
        clauses.append("status IN ('new', 'acknowledged')")
    elif status != "all":
        if status not in ACTION_ITEM_STATUSES:
            conn.close()
            raise ValueError("invalid action item status")
        clauses.append("status = ?")
        params.append(status)
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(min(max(int(limit), 1), 500))
    cursor.execute(f'''
        SELECT * FROM action_items
        {where_sql}
        ORDER BY
            CASE status WHEN 'new' THEN 0 WHEN 'acknowledged' THEN 1
                        WHEN 'snoozed' THEN 2 WHEN 'resolved' THEN 3 ELSE 4 END,
            currently_observed DESC,
            CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,
            last_seen DESC
        LIMIT ?
    ''', params)
    rows = cursor.fetchall()
    cursor.execute("SELECT status, COUNT(*) AS count FROM action_items GROUP BY status")
    counts = {row["status"]: row["count"] for row in cursor.fetchall()}
    conn.commit()
    conn.close()

    items = []
    for row in rows:
        item = dict(row)
        try:
            item["evidence"] = json.loads(item.pop("evidence_json"))
        except (TypeError, json.JSONDecodeError):
            item["evidence"] = {}
            item.pop("evidence_json", None)
        item["currently_observed"] = bool(item["currently_observed"])
        items.append(item)

    summary = {name: counts.get(name, 0) for name in ACTION_ITEM_STATUSES}
    summary["open"] = summary["new"] + summary["acknowledged"]
    summary["total"] = sum(counts.values())
    return items, summary


def update_action_item(db_path, item_id, status, note=None, snooze_minutes=60):
    """Apply a workflow decision to one action item."""
    if status not in ACTION_ITEM_STATUSES:
        raise ValueError("invalid action item status")
    init_database(db_path)
    now = datetime.now()
    snoozed_until = None
    if status == "snoozed":
        try:
            snooze_minutes = min(max(int(snooze_minutes), 1), 10080)
        except (TypeError, ValueError):
            raise ValueError("snooze_minutes must be an integer")
        snoozed_until = (now + timedelta(minutes=snooze_minutes)).isoformat()

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    if note is None:
        cursor.execute('''
            UPDATE action_items
            SET status = ?, updated_at = ?, snoozed_until = ?
            WHERE id = ?
        ''', (status, now.isoformat(), snoozed_until, item_id))
    else:
        cursor.execute('''
            UPDATE action_items
            SET status = ?, note = ?, updated_at = ?, snoozed_until = ?
            WHERE id = ?
        ''', (status, str(note)[:2000], now.isoformat(), snoozed_until, item_id))
    changed = cursor.rowcount
    conn.commit()
    conn.close()
    return bool(changed)
