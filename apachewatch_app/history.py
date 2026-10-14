"""Persistence for alerts, metrics, and hourly traffic history."""

import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta

from .database import init_database
from .logs import parse_access_log


def save_alerts(db_path, alerts, cooldown_minutes=30):
    """Save alerts to SQLite, suppressing repeated alert types during cooldown."""
    if not alerts:
        return 0

    init_database(db_path)

    timestamp = datetime.now().isoformat()
    cooldown_cutoff = None
    try:
        cooldown_minutes = float(cooldown_minutes)
    except (TypeError, ValueError):
        cooldown_minutes = 0

    if cooldown_minutes > 0:
        cooldown_cutoff = (datetime.now() - timedelta(minutes=cooldown_minutes)).isoformat()

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    inserted_alerts = []

    for alert in alerts:
        if cooldown_cutoff:
            cursor.execute('''
                SELECT 1 FROM alerts
                WHERE alert_type = ? AND timestamp >= ?
                LIMIT 1
            ''', (alert["alert_type"], cooldown_cutoff))
            if cursor.fetchone():
                continue

        cursor.execute('''
            INSERT INTO alerts (
                timestamp, severity, alert_type, message, value, threshold
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            timestamp,
            alert["severity"],
            alert["alert_type"],
            alert["message"],
            alert.get("value"),
            alert.get("threshold")
        ))
        inserted_alerts.append(alert)

    conn.commit()
    conn.close()
    return inserted_alerts


def get_recent_alerts(db_path, limit=50):
    """Get recent alerts from the database."""
    init_database(db_path)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute('''
        SELECT timestamp, severity, alert_type, message, value, threshold
        FROM alerts
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (limit,))

    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def add_metrics_snapshot(db_path, metrics):
    """Add a metrics snapshot to the database."""
    init_database(db_path)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO metrics (
            timestamp, cpu_percent,
            memory_percent, memory_used_gb, memory_total_gb,
            disk_percent, disk_used_gb, disk_total_gb
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        metrics['timestamp'],
        metrics['cpu_percent'],
        metrics['memory']['percent'],
        metrics['memory']['used_gb'],
        metrics['memory']['total_gb'],
        metrics['disk']['percent'],
        metrics['disk']['used_gb'],
        metrics['disk']['total_gb']
    ))

    conn.commit()
    conn.close()


def get_metrics_history(db_path, limit=1000):
    """Get recent metrics history from the database."""
    init_database(db_path)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # Enable column access by name
    cursor = conn.cursor()

    cursor.execute('''
        SELECT * FROM metrics
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (limit,))

    rows = cursor.fetchall()
    conn.close()

    # Convert to list of dictionaries
    history = []
    for row in rows:
        history.append({
            'timestamp': row['timestamp'],
            'cpu_percent': row['cpu_percent'],
            'memory': {
                'percent': row['memory_percent'],
                'used_gb': row['memory_used_gb'],
                'total_gb': row['memory_total_gb']
            },
            'disk': {
                'percent': row['disk_percent'],
                'used_gb': row['disk_used_gb'],
                'total_gb': row['disk_total_gb']
            }
        })

    # Reverse to get chronological order (oldest first)
    return list(reversed(history))


def aggregate_access_logs(db_path, log_path, max_lines=10000):
    """Parse access logs and aggregate by hour, storing in database."""
    init_database(db_path)

    # Parse access logs
    entries = parse_access_log(log_path, max_lines=max_lines)

    if not entries:
        return

    # Aggregate by hour
    hourly_data = defaultdict(lambda: {
        'request_count': 0,
        'status_success': 0,
        'status_redirects': 0,
        'status_client_errors': 0,
        'status_server_errors': 0,
        'ips': set()
    })

    for entry in entries:
        try:
            # Parse Apache timestamp format: 04/Jan/2026:14:35:22 +0000
            timestamp_str = entry['timestamp']
            dt = datetime.strptime(timestamp_str.split()[0], '%d/%b/%Y:%H:%M:%S')
            # Round to hour
            hour_key = dt.strftime('%Y-%m-%d %H:00:00')

            hourly_data[hour_key]['request_count'] += 1
            hourly_data[hour_key]['ips'].add(entry['ip'])

            # Track status codes
            status = entry['status']
            if 200 <= status < 300:
                hourly_data[hour_key]['status_success'] += 1
            elif 300 <= status < 400:
                hourly_data[hour_key]['status_redirects'] += 1
            elif 400 <= status < 500:
                hourly_data[hour_key]['status_client_errors'] += 1
            elif 500 <= status < 600:
                hourly_data[hour_key]['status_server_errors'] += 1
        except Exception:
            # Skip entries with unparseable timestamps
            continue

    # Store in database (upsert)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    for hour_timestamp, data in hourly_data.items():
        cursor.execute('''
            INSERT INTO access_logs_hourly (
                hour_timestamp, request_count,
                status_success, status_redirects, status_client_errors, status_server_errors,
                unique_ips
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hour_timestamp) DO UPDATE SET
                request_count = excluded.request_count,
                status_success = excluded.status_success,
                status_redirects = excluded.status_redirects,
                status_client_errors = excluded.status_client_errors,
                status_server_errors = excluded.status_server_errors,
                unique_ips = excluded.unique_ips
        ''', (
            hour_timestamp,
            data['request_count'],
            data['status_success'],
            data['status_redirects'],
            data['status_client_errors'],
            data['status_server_errors'],
            len(data['ips'])
        ))

    conn.commit()
    conn.close()


def get_traffic_chart_data(db_path, hours=24):
    """Get traffic data for charts. Hourly resolution for <=72h, daily buckets for longer ranges."""
    init_database(db_path)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    use_daily = hours > 72

    if use_daily:
        if hours >= 10000:
            cursor.execute('''
                SELECT
                    date(hour_timestamp)      AS day,
                    SUM(request_count)        AS request_count,
                    SUM(status_success)       AS status_success,
                    SUM(status_redirects)     AS status_redirects,
                    SUM(status_client_errors) AS status_client_errors,
                    SUM(status_server_errors) AS status_server_errors,
                    MAX(unique_ips)           AS unique_ips
                FROM access_logs_hourly
                GROUP BY date(hour_timestamp)
                ORDER BY day ASC
            ''')
        else:
            days = hours // 24
            cursor.execute('''
                SELECT
                    date(hour_timestamp)      AS day,
                    SUM(request_count)        AS request_count,
                    SUM(status_success)       AS status_success,
                    SUM(status_redirects)     AS status_redirects,
                    SUM(status_client_errors) AS status_client_errors,
                    SUM(status_server_errors) AS status_server_errors,
                    MAX(unique_ips)           AS unique_ips
                FROM access_logs_hourly
                GROUP BY date(hour_timestamp)
                ORDER BY day DESC
                LIMIT ?
            ''', (days,))

        rows = cursor.fetchall()
        conn.close()
        data = [
            {
                'hour': row['day'],
                'requests': row['request_count'],
                'status_success': row['status_success'],
                'status_redirects': row['status_redirects'],
                'status_client_errors': row['status_client_errors'],
                'status_server_errors': row['status_server_errors'],
                'unique_ips': row['unique_ips']
            }
            for row in reversed(rows)
        ]
    else:
        cursor.execute('''
            SELECT * FROM access_logs_hourly
            ORDER BY hour_timestamp DESC
            LIMIT ?
        ''', (hours,))
        rows = cursor.fetchall()
        conn.close()
        data = [
            {
                'hour': row['hour_timestamp'],
                'requests': row['request_count'],
                'status_success': row['status_success'],
                'status_redirects': row['status_redirects'],
                'status_client_errors': row['status_client_errors'],
                'status_server_errors': row['status_server_errors'],
                'unique_ips': row['unique_ips']
            }
            for row in reversed(rows)
        ]

    return data, 'daily' if use_daily else 'hourly'
