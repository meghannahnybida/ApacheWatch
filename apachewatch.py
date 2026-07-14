#!/usr/bin/env python3
"""
ApacheWatch - Simple server monitoring and log analysis tool.
A minimal, easy-to-understand implementation.
"""

import os
import re
import sqlite3
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
import psutil
import yaml
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, jsonify, render_template

# Import IP analysis module
try:
    from ip_analyzer import analyze_ip_visitor
    IP_ANALYSIS_AVAILABLE = True
except ImportError:
    IP_ANALYSIS_AVAILABLE = False
    print("Warning: IP analysis module not available")

# =============================================================================
# CONFIGURATION
# =============================================================================

DEFAULT_ALERTS_CONFIG = {
    "enabled": True,
    "cooldown_minutes": 30,
    "thresholds": {
        "disk_percent": 85,
        "server_errors_5xx": 5,
        "client_errors_4xx": 50,
        "requests_per_ip": 100,
        "bot_percentage": 75
    }
}

def apply_config_defaults(config_data):
    """Apply defaults for optional config sections."""
    if not config_data:
        config_data = {}

    config_data.setdefault("server_name", "my-server")
    config_data.setdefault("apache", {})
    config_data["apache"].setdefault("error_log", "/var/log/apache2/error.log")
    config_data["apache"].setdefault("access_log", "/var/log/apache2/access.log")
    config_data.setdefault("database", "./data/apachewatch.db")
    config_data.setdefault("web", {})
    config_data["web"].setdefault("host", "0.0.0.0")
    config_data["web"].setdefault("port", 8080)

    config_data.setdefault("alerts", {})
    config_data["alerts"].setdefault("enabled", DEFAULT_ALERTS_CONFIG["enabled"])
    config_data["alerts"].setdefault("cooldown_minutes", DEFAULT_ALERTS_CONFIG["cooldown_minutes"])
    config_data["alerts"].setdefault("thresholds", {})
    for name, value in DEFAULT_ALERTS_CONFIG["thresholds"].items():
        config_data["alerts"]["thresholds"].setdefault(name, value)

    return config_data

def load_config(config_path="config.yaml"):
    """Load configuration from YAML file."""
    if os.path.exists(config_path):
        with open(config_path) as f:
            return apply_config_defaults(yaml.safe_load(f))
    # Default config if file doesn't exist
    return apply_config_defaults({
        "server_name": "my-server",
        "apache": {
            "error_log": "/var/log/apache2/error.log",
            "access_log": "/var/log/apache2/access.log"
        },
        "database": "./data/apachewatch.db",
        "web": {"host": "0.0.0.0", "port": 8080}
    })

# =============================================================================
# METRICS COLLECTION
# =============================================================================

def collect_metrics():
    """Collect current system metrics."""
    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    return {
        "timestamp": datetime.now().isoformat(),
        "cpu_percent": cpu_percent,
        "memory": {
            "percent": memory.percent,
            "used_gb": round(memory.used / (1024**3), 2),
            "total_gb": round(memory.total / (1024**3), 2)
        },
        "disk": {
            "percent": disk.percent,
            "used_gb": round(disk.used / (1024**3), 2),
            "total_gb": round(disk.total / (1024**3), 2)
        }
    }

# =============================================================================
# LOG PARSING
# =============================================================================

def _tail_file(log_path, max_lines):
    """Read the last max_lines lines from a file without loading it into memory.

    Seeks backwards from the end of the file in 8KB chunks, so a 2GB log file
    costs the same as a 10KB one as long as max_lines is small.
    """
    with open(log_path, 'rb') as f:
        f.seek(0, 2)  # Seek to end
        size = f.tell()
        if size == 0:
            return []

        block_size = 8192
        blocks = []
        remaining = size
        newlines_seen = 0

        while remaining > 0 and newlines_seen <= max_lines:
            read_size = min(block_size, remaining)
            remaining -= read_size
            f.seek(remaining)
            block = f.read(read_size)
            blocks.insert(0, block)
            newlines_seen += block.count(b'\n')

        content = b''.join(blocks)
        lines = content.split(b'\n')
        # A trailing newline produces a spurious empty final entry — remove it
        if lines and not lines[-1]:
            lines = lines[:-1]
        return [line.decode('utf-8', errors='replace') for line in lines[-max_lines:]]


def parse_error_log(log_path, max_lines=100, level_filter=None):
    """Parse recent entries from Apache error log.

    Args:
        log_path: Path to the Apache error log file
        max_lines: Maximum number of lines to read from the end of the file
        level_filter: Optional log level to filter by ('error', 'warn', 'info', etc.)
    """
    entries = []

    if not os.path.exists(log_path):
        return entries

    try:
        lines = _tail_file(log_path, max_lines)

        # Pattern for Apache error log
        pattern = r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.+)'

        for line in lines:
            line = line.strip()
            if not line:
                continue

            match = re.match(pattern, line)
            if match:
                timestamp_str, level_info, message = match.groups()
                # Extract just the level (e.g., "error" from "core:error")
                level = level_info.split(":")[-1] if ":" in level_info else level_info

                entries.append({
                    "timestamp": timestamp_str,
                    "level": level,
                    "message": message[:200]  # Truncate long messages
                })
            else:
                # Line didn't match pattern, store as-is
                entries.append({
                    "timestamp": "",
                    "level": "unknown",
                    "message": line[:200]
                })

        # Apply level filter if specified
        if level_filter:
            entries = [e for e in entries if e['level'].lower() == level_filter.lower()]

    except PermissionError:
        entries.append({
            "timestamp": datetime.now().isoformat(),
            "level": "error",
            "message": f"Permission denied reading {log_path}"
        })
    except Exception as e:
        entries.append({
            "timestamp": datetime.now().isoformat(),
            "level": "error",
            "message": f"Error reading log: {str(e)}"
        })

    return entries

def parse_access_log(log_path, max_lines=1000):
    """Parse Apache access log entries.

    Args:
        log_path: Path to the Apache access log file
        max_lines: Maximum number of lines to read from the end of the file

    Returns:
        List of dictionaries containing parsed log entries
    """
    entries = []

    if not os.path.exists(log_path):
        return entries

    try:
        lines = _tail_file(log_path, max_lines)

        # Apache common/combined log format pattern
        # IP - user [timestamp] "method path protocol" status size "referer" "user-agent"
        pattern = r'^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\S+)\s*"?([^"]*)"?\s*"?([^"]*)"?'

        for line in lines:
            line = line.strip()
            if not line:
                continue

            match = re.match(pattern, line)
            if match:
                ip, user, timestamp, method, path, protocol, status, size, referer, user_agent = match.groups()

                entries.append({
                    "ip": ip,
                    "user": user if user != "-" else None,
                    "timestamp": timestamp,
                    "method": method,
                    "path": path,
                    "protocol": protocol,
                    "status": int(status),
                    "size": int(size) if size.isdigit() else 0,
                    "referer": referer if referer and referer != "-" else None,
                    "user_agent": user_agent if user_agent else None
                })

    except PermissionError:
        print(f"WARNING: Permission denied reading access log: {log_path}", flush=True)
        print("  Try running with sudo, or add your user to the 'adm' group.", flush=True)
    except Exception as e:
        print(f"WARNING: Could not parse access log {log_path}: {e}", flush=True)

    return entries

def analyze_access_logs(entries):
    """Analyze access log entries to generate statistics.

    Args:
        entries: List of parsed access log entries

    Returns:
        Dictionary containing analytics data
    """
    from collections import Counter

    if not entries:
        return {
            "top_ips": [],
            "top_pages": [],
            "status_codes": {},
            "total_requests": 0,
            "unique_visitors": 0,
            "bot_stats": {
                "total_bots": 0,
                "total_humans": 0,
                "bot_percentage": 0
            }
        }

    # Count IPs
    ip_counter = Counter(entry["ip"] for entry in entries)

    # Enhanced IP analysis with hostname and bot detection
    enriched_ips = []
    bot_count = 0
    human_count = 0

    if IP_ANALYSIS_AVAILABLE:
        # Pre-collect one user agent per unique IP to avoid scanning entries repeatedly
        ip_user_agents = {}
        for entry in entries:
            ip = entry["ip"]
            if ip not in ip_user_agents and entry.get("user_agent"):
                ip_user_agents[ip] = entry["user_agent"]

        top_ip_list = ip_counter.most_common(20)

        def _analyze_ip(ip_count):
            ip, count = ip_count
            result = analyze_ip_visitor(ip, ip_user_agents.get(ip))
            result["requests"] = count
            return result

        # Run all DNS lookups in parallel (max 4 seconds total) instead of
        # sequentially (up to 2s × 20 IPs = 40s worst case)
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_map = {executor.submit(_analyze_ip, pair): pair[0] for pair in top_ip_list}
            try:
                for future in as_completed(future_map, timeout=4):
                    try:
                        enriched_ips.append(future.result())
                    except Exception:
                        pass
            except concurrent.futures.TimeoutError:
                # Collect whatever finished within the time limit
                for future in future_map:
                    if future.done():
                        try:
                            enriched_ips.append(future.result())
                        except Exception:
                            pass

        for analysis in enriched_ips:
            ip = analysis.get("ip", "")
            if analysis.get("is_bot"):
                bot_count += sum(1 for e in entries if e["ip"] == ip)
            elif analysis.get("is_bot") is False:
                human_count += sum(1 for e in entries if e["ip"] == ip)
    else:
        # Fallback without IP analysis
        enriched_ips = [
            {"ip": ip, "requests": count}
            for ip, count in ip_counter.most_common(10)
        ]

    # Count pages/endpoints
    page_counter = Counter(entry["path"] for entry in entries)

    # Count status codes
    status_counter = Counter(entry["status"] for entry in entries)

    # Get top pages with request counts
    top_pages = [
        {"path": path, "requests": count}
        for path, count in page_counter.most_common(10)
    ]

    # Convert status codes to dict
    status_codes = dict(status_counter)

    # Calculate bot percentage
    total_requests = len(entries)
    bot_percentage = round((bot_count / total_requests * 100), 1) if total_requests > 0 else 0

    return {
        "top_ips": enriched_ips[:10],  # Return top 10
        "top_pages": top_pages,
        "status_codes": status_codes,
        "total_requests": total_requests,
        "unique_visitors": len(ip_counter),
        "bot_stats": {
            "total_bots": bot_count,
            "total_humans": human_count,
            "bot_percentage": bot_percentage
        }
    }

# =============================================================================
# DATA STORAGE (SQLite Database)
# =============================================================================

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

def init_database(db_path):
    """Initialize the SQLite database and create tables if they don't exist."""
    # Ensure directory exists
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create metrics table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            cpu_percent REAL,
            memory_percent REAL,
            memory_used_gb REAL,
            memory_total_gb REAL,
            disk_percent REAL,
            disk_used_gb REAL,
            disk_total_gb REAL
        )
    ''')

    # Create index on timestamp for faster queries
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_timestamp ON metrics(timestamp)
    ''')

    # Create access_logs aggregates table for traffic charts
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_logs_hourly (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hour_timestamp TEXT NOT NULL UNIQUE,
            request_count INTEGER DEFAULT 0,
            status_success INTEGER DEFAULT 0,
            status_redirects INTEGER DEFAULT 0,
            status_client_errors INTEGER DEFAULT 0,
            status_server_errors INTEGER DEFAULT 0,
            unique_ips INTEGER DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_hour_timestamp ON access_logs_hourly(hour_timestamp)
    ''')

    # Create alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            message TEXT NOT NULL,
            value REAL,
            threshold REAL
        )
    ''')

    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)
    ''')

    conn.commit()
    conn.close()

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

def evaluate_and_save_current_alerts(metrics=None, access_stats=None):
    """Evaluate current alert state and save any new alert rows."""
    if metrics is None:
        metrics = collect_metrics()

    if access_stats is None:
        access_entries = parse_access_log(config["apache"].get("access_log", ""), max_lines=1000)
        access_stats = analyze_access_logs(access_entries)

    alerts = evaluate_alerts(metrics, access_stats, config)
    cooldown_minutes = config.get("alerts", {}).get("cooldown_minutes", 30)
    save_alerts(config["database"], alerts, cooldown_minutes=cooldown_minutes)
    return alerts

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
    from collections import defaultdict
    from datetime import datetime

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

# =============================================================================
# FLASK APP
# =============================================================================

app = Flask(__name__)
config = load_config()

@app.route("/")
def dashboard():
    """Render the dashboard."""
    from flask import request

    metrics = collect_metrics()
    level_filter = request.args.get('level')  # Get level filter from query params
    limit = int(request.args.get('limit', 20))  # Get limit from query params, default 20
    logs = parse_error_log(config["apache"]["error_log"], max_lines=100, level_filter=level_filter)[-limit:]

    # Save metrics snapshot
    add_metrics_snapshot(config["database"], metrics)

    # Aggregate access logs for traffic charts
    if config["apache"].get("access_log"):
        aggregate_access_logs(config["database"], config["apache"]["access_log"])

    evaluate_and_save_current_alerts(metrics=metrics)
    recent_alerts = get_recent_alerts(config["database"], limit=5)

    return render_template(
        "dashboard.html",
        server_name=config["server_name"],
        metrics=metrics,
        logs=logs,
        current_filter=level_filter,
        recent_alerts=recent_alerts
    )

@app.route("/api/metrics")
def api_metrics():
    """Get current metrics as JSON."""
    return jsonify(collect_metrics())

@app.route("/api/logs")
def api_logs():
    """Get recent log entries as JSON."""
    from flask import request

    level_filter = request.args.get('level')  # Get level filter from query params
    limit = int(request.args.get('limit', 100))  # Get limit from query params, default 100
    # Read more lines than limit to ensure enough entries after filtering
    logs = parse_error_log(config["apache"]["error_log"], max_lines=max(limit * 2, 100), level_filter=level_filter)
    return jsonify(logs[-limit:])

@app.route("/api/history")
def api_history():
    """Get metrics history."""
    history = get_metrics_history(config["database"], limit=1000)
    return jsonify({
        "metrics_history": history,
        "count": len(history)
    })

@app.route("/api/access-stats")
def api_access_stats():
    """Get access log analytics."""
    # Parse access log
    entries = parse_access_log(config["apache"].get("access_log", ""), max_lines=1000)

    # Analyze the entries
    stats = analyze_access_logs(entries)
    evaluate_and_save_current_alerts(access_stats=stats)

    return jsonify(stats)

@app.route("/api/alerts")
def api_alerts():
    """Get recent alerts as JSON."""
    evaluate_and_save_current_alerts()
    alerts = get_recent_alerts(config["database"], limit=50)

    return jsonify({
        "alerts": alerts,
        "count": len(alerts)
    })

@app.route("/api/traffic-chart")
def api_traffic_chart():
    """Get traffic data for charts."""
    from flask import request

    hours = int(request.args.get('hours', 24))
    data, resolution = get_traffic_chart_data(config["database"], hours=hours)

    return jsonify({
        'data': data,
        'resolution': resolution,
        'count': len(data)
    })

# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
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

    app.run(
        host=config["web"]["host"],
        port=config["web"]["port"],
        debug=True
    )
