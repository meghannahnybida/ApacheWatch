#!/usr/bin/env python3
"""
ApacheWatch - Simple server monitoring and log analysis tool.
A minimal, easy-to-understand implementation.
"""

import os
import re
import sqlite3
import psutil
import yaml
from datetime import datetime
from pathlib import Path
from flask import Flask, jsonify, render_template

# =============================================================================
# CONFIGURATION
# =============================================================================

def load_config(config_path="config.yaml"):
    """Load configuration from YAML file."""
    if os.path.exists(config_path):
        with open(config_path) as f:
            return yaml.safe_load(f)
    # Default config if file doesn't exist
    return {
        "server_name": "my-server",
        "apache": {
            "error_log": "/var/log/apache2/error.log",
            "access_log": "/var/log/apache2/access.log"
        },
        "database": "./data/apachewatch.db",
        "web": {"host": "0.0.0.0", "port": 8080}
    }

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
        with open(log_path, 'r') as f:
            lines = f.readlines()[-max_lines:]  # Get last N lines
        
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
        with open(log_path, 'r') as f:
            lines = f.readlines()[-max_lines:]
        
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
        pass  # Silently fail if we can't read the file
    except Exception as e:
        pass  # Silently fail on parsing errors
    
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
            "unique_visitors": 0
        }
    
    # Count IPs
    ip_counter = Counter(entry["ip"] for entry in entries)
    
    # Count pages/endpoints
    page_counter = Counter(entry["path"] for entry in entries)
    
    # Count status codes
    status_counter = Counter(entry["status"] for entry in entries)
    
    # Get top IPs with request counts
    top_ips = [
        {"ip": ip, "requests": count}
        for ip, count in ip_counter.most_common(10)
    ]
    
    # Get top pages with request counts
    top_pages = [
        {"path": path, "requests": count}
        for path, count in page_counter.most_common(10)
    ]
    
    # Convert status codes to dict
    status_codes = dict(status_counter)
    
    return {
        "top_ips": top_ips,
        "top_pages": top_pages,
        "status_codes": status_codes,
        "total_requests": len(entries),
        "unique_visitors": len(ip_counter)
    }

# =============================================================================
# DATA STORAGE (SQLite Database)
# =============================================================================

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
    
    conn.commit()
    conn.close()

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
    """Get traffic data for charts."""
    init_database(db_path)
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get last N hours of data
    cursor.execute('''
        SELECT * FROM access_logs_hourly
        ORDER BY hour_timestamp DESC
        LIMIT ?
    ''', (hours,))
    
    rows = cursor.fetchall()
    conn.close()
    
    # Convert to list and reverse to get chronological order
    data = []
    for row in reversed(rows):
        data.append({
            'hour': row['hour_timestamp'],
            'requests': row['request_count'],
            'status_success': row['status_success'],
            'status_redirects': row['status_redirects'],
            'status_client_errors': row['status_client_errors'],
            'status_server_errors': row['status_server_errors'],
            'unique_ips': row['unique_ips']
        })
    
    return data

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
    
    return render_template(
        "dashboard.html",
        server_name=config["server_name"],
        metrics=metrics,
        logs=logs,
        current_filter=level_filter
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
    
    return jsonify(stats)

@app.route("/api/traffic-chart")
def api_traffic_chart():
    """Get traffic data for charts."""
    from flask import request
    
    hours = int(request.args.get('hours', 24))
    data = get_traffic_chart_data(config["database"], hours=hours)
    
    return jsonify({
        'data': data,
        'count': len(data)
    })

# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print(f"Starting ApacheWatch...")
    print(f"Server: {config['server_name']}")
    print(f"Dashboard: http://{config['web']['host']}:{config['web']['port']}")
    print(f"Error log: {config['apache']['error_log']}")
    
    app.run(
        host=config["web"]["host"],
        port=config["web"]["port"],
        debug=True
    )
