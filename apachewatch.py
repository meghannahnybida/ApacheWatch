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

def parse_error_log(log_path, max_lines=100):
    """Parse recent entries from Apache error log."""
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

# =============================================================================
# FLASK APP
# =============================================================================

app = Flask(__name__)
config = load_config()

@app.route("/")
def dashboard():
    """Render the dashboard."""
    metrics = collect_metrics()
    logs = parse_error_log(config["apache"]["error_log"])
    
    # Save metrics snapshot
    add_metrics_snapshot(config["database"], metrics)
    
    return render_template(
        "dashboard.html",
        server_name=config["server_name"],
        metrics=metrics,
        logs=logs
    )

@app.route("/api/metrics")
def api_metrics():
    """Get current metrics as JSON."""
    return jsonify(collect_metrics())

@app.route("/api/logs")
def api_logs():
    """Get recent log entries as JSON."""
    return jsonify(parse_error_log(config["apache"]["error_log"]))

@app.route("/api/history")
def api_history():
    """Get metrics history."""
    history = get_metrics_history(config["database"], limit=1000)
    return jsonify({
        "metrics_history": history,
        "count": len(history)
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
