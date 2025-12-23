#!/usr/bin/env python3
"""
ApacheWatch - Simple server monitoring and log analysis tool.
A minimal, easy-to-understand implementation.
"""

import os
import re
import json
import psutil
import yaml
from datetime import datetime
from pathlib import Path
from flask import Flask, jsonify, render_template_string

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
        "data_file": "./data/apachewatch.json",
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
# DATA STORAGE (Simple JSON file)
# =============================================================================

def load_data(data_file):
    """Load stored data from JSON file."""
    if os.path.exists(data_file):
        with open(data_file) as f:
            return json.load(f)
    return {"metrics_history": [], "last_updated": None}

def save_data(data_file, data):
    """Save data to JSON file."""
    # Ensure directory exists
    Path(data_file).parent.mkdir(parents=True, exist_ok=True)
    with open(data_file, 'w') as f:
        json.dump(data, f, indent=2)

def add_metrics_snapshot(data_file, metrics, max_history=1000):
    """Add a metrics snapshot to history."""
    data = load_data(data_file)
    data["metrics_history"].append(metrics)
    # Keep only last N entries
    data["metrics_history"] = data["metrics_history"][-max_history:]
    data["last_updated"] = datetime.now().isoformat()
    save_data(data_file, data)

# =============================================================================
# WEB DASHBOARD
# =============================================================================

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>ApacheWatch</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; padding: 20px; }
        h1 { color: #333; margin-bottom: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .card h2 { font-size: 14px; color: #666; margin-bottom: 10px; }
        .card .value { font-size: 36px; font-weight: bold; color: #333; }
        .card .sub { font-size: 12px; color: #999; margin-top: 5px; }
        .bar { height: 8px; background: #eee; border-radius: 4px; margin-top: 10px; overflow: hidden; }
        .bar-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
        .bar-fill.good { background: #10b981; }
        .bar-fill.warn { background: #f59e0b; }
        .bar-fill.bad { background: #ef4444; }
        .logs { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .logs h2 { margin-bottom: 15px; }
        .log-entry { padding: 8px; border-bottom: 1px solid #eee; font-family: monospace; font-size: 12px; }
        .log-entry:last-child { border-bottom: none; }
        .log-entry .level { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 10px; margin-right: 8px; }
        .level-error { background: #fee2e2; color: #dc2626; }
        .level-warn { background: #fef3c7; color: #d97706; }
        .level-info { background: #dbeafe; color: #2563eb; }
        .level-notice { background: #e0e7ff; color: #4f46e5; }
        .refresh-note { text-align: center; color: #999; font-size: 12px; margin-top: 20px; }
    </style>
</head>
<body>
    <h1>🖥️ ApacheWatch - {{ server_name }}</h1>
    
    <div class="grid">
        <div class="card">
            <h2>CPU Usage</h2>
            <div class="value">{{ metrics.cpu_percent }}%</div>
            <div class="bar"><div class="bar-fill {{ 'bad' if metrics.cpu_percent > 90 else 'warn' if metrics.cpu_percent > 70 else 'good' }}" style="width: {{ metrics.cpu_percent }}%"></div></div>
        </div>
        
        <div class="card">
            <h2>Memory Usage</h2>
            <div class="value">{{ metrics.memory.percent }}%</div>
            <div class="sub">{{ metrics.memory.used_gb }} GB / {{ metrics.memory.total_gb }} GB</div>
            <div class="bar"><div class="bar-fill {{ 'bad' if metrics.memory.percent > 90 else 'warn' if metrics.memory.percent > 70 else 'good' }}" style="width: {{ metrics.memory.percent }}%"></div></div>
        </div>
        
        <div class="card">
            <h2>Disk Usage</h2>
            <div class="value">{{ metrics.disk.percent }}%</div>
            <div class="sub">{{ metrics.disk.used_gb }} GB / {{ metrics.disk.total_gb }} GB</div>
            <div class="bar"><div class="bar-fill {{ 'bad' if metrics.disk.percent > 90 else 'warn' if metrics.disk.percent > 70 else 'good' }}" style="width: {{ metrics.disk.percent }}%"></div></div>
        </div>
    </div>
    
    <div class="logs">
        <h2>Recent Log Entries</h2>
        {% for entry in logs[-20:]|reverse %}
        <div class="log-entry">
            <span class="level level-{{ entry.level }}">{{ entry.level.upper() }}</span>
            {{ entry.message }}
        </div>
        {% else %}
        <div class="log-entry">No log entries found or unable to read log file.</div>
        {% endfor %}
    </div>
    
    <p class="refresh-note">Last updated: {{ metrics.timestamp }} | Refresh page to update</p>
</body>
</html>
"""

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
    add_metrics_snapshot(config["data_file"], metrics)
    
    return render_template_string(
        DASHBOARD_HTML,
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
    data = load_data(config["data_file"])
    return jsonify(data)

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
