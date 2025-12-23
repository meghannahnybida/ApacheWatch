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
