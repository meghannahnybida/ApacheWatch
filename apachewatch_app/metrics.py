"""System metrics and Apache source health."""

import os
from datetime import datetime
import psutil


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


def collect_monitoring_health(config_data):
    """Describe Apache process visibility and configured log-source availability."""
    containerized = os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")
    apache_processes = []
    process_names = {"apache2", "httpd", "httpd-prefork", "httpd-worker", "httpd-event"}
    try:
        for process in psutil.process_iter(["pid", "name", "create_time"]):
            try:
                name = (process.info.get("name") or "").lower()
                if name in process_names:
                    apache_processes.append({
                        "pid": process.info.get("pid"),
                        "name": process.info.get("name"),
                        "create_time": process.info.get("create_time"),
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except (psutil.Error, OSError):
        apache_processes = []

    started_at = None
    uptime_seconds = None
    start_times = [item["create_time"] for item in apache_processes if item.get("create_time")]
    if start_times:
        oldest_start = min(start_times)
        started_at = datetime.fromtimestamp(oldest_start).isoformat()
        uptime_seconds = max(0, int(datetime.now().timestamp() - oldest_start))

    def log_health(label, path):
        result = {
            "label": label,
            "path": path or None,
            "configured": bool(path),
            "exists": False,
            "readable": False,
            "size_bytes": None,
            "modified_at": None,
            "age_seconds": None,
            "status": "not_configured",
        }
        if not path:
            return result
        if not os.path.exists(path):
            result["status"] = "missing"
            return result

        result["exists"] = True
        result["readable"] = os.access(path, os.R_OK)
        result["status"] = "ready" if result["readable"] else "unreadable"
        try:
            modified = os.path.getmtime(path)
            result["size_bytes"] = os.path.getsize(path)
            result["modified_at"] = datetime.fromtimestamp(modified).isoformat()
            result["age_seconds"] = max(0, int(datetime.now().timestamp() - modified))
        except OSError:
            pass
        return result

    apache_config = config_data.get("apache", {})
    return {
        "apache": {
            "detected": bool(apache_processes),
            "process_count": len(apache_processes),
            "started_at": started_at,
            "uptime_seconds": uptime_seconds,
            "status": "detected" if apache_processes else "not_detected",
            "containerized": containerized,
        },
        "logs": [
            log_health("Error log", apache_config.get("error_log", "")),
            log_health("Access log", apache_config.get("access_log", "")),
        ],
        "checked_at": datetime.now().isoformat(),
    }
