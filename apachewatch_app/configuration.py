"""Configuration loading and defaults."""

import os
import yaml


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


DEFAULT_SECURITY_CONFIG = {
    "allowlist": ["127.0.0.0/8", "::1/128"],
    "minimum_score": 35,
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

    config_data.setdefault("security", {})
    config_data["security"].setdefault("allowlist", DEFAULT_SECURITY_CONFIG["allowlist"].copy())
    config_data["security"].setdefault("minimum_score", DEFAULT_SECURITY_CONFIG["minimum_score"])

    config_data.setdefault("monitoring", {})
    config_data["monitoring"].setdefault("enabled", True)
    config_data["monitoring"].setdefault("interval_seconds", 60)
    config_data.setdefault("notifications", {})
    config_data["notifications"].setdefault("email", {})
    email = config_data["notifications"]["email"]
    email.setdefault("enabled", False)
    email.setdefault("recipients", [])
    email.setdefault("severity", "critical")
    email.setdefault("smtp", {})

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
