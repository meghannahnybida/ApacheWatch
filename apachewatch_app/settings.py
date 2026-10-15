"""Validated, persistent overrides for the alert thresholds."""

import math
import sqlite3
from pathlib import Path

THRESHOLD_LIMITS = {
    "disk_percent": (1, 100, False),
    "server_errors_5xx": (1, 1000000000, True),
    "client_errors_4xx": (1, 1000000000, True),
    "requests_per_ip": (1, 1000000000, True),
    "bot_percentage": (0, 100, False),
}


def get_thresholds(config_data):
    values = dict(config_data.get("alerts", {}).get("thresholds", {}))
    database = config_data.get("database")
    if database and Path(database).exists():
        with sqlite3.connect(database, timeout=15) as conn:
            if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='alert_thresholds'").fetchone():
                values.update(conn.execute("SELECT name, value FROM alert_thresholds"))
    return values


def save_thresholds(config_data, values):
    if not isinstance(values, dict) or not values:
        raise ValueError("Provide at least one alert threshold.")
    for name, value in values.items():
        if name not in THRESHOLD_LIMITS:
            raise ValueError("Unknown alert threshold.")
        minimum, maximum, integer = THRESHOLD_LIMITS[name]
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or not minimum <= value <= maximum or not math.isfinite(value)
                or (integer and value != int(value))):
            raise ValueError(f"{name} must be {'a whole number' if integer else 'a number'} between {minimum} and {maximum}.")
    Path(config_data["database"]).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(config_data["database"], timeout=15) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS alert_thresholds (name TEXT PRIMARY KEY, value REAL NOT NULL)")
        conn.executemany(
            "INSERT INTO alert_thresholds(name, value) VALUES (?, ?) "
            "ON CONFLICT(name) DO UPDATE SET value = excluded.value", values.items(),
        )
