"""SQLite schema initialization shared by the storage modules."""

import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path
import notifications
from .activity import record_activity
from .log_views import SCHEMA as LOG_VIEWS_SCHEMA


def init_database(db_path):
    """Initialize the SQLite database and create tables if they don't exist."""
    # Ensure directory exists
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    with closing(sqlite3.connect(db_path)) as conn, conn:
        cursor = conn.cursor()
        cursor.execute('BEGIN IMMEDIATE')
        cursor.execute(LOG_VIEWS_SCHEMA)

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

        # Durable workflow state for alerts, error incidents, and traffic threats.
        # The source_key remains stable when the same finding is observed again,
        # allowing evidence to refresh without losing an operator's decision.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS action_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                source_key TEXT NOT NULL UNIQUE,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                evidence_json TEXT NOT NULL DEFAULT '{}',
                related_view TEXT,
                related_query TEXT,
                status TEXT NOT NULL DEFAULT 'new',
                note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                snoozed_until TEXT,
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                currently_observed INTEGER NOT NULL DEFAULT 1
            )
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_action_items_status
            ON action_items(status, updated_at)
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS action_item_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id INTEGER NOT NULL REFERENCES action_items(id) ON DELETE CASCADE,
                event_type TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}'
            )
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_action_activity_item
            ON action_item_activity(item_id, id DESC)
        ''')
        cursor.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS idx_action_activity_first_seen
            ON action_item_activity(item_id) WHERE event_type = 'first_seen'
        ''')
        # Only the first-seen date and current state are known for older findings.
        # Preserve those facts without inventing earlier note or status changes.
        legacy = cursor.execute('''
            SELECT id, created_at, status, note, snoozed_until FROM action_items AS item
            WHERE NOT EXISTS (
                SELECT 1 FROM action_item_activity
                WHERE item_id = item.id AND event_type = 'first_seen'
            )
        ''').fetchall()
        tracking_started = datetime.now()
        for item_id, created_at, status, note, snoozed_until in legacy:
            record_activity(conn, item_id, 'first_seen', created_at)
            record_activity(conn, item_id, 'tracking_started', tracking_started,
                            status=status, note=note, snoozed_until=snoozed_until)

    notifications.init_notification_storage(db_path)
