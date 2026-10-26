"""Finding activity recorded in the same transaction as workflow changes."""

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone


def _utc_timestamp(value):
    timestamp = datetime.fromisoformat(value) if isinstance(value, str) else value
    return timestamp.astimezone(timezone.utc).isoformat()


def record_activity(conn, item_id, event_type, occurred_at, **details):
    timestamp = _utc_timestamp(occurred_at)
    for key in ('snoozed_until', 'previous_review_time'):
        if details.get(key):
            details[key] = _utc_timestamp(details[key])
    conn.execute('''
        INSERT INTO action_item_activity (item_id, event_type, occurred_at, details_json)
        VALUES (?, ?, ?, ?)
    ''', (item_id, event_type, timestamp, json.dumps(details)))


def get_action_activity(db_path, item_id, limit=10, before=None):
    """Return newest-first events; an ID cursor keeps older pages stable."""
    # The schema initializer uses record_activity for legacy finding snapshots.
    from .database import init_database

    limit = min(max(int(limit), 1), 100)
    if before is not None:
        before = int(before)
        if not 0 < before <= 9223372036854775807:
            raise ValueError('before must be a valid positive event ID')
    if not 0 < item_id <= 9223372036854775807:
        return None
    init_database(db_path)
    with closing(sqlite3.connect(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        if not conn.execute('SELECT 1 FROM action_items WHERE id = ?', (item_id,)).fetchone():
            return None
        params = [item_id]
        condition = ''
        if before is not None:
            condition = 'AND id < ?'
            params.append(int(before))
        params.append(limit + 1)
        rows = conn.execute(f'''
            SELECT id, event_type, occurred_at, details_json
            FROM action_item_activity WHERE item_id = ? {condition}
            ORDER BY id DESC LIMIT ?
        ''', params).fetchall()
        total = conn.execute('SELECT COUNT(*) FROM action_item_activity WHERE item_id = ?', (item_id,)).fetchone()[0]
    events = []
    for row in rows[:limit]:
        event = dict(row)
        try:
            details = json.loads(event.pop('details_json'))
            event['details'] = details if isinstance(details, dict) else {}
        except (TypeError, json.JSONDecodeError):
            event['details'] = {}
        events.append(event)
    return {'item_id': item_id, 'events': events, 'count': len(events), 'total': total,
            'next_before': events[-1]['id'] if len(rows) > limit else None}
