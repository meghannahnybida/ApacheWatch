"""Named log views stored alongside the server's other persistent settings."""

import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path

from .log_search import _filters

MAX_VIEWS = 50
SCHEMA = '''CREATE TABLE IF NOT EXISTS saved_log_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    name_key TEXT NOT NULL UNIQUE,
    state_json TEXT NOT NULL
)'''
FIELDS = {'source', 'format', 'limit', 'q', 'ip', 'url', 'from', 'to', 'level', 'status'}


class LogViewConflict(ValueError):
    """A duplicate name or the saved-view limit prevents this change."""


def _validate(payload):
    if not isinstance(payload, dict) or set(payload) != {'name', 'state'}:
        raise ValueError('Provide a view name and its current filters.')
    name = payload['name']
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
        raise ValueError('Choose a view name between 1 and 80 characters.')
    name = name.strip()
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise ValueError('Use a single line for the view name.')
    values = payload['state']
    if not isinstance(values, dict) or set(values) - FIELDS:
        raise ValueError('Provide valid log view filters.')
    state = {'source': 'error', 'format': 'formatted', 'limit': 20,
             **{key: '' for key in ('q', 'ip', 'url', 'from', 'to', 'level')},
             'status': 'all', **values}
    if not isinstance(state['source'], str) or state['source'] not in {'error', 'access'}:
        raise ValueError('Choose the error or access log.')
    if not isinstance(state['format'], str) or state['format'] not in {'formatted', 'terminal'}:
        raise ValueError('Choose Formatted or Terminal.')
    if type(state['limit']) is not int or state['limit'] not in {10, 20, 50, 100, 500}:
        raise ValueError('Choose 10, 20, 50, 100, or 500 lines.')
    if state['format'] == 'formatted' and state['limit'] > 100:
        raise ValueError('Formatted views support up to 100 lines.')
    for key in ('q', 'ip', 'url', 'from', 'to', 'level', 'status'):
        if not isinstance(state[key], str):
            raise ValueError('Log view filters must be text.')
        state[key] = state[key].strip()
    if state['level'] not in {'', 'errors', 'warn', 'information', 'diagnostics'}:
        raise ValueError('Choose a level from the log viewer.')
    # Share validation with search, including IPs, date order, and source-specific filters.
    _filters(state, state['source'])
    for key in ('from', 'to'):
        if state[key] and not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?', state[key]):
            raise ValueError('Use a local date and time for saved date filters, such as 2026-11-08T10:00.')
    state['status'] = state['status'] or 'all'
    return name, state


def _view(row):
    return {'id': row[0], 'name': row[1], 'state': json.loads(row[2])}


def get_log_views(db_path):
    if not Path(db_path).exists():
        return []
    with closing(sqlite3.connect(db_path, timeout=15)) as conn:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='saved_log_views'").fetchone():
            return []
        return [_view(row) for row in conn.execute(
            'SELECT id, name, state_json FROM saved_log_views ORDER BY name_key, id')]


def save_log_view(db_path, payload, view_id=None):
    name, state = _validate(payload)
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    try:
        with closing(sqlite3.connect(db_path, timeout=15)) as conn, conn:
            conn.execute('BEGIN IMMEDIATE')
            conn.execute(SCHEMA)
            if view_id is None:
                if conn.execute('SELECT COUNT(*) FROM saved_log_views').fetchone()[0] >= MAX_VIEWS:
                    raise LogViewConflict('You can save up to 50 views. Delete one before adding another.')
                cursor = conn.execute(
                    'INSERT INTO saved_log_views(name, name_key, state_json) VALUES (?, ?, ?)',
                    (name, name.casefold(), json.dumps(state)),
                )
                view_id = cursor.lastrowid
            else:
                cursor = conn.execute(
                    'UPDATE saved_log_views SET name = ?, name_key = ?, state_json = ? WHERE id = ?',
                    (name, name.casefold(), json.dumps(state), view_id),
                )
                if not cursor.rowcount:
                    raise LookupError('This saved view no longer exists. Reload the saved views.')
    except sqlite3.IntegrityError:
        raise LogViewConflict('A view with this name already exists. Choose another name or edit that view.') from None
    return {'id': view_id, 'name': name, 'state': state}


def delete_log_view(db_path, view_id):
    if not Path(db_path).exists():
        raise LookupError('This saved view no longer exists. Reload the saved views.')
    with closing(sqlite3.connect(db_path, timeout=15)) as conn, conn:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='saved_log_views'").fetchone():
            raise LookupError('This saved view no longer exists. Reload the saved views.')
        if not conn.execute('DELETE FROM saved_log_views WHERE id = ?', (view_id,)).rowcount:
            raise LookupError('This saved view no longer exists. Reload the saved views.')
