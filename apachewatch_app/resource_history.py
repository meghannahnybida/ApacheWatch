"""Bounded resource charts aggregated from all readings in a selected time range."""

import math
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

from .database import init_database


RESOURCES = {'cpu': 'cpu_percent', 'memory': 'memory_percent', 'disk': 'disk_percent'}
INTERVALS = {'1': 60, '24': 300, '168': 1800, '720': 7200}
# Existing snapshots use server-local timestamps; offset-bearing timestamps are
# already unambiguous. Normalize both to epoch seconds before filtering/sorting.
EPOCH = """CAST(CASE
    WHEN substr(timestamp, -1) = 'Z' OR substr(timestamp, -6, 1) IN ('+', '-')
    THEN strftime('%s', timestamp)
    ELSE strftime('%s', timestamp, 'utc')
END AS INTEGER)"""


def _iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def get_resource_history(db_path, resource='cpu', hours='24', now=None, threshold=None):
    if resource not in RESOURCES:
        raise ValueError('resource must be cpu, memory, or disk')
    hours = str(hours)
    if hours not in {*INTERVALS, 'all'}:
        raise ValueError('hours must be 1, 24, 168, 720, or all')
    now = now or datetime.now(timezone.utc)
    end = int(now.timestamp())
    start = end - int(hours) * 3600 if hours != 'all' else None
    column = RESOURCES[resource]
    # CPU and memory have no alert rules: show a guide, never a claimed alert.
    threshold = 90 if resource != 'disk' else threshold
    if (isinstance(threshold, bool) or not isinstance(threshold, (int, float))
            or not math.isfinite(threshold) or not 0 <= threshold <= 100):
        threshold = None
    init_database(db_path)
    # Only the whitelisted column above is interpolated; all bounds are bound.
    readings = f'''WITH readings AS (
        SELECT id, {EPOCH} AS recorded_at, {column} AS value FROM metrics
        WHERE {column} >= 0 AND {column} <= 100
    )'''
    where = 'WHERE recorded_at <= ?'
    params = [end]
    if start is not None:
        where += ' AND recorded_at >= ?'
        params.append(start)
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.row_factory = sqlite3.Row
        conn.execute('BEGIN')
        summary = conn.execute(readings + f'''
            SELECT COUNT(*) AS samples, MIN(recorded_at) AS first_at,
                   AVG(value) AS average, MAX(value) AS peak,
                   SUM(CASE WHEN value >= ? THEN 1 ELSE 0 END) AS high_samples
            FROM readings {where}
        ''', [threshold, *params]).fetchone()
        if start is None:
            start = summary['first_at'] if summary['first_at'] is not None else end
            interval = max(60, math.ceil((end - start + 1) / (400 * 60)) * 60)
        else:
            interval = INTERVALS[hours]
        latest = conn.execute(readings + f'''
            SELECT value, recorded_at FROM readings {where}
            ORDER BY recorded_at DESC, id DESC LIMIT 1
        ''', params).fetchone()
        rows = conn.execute(readings + f'''
            SELECT (recorded_at / ?) * ? AS bucket, AVG(value) AS average,
                   MIN(value) AS minimum, MAX(value) AS maximum, COUNT(*) AS samples
            FROM readings {where} GROUP BY bucket ORDER BY bucket
        ''', [interval, interval, *params]).fetchall()
    points = [{'timestamp': _iso(max(row['bucket'], start)),
               'average': round(row['average'], 2), 'min': round(row['minimum'], 2),
               'max': round(row['maximum'], 2), 'samples': row['samples']} for row in rows]
    return {'resource': resource, 'hours': hours, 'from': _iso(start), 'to': _iso(end),
            'interval_seconds': interval, 'samples': summary['samples'], 'points': points,
            'threshold': {'value': threshold, 'kind': 'alert' if resource == 'disk' else 'guide',
                          'readings_at_or_above': summary['high_samples'] or 0} if threshold is not None else None,
            'summary': {'latest': round(latest['value'], 2) if latest else None,
                        'latest_at': _iso(latest['recorded_at']) if latest else None,
                        'average': round(summary['average'], 2) if summary['samples'] else None,
                        'peak': round(summary['peak'], 2) if summary['samples'] else None}}
