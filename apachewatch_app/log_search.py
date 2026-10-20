"""Bounded, backwards searches of configured logs, with stable pagination."""

import base64
import hashlib
import ipaddress
import json
import os
import re
from datetime import datetime
from pathlib import Path

from .logs import (
    extract_affected_urls, group_error_incidents, parse_access_line,
    parse_access_timestamp, parse_error_line, parse_error_timestamp,
)

MAX_SCAN_BYTES = 8 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
LEVELS = {'emerg', 'alert', 'crit', 'error', 'warn', 'notice', 'info', 'debug',
          'unknown', *(f'trace{n}' for n in range(1, 9))}
CLIENT = re.compile(r'\[(?:client|remote)\s+(\[[^\]]+\](?::\d+)?|[^\]]+)\]', re.IGNORECASE)


class LogChangedError(ValueError):
    """The file no longer matches the search's original snapshot."""


def _level(value):
    value = value.lower()
    return {'warning': 'warn', 'critical': 'crit'}.get(value, value)


def _filters(params, source):
    result = {key: params.get(key, '').strip() for key in ('q', 'ip', 'url', 'from', 'to', 'level', 'status')}
    if any(len(value) > 1000 for value in result.values()):
        raise ValueError('Search fields must be 1,000 characters or fewer.')
    result['q'], result['url'] = result['q'].casefold(), result['url'].casefold()
    if result['ip']:
        try:
            result['ip'] = str(ipaddress.ip_address(result['ip']))
        except ValueError:
            raise ValueError('Enter a valid client IP address.') from None
    for key in ('from', 'to'):
        if result[key]:
            try:
                value = datetime.fromisoformat(result[key])
                if value.tzinfo is not None:
                    raise ValueError
                result[key] = value
            except ValueError:
                raise ValueError('Use dates and times as written in the log, without a timezone.') from None
    if result['from'] and result['to'] and result['from'] > result['to']:
        raise ValueError('The start date must be before the end date.')
    result['level'] = _level(result['level'])
    result['status'] = result['status'] or 'all'
    if result['level'] and result['level'] not in LEVELS:
        raise ValueError('Choose a valid error level.')
    if result['status'] not in {'all', '2', '3', '4', '5'}:
        raise ValueError('Choose a valid response status.')
    if source == 'access' and result['level']:
        raise ValueError('Error levels apply to the error log only.')
    if source == 'error' and result['status'] != 'all':
        raise ValueError('Response status applies to the access log only.')
    return result


def _client_ip(message):
    match = CLIENT.search(message)
    if not match:
        return None
    value = match.group(1)
    if value.startswith('['):
        value = value[1:value.index(']')]
    else:
        host, separator, port = value.rpartition(':')
        if separator and port.isdigit():
            try:
                return str(ipaddress.ip_address(host))
            except ValueError:
                pass
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _matches(entry, raw, filters, source):
    if filters['q'] and filters['q'] not in raw.casefold():
        return False
    if filters['ip']:
        try:
            if str(ipaddress.ip_address(entry.get('ip', ''))) != filters['ip']:
                return False
        except ValueError:
            return False
    if filters['url']:
        urls = [entry['path']] if source == 'access' and entry.get('path') else extract_affected_urls(entry.get('message', ''))
        if not any(filters['url'] in url.casefold() for url in urls):
            return False
    if filters['level'] and _level(entry.get('level', 'unknown')) != filters['level']:
        return False
    if filters['status'] != 'all':
        status = entry.get('status')
        if not isinstance(status, int) or str(status // 100) != filters['status']:
            return False
    if filters['from'] or filters['to']:
        timestamp = (parse_access_timestamp if source == 'access' else parse_error_timestamp)(entry.get('timestamp', ''))
        if not timestamp:
            return False
        # The UI deliberately uses the wall-clock timestamps printed in the file.
        timestamp = timestamp.replace(tzinfo=None)
        if filters['from'] and timestamp < filters['from']:
            return False
        if filters['to'] and timestamp > filters['to']:
            return False
    return True


def _reverse_lines(handle, end):
    """Yield (line start, original bytes) newest first, including blank lines."""
    position, remainder, first = end, b'', True
    while position:
        length = min(position, 65536)
        position -= length
        handle.seek(position)
        data = handle.read(length) + remainder
        pieces = data.split(b'\n')
        offset = position + len(data)
        for line in reversed(pieces[1:]):
            offset -= len(line)
            if not (first and not line):
                if len(line) > MAX_LINE_BYTES:
                    raise OSError('A log line exceeds the search size limit.')
                yield offset, line.removesuffix(b'\r')
            first = False
            offset -= 1
        remainder = pieces[0]
        if len(remainder) > MAX_LINE_BYTES:
            raise OSError('A log line exceeds the search size limit.')
    if end:
        yield 0, remainder.removesuffix(b'\r')


def _stamp(handle, end):
    handle.seek(0)
    prefix = handle.read(min(end, 256))
    handle.seek(max(0, end - 256))
    return hashlib.sha256(prefix + handle.read(min(end, 256))).hexdigest()


def _cursor(value):
    try:
        if len(value) > 2048:
            raise ValueError
        data = json.loads(base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)))
        if not isinstance(data, dict) or any(type(data.get(key)) is not int for key in ('end', 'before')):
            raise ValueError
        if not 0 < data['before'] <= data['end']:
            raise ValueError
        return data
    except (ValueError, TypeError, UnicodeError):
        raise ValueError('Invalid search cursor. Refresh the search.') from None


def search_log(path, source, params):
    """Read one page from a file snapshot, never loading the whole log."""
    if source not in {'error', 'access'}:
        raise ValueError('source must be error or access')
    try:
        limit = min(max(int(params.get('limit', 20)), 1), 500)
    except ValueError:
        raise ValueError('limit must be an integer') from None
    filters = _filters(params, source)
    fingerprint = hashlib.sha256(json.dumps([source, filters], default=str, sort_keys=True).encode()).hexdigest()
    cursor = _cursor(params['cursor']) if params.get('cursor') else None
    entries, scanned, offset = [], 0, 0
    with open(path, 'rb') as handle:
        stat = os.fstat(handle.fileno())
        identity = [stat.st_dev, stat.st_ino]
        end = cursor['end'] if cursor else stat.st_size
        if cursor and (cursor.get('file') != identity or end > stat.st_size):
            raise LogChangedError('The log file changed. Refresh the search to start again.')
        stamp = _stamp(handle, end)
        if cursor and cursor.get('stamp') != stamp:
            raise LogChangedError('The log file changed. Refresh the search to start again.')
        if cursor and cursor.get('filters') != fingerprint:
            raise ValueError('Search filters changed. Refresh the search.')
        before = cursor['before'] if cursor else end
        for offset, line in _reverse_lines(handle, before):
            scanned += 1
            raw = line.decode('utf-8', errors='replace')
            entry = parse_access_line(raw) if source == 'access' else parse_error_line(raw)
            entry = entry or {}
            if source == 'error':
                entry['ip'] = _client_ip(entry['message'])
            if _matches(entry, raw, filters, source):
                entries.append({**entry, 'raw': raw})
            if len(entries) >= limit or before - offset >= MAX_SCAN_BYTES:
                break
        # Detect rotation/truncation during the scan instead of mixing snapshots.
        if os.stat(path).st_ino != stat.st_ino or os.fstat(handle.fileno()).st_size < end or _stamp(handle, end) != stamp:
            raise LogChangedError('The log file changed. Refresh the search to start again.')
    next_cursor = None
    if offset > 0:
        data = {'end': end, 'before': offset, 'file': identity, 'stamp': stamp, 'filters': fingerprint}
        next_cursor = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
    access = [entry for entry in entries if 'status' in entry]
    return {
        'source': source, 'filename': Path(path).name, 'entries': entries,
        'lines': [entry['raw'] for entry in reversed(entries)],
        'incidents': group_error_incidents([entry for entry in reversed(entries) if entry.get('message')], limit=limit) if source == 'error' else [],
        'count': len(entries), 'scanned_lines': scanned, 'next_cursor': next_cursor,
        'summary': {'total': len(access), 'unique_ips': len({entry['ip'] for entry in access}),
                    'success': sum(200 <= entry['status'] < 300 for entry in access),
                    'client_errors': sum(400 <= entry['status'] < 500 for entry in access),
                    'server_errors': sum(500 <= entry['status'] < 600 for entry in access)},
        'unparsed_count': sum('status' not in entry for entry in entries) if source == 'access' else 0,
    }
