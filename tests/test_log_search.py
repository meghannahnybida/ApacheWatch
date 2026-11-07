import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apachewatch_app import create_app


def access(ip='192.0.2.10', path='/checkout', status=500, time='10:00:00', day='20/Oct/2026'):
    return f'{ip} - - [{day}:{time} +0530] "GET {path} HTTP/1.1" {status} 123 "-" "Mozilla/5.0"'


def error(message='URL /checkout failed', level='error', client='192.0.2.10:54321', time='10:00:00'):
    return f'[Tue Oct 20 {time} 2026] [core:{level}] [client {client}] {message}'


class ConfiguredLogTestCase(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.error = self.root / 'error.log'
        self.access = self.root / 'access.log'
        self.error.write_text('')
        self.access.write_text('')
        self.app = create_app({'database': str(self.root / 'test.db'), 'apache': {
            'error_log': str(self.error), 'access_log': str(self.access)}})
        self.client = self.app.test_client()

    def search(self, source='error', **params):
        response = self.client.get('/api/log-search', query_string={'source': source, **params})
        self.assertEqual(response.status_code, 200, response.get_json())
        return response.get_json()


class LogSearchTests(ConfiguredLogTestCase):
    def test_simplified_level_groups_keep_critical_and_trace_messages(self):
        levels = ['emerg', 'alert', 'crit', 'error', 'warn', 'notice', 'info', 'debug',
                  *(f'trace{n}' for n in range(1, 9)), 'unknown']
        lines = {level: error(level=level) for level in levels}
        self.error.write_text('\n'.join(lines.values()) + '\n')
        groups = {'errors': levels[:4], 'warn': ['warn'], 'information': ['notice', 'info'],
                  'diagnostics': ['debug', *(f'trace{n}' for n in range(1, 9))]}
        for group, members in groups.items():
            with self.subTest(group=group):
                page = self.search(level=group, limit=2)
                collected = page['lines']
                while page['next_cursor']:
                    page = self.search(level=group, limit=2, cursor=page['next_cursor'])
                    collected = page['lines'] + collected
                self.assertEqual(collected, [lines[level] for level in members])
        self.assertEqual(self.search()['count'], len(levels))
        # Exact API filters remain available for integrations.
        self.assertEqual(self.search(level='crit')['lines'], [lines['crit']])
        self.assertEqual(self.search(level='trace8')['lines'], [lines['trace8']])

    def test_search_finds_entries_beyond_the_old_tail_limits(self):
        old = access(path='/older-needle')
        self.access.write_text(old + '\n' + (access(path='/recent') + '\n') * 12000)
        result = self.search('access', q='OLDER-NEEDLE')
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['lines'], [old])
        self.assertEqual(result['entries'][0]['path'], '/older-needle')
        self.assertIsNone(result['next_cursor'])

    def test_access_filters_intersect_and_use_the_time_written_in_the_file(self):
        wanted = access()
        lines = [wanted, access(ip='192.0.2.100'), access(path='/other'), access(status=404),
                 access(time='09:59:59'), access(time='10:00:01'), 'unparsed request']
        self.access.write_text('\n'.join(lines))
        result = self.search('access', q='GET', ip='192.0.2.10', url='/check', status='5',
                             **{'from': '2026-10-20T10:00:00', 'to': '2026-10-20T10:00:00'})
        self.assertEqual(result['lines'], [wanted])
        self.assertEqual(result['summary']['total'], 1)
        self.assertEqual(result['summary']['server_errors'], 1)
        self.assertEqual(result['summary']['unique_ips'], 1)
        self.assertEqual(result['unparsed_count'], 0)

    def test_error_filters_search_original_context_before_grouping(self):
        wanted = error(message='Permission denied: URL /private', level='warning')
        self.error.write_text('\n'.join([
            wanted, error(message='URL /other failed', level='warn'), error(level='error'),
            error(client='192.0.2.100:54321', level='warn'),
        ]))
        result = self.search(ip='192.0.2.10', url='/private', level='warn', q='PERMISSION',
                             **{'from': '2026-10-20T10:00', 'to': '2026-10-20T11:00'})
        self.assertEqual(result['lines'], [wanted])
        self.assertEqual(result['incidents'][0]['count'], 1)
        # Filtering by client must still work after grouping removes client-specific text.
        result = self.search(q='192.0.2.10:54321')
        self.assertEqual(result['count'], 3)
        self.assertTrue(result['incidents'])

    def test_ipv6_addresses_are_normalized_and_client_ports_are_removed(self):
        wanted = access(ip='2001:db8::1')
        self.access.write_text(wanted + '\n' + access(ip='2001:db8::10'))
        self.assertEqual(self.search('access', ip='2001:0db8:0:0:0:0:0:1')['lines'], [wanted])
        for client in ('[2001:db8::1]:443', '2001:db8::1:443', '2001:db8::1:54321'):
            with self.subTest(client=client):
                line = error(client=client)
                self.error.write_text(line)
                self.assertEqual(self.search(ip='2001:db8::1')['lines'], [line])

    def test_search_is_literal_and_preserves_full_messages_and_original_spacing(self):
        line = error(message='x' * 800 + ' needle.*[ café <script>text</script>   ')
        self.error.write_text(line)
        result = self.search(q='NEEDLE.*[')
        self.assertEqual(result['lines'], [line])
        self.assertIn('needle.*[', result['incidents'][0]['message'])
        self.assertEqual(self.search(q='needle.+')['count'], 0)

    def test_pages_preserve_every_line_and_ignore_appends_until_refresh(self):
        lines = [f'line {i} café ' + 'x' * (i % 300) for i in range(900)]
        lines[15] = ''
        lines[450] = '<img src=x onerror=alert(1)>'
        self.error.write_bytes(('\r\n'.join(lines) + '\r\n').encode())
        page = self.search(limit=17)
        collected = list(reversed(page['lines']))
        with self.error.open('a') as log:
            log.write('newly appended\n')
        while page['next_cursor']:
            page = self.search(limit=17, cursor=page['next_cursor'])
            collected.extend(reversed(page['lines']))
        self.assertEqual(collected, list(reversed(lines)))
        self.assertEqual(self.search(limit=1)['lines'], ['newly appended'])

    def test_rotated_truncated_and_rewritten_files_invalidate_the_cursor(self):
        for operation in ('rotate', 'truncate', 'rewrite'):
            with self.subTest(operation=operation):
                self.error.write_text('first line\nsecond line\nthird line\n')
                cursor = self.search(limit=1)['next_cursor']
                if operation == 'rotate':
                    self.error.rename(self.root / 'error.log.1')
                    self.error.write_text('new file\n')
                elif operation == 'truncate':
                    self.error.write_text('')
                else:
                    self.error.write_text('other line\nsecond line\nthird line\n')
                response = self.client.get('/api/log-search', query_string={'cursor': cursor})
                self.assertEqual(response.status_code, 409)
                self.assertIn('Refresh', response.get_json()['error'])

    def test_scan_budget_returns_a_cursor_even_when_this_batch_has_no_matches(self):
        self.error.write_text('old needle\n' + 'unrelated\n' * 30)
        with patch('apachewatch_app.log_search.MAX_SCAN_BYTES', 25):
            page = self.search(q='needle')
            self.assertEqual(page['count'], 0)
            self.assertIsNotNone(page['next_cursor'])
            collected = []
            pages = 0
            while True:
                collected.extend(page['lines'])
                pages += 1
                if not page['next_cursor']:
                    break
                page = self.search(q='needle', cursor=page['next_cursor'])
        self.assertGreater(pages, 1)
        self.assertEqual(collected, ['old needle'])

    def test_cursor_cannot_be_reused_for_different_filters_or_sources(self):
        self.error.write_text('line one\nline two\n')
        cursor = self.search(limit=1)['next_cursor']
        for params in ({'q': 'other'}, {'source': 'access'}):
            response = self.client.get('/api/log-search', query_string={'cursor': cursor, **params})
            self.assertIn(response.status_code, (400, 409))

    def test_invalid_filters_and_cursors_return_actionable_errors(self):
        cases = [{'source': '../../etc/passwd'}, {'limit': 'abc'}, {'ip': '192.0.2'},
                 {'from': 'yesterday'}, {'from': '2026-10-20', 'to': '2026-10-19'},
                 {'from': '2026-10-20T00:00:00Z'}, {'level': 'other'}, {'status': '9'},
                 {'status': '5'}, {'source': 'access', 'level': 'error'}, {'q': 'x' * 1001},
                 {'cursor': 'x' * 2050}, {'cursor': 'garbage'}, {'cursor': 'W10'}]
        for params in cases:
            with self.subTest(params=params):
                response = self.client.get('/api/log-search', query_string=params)
                self.assertEqual(response.status_code, 400)
                self.assertTrue(response.get_json()['error'])

    def test_empty_and_unrecognized_lines_remain_available_in_terminal_results(self):
        self.assertEqual(self.search()['lines'], [])
        self.access.write_text('  unknown line  \n\nlast line')
        result = self.search('access')
        self.assertEqual(result['lines'], ['  unknown line  ', '', 'last line'])
        self.assertEqual(result['unparsed_count'], 3)
        self.assertEqual(result['summary']['total'], 0)
        self.assertEqual(self.search('access', ip='192.0.2.10')['count'], 0)

    def test_page_size_is_bounded(self):
        self.error.write_text('log line\n' * 600)
        self.assertEqual(self.search(limit=100000)['count'], 500)
        self.assertEqual(self.search(limit=0)['count'], 1)

    def test_oversized_lines_report_a_read_failure(self):
        self.error.write_text('x' * (1024 * 1024 + 1))
        self.assertEqual(self.client.get('/api/log-search').status_code, 503)

    def test_missing_unconfigured_and_unreadable_logs(self):
        self.error.unlink()
        self.assertEqual(self.client.get('/api/log-search').status_code, 404)
        with patch.dict(self.app.config['APACHEWATCH']['apache'], error_log=''):
            self.assertEqual(self.client.get('/api/log-search').status_code, 503)
        with patch('apachewatch_app.log_search.open', side_effect=PermissionError):
            response = self.client.get('/api/log-search')
            self.assertEqual(response.status_code, 403)
            self.assertIn('permissions', response.get_json()['error'])


class TerminalLogTests(ConfiguredLogTestCase):
    def stream(self, cursor, source='error', **params):
        response = self.client.get('/api/log-stream', query_string={'source': source, 'cursor': cursor, **params})
        self.assertEqual(response.status_code, 200, response.get_json())
        return response.get_json()

    def context(self, page, offset, source='error'):
        return self.client.get('/api/log-context', query_string={
            'source': source, 'snapshot': page['snapshot'], 'offset': offset})

    def test_live_bursts_preserve_duplicate_lines_and_drain_in_order(self):
        self.error.write_text('initial\n')
        cursor = self.search()['stream_cursor']
        lines = ['same line'] * 1203
        with self.error.open('a') as handle:
            handle.write('\n'.join(lines) + '\n')
        received, offsets = [], []
        while True:
            result = self.stream(cursor)
            received.extend(line['raw'] for line in result['terminal_lines'])
            offsets.extend(line['offset'] for line in result['terminal_lines'])
            cursor = result['stream_cursor']
            if not result['has_more']:
                break
        self.assertEqual(received, lines)
        self.assertEqual(len(set(offsets)), len(lines))
        self.assertEqual(self.stream(cursor)['terminal_lines'], [])

    def test_live_reads_use_the_same_grouped_levels_as_search(self):
        page = self.search(level='diagnostics')
        lines = [error(level=level) for level in ['error', 'debug', 'trace1', 'trace8', 'info']]
        self.error.write_text('\n'.join(lines) + '\n')
        result = self.stream(page['stream_cursor'], level='diagnostics')
        self.assertEqual([line['raw'] for line in result['terminal_lines']], lines[1:4])

    def test_partial_line_is_updated_at_its_original_offset(self):
        self.error.write_bytes(b'first\npartial caf\xc3')
        page = self.search()
        offset = page['terminal_lines'][-1]['offset']
        with self.error.open('ab') as handle:
            handle.write(b'\xa9\r\n\nlast\n')
        result = self.stream(page['stream_cursor'])
        self.assertEqual(result['terminal_lines'], [
            {'offset': offset, 'raw': 'partial café'},
            {'offset': offset + len('partial café\r\n'.encode()), 'raw': ''},
            {'offset': offset + len('partial café\r\n\n'.encode()), 'raw': 'last'},
        ])
        self.assertEqual(self.stream(result['stream_cursor'])['terminal_lines'], [])

    def test_filtered_stream_advances_across_empty_bounded_batches(self):
        page = self.search(q='needle')
        with self.error.open('a') as handle:
            handle.write('other\n' * 15 + 'needle\n')
        cursor, matches, polls = page['stream_cursor'], [], 0
        with patch('apachewatch_app.log_search.MAX_SCAN_BYTES', 20):
            while True:
                result = self.stream(cursor, q='needle')
                matches.extend(line['raw'] for line in result['terminal_lines'])
                cursor = result['stream_cursor']
                polls += 1
                if not result['has_more']:
                    break
        self.assertGreater(polls, 1)
        self.assertEqual(matches, ['needle'])

    def test_empty_access_log_stream_applies_intersecting_filters(self):
        page = self.search('access', status='5', ip='192.0.2.10', url='/check')
        wanted = access()
        self.access.write_text('\n'.join([
            access(ip='192.0.2.100'), access(status=404), access(path='/other'),
            'unparsed', wanted,
        ]) + '\n')
        result = self.stream(page['stream_cursor'], 'access', status='5', ip='192.0.2.10', url='/check')
        self.assertEqual([line['raw'] for line in result['terminal_lines']], [wanted])
        self.assertFalse(result['has_more'])

    def test_context_uses_snapshot_neighbors_ignoring_filters_and_later_appends(self):
        lines = ['before 1', '', 'before café', 'needle <script>alert(1)</script>', 'after 1', 'after 2', 'after 3', 'after 4']
        self.error.write_text('\r\n'.join(lines) + '\r\n')
        page = self.search(q='needle')
        with self.error.open('a') as handle:
            handle.write('newly appended\n')
        offset = page['terminal_lines'][0]['offset']
        response = self.context(page, offset)
        self.assertEqual(response.status_code, 200)
        self.assertEqual([line['raw'] for line in response.get_json()['lines']], lines[:7])
        first = self.context(page, 0).get_json()['lines']
        self.assertEqual([line['raw'] for line in first], lines[:4])
        last_offset = len(('\r\n'.join(lines[:-1]) + '\r\n').encode())
        last = self.context(page, last_offset).get_json()['lines']
        self.assertEqual([line['raw'] for line in last], lines[-4:])

    def test_live_and_context_reject_changed_files(self):
        for operation in ('rotate', 'truncate', 'rewrite'):
            with self.subTest(operation=operation):
                self.error.write_text('first\nsecond\n')
                page = self.search()
                if operation == 'rotate':
                    self.error.rename(self.root / 'previous.log')
                    self.error.write_text('replacement\n')
                elif operation == 'truncate':
                    self.error.write_text('')
                else:
                    self.error.write_text('other\nsecond\n')
                response = self.client.get('/api/log-stream', query_string={'cursor': page['stream_cursor']})
                self.assertEqual(response.status_code, 409)
                self.assertEqual(self.context(page, 0).status_code, 409)

    def test_stream_and_context_validate_positions_sources_and_filters(self):
        self.error.write_text('first\nsecond\n')
        page = self.search()
        for params in ({'cursor': 'garbage'}, {'cursor': 'W10'},
                       {'cursor': page['stream_cursor'], 'q': 'different'},
                       {'cursor': page['stream_cursor'], 'source': 'access'}):
            self.assertEqual(self.client.get('/api/log-stream', query_string=params).status_code, 400)
        for offset in (-1, 1, 1000, 'bad'):
            self.assertEqual(self.context(page, offset).status_code, 400)
        self.assertEqual(self.context(page, 0, 'access').status_code, 400)


if __name__ == '__main__':
    unittest.main()
