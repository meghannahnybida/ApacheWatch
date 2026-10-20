import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apachewatch_app import create_app


def access(ip='192.0.2.10', path='/checkout', status=500, time='10:00:00', day='20/Oct/2026'):
    return f'{ip} - - [{day}:{time} +0530] "GET {path} HTTP/1.1" {status} 123 "-" "Mozilla/5.0"'


def error(message='URL /checkout failed', level='error', client='192.0.2.10:54321', time='10:00:00'):
    return f'[Tue Oct 20 {time} 2026] [core:{level}] [client {client}] {message}'


class LogSearchTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
