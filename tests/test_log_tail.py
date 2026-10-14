import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apachewatch import app, config


class LogTailApiTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.error_log = Path(self.directory.name) / 'error.log'
        self.access_log = Path(self.directory.name) / 'access.log'
        self.error_log.write_text('first error\nsecond error\n')
        self.access_log.write_text('first request\nsecond request\n')
        self.config_patch = patch.dict(config['apache'], error_log=str(self.error_log), access_log=str(self.access_log))
        self.config_patch.start()
        self.addCleanup(self.config_patch.stop)
        self.client = app.test_client()

    def test_preserves_original_lines_and_file_order(self):
        lines = ['[original timestamp] [core:error]   ' + 'x' * 1200, '', '<script>text, not HTML</script>', '  final line  ']
        self.error_log.write_text('\n'.join(lines))
        response = self.client.get('/api/log-tail?source=error&limit=100')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {'source': 'error', 'filename': 'error.log', 'lines': lines})

    def test_can_read_access_log_and_new_lines(self):
        response = self.client.get('/api/log-tail?source=access&limit=1')
        self.assertEqual(response.get_json()['lines'], ['second request'])
        with self.access_log.open('a') as logfile:
            logfile.write('third request\n')
        response = self.client.get('/api/log-tail?source=access&limit=2')
        self.assertEqual(response.get_json()['lines'], ['second request', 'third request'])
        self.assertEqual(response.get_json()['filename'], 'access.log')

    def test_empty_and_rotated_logs(self):
        self.error_log.write_text('')
        self.assertEqual(self.client.get('/api/log-tail').get_json()['lines'], [])
        self.error_log.rename(self.error_log.with_suffix('.log.1'))
        self.error_log.write_text('new log after rotation\n')
        self.assertEqual(self.client.get('/api/log-tail').get_json()['lines'], ['new log after rotation'])

    def test_invalid_source_and_limit(self):
        for query in ('source=../../etc/passwd', 'source=other', 'limit=many'):
            with self.subTest(query=query):
                self.assertEqual(self.client.get('/api/log-tail?' + query).status_code, 400)

    def test_limit_is_bounded(self):
        self.error_log.write_text('line\n' * 1100)
        self.assertEqual(len(self.client.get('/api/log-tail?limit=100000').get_json()['lines']), 1000)
        self.assertEqual(len(self.client.get('/api/log-tail?limit=0').get_json()['lines']), 1)

    def test_missing_unconfigured_and_unreadable_files(self):
        self.error_log.unlink()
        self.assertEqual(self.client.get('/api/log-tail').status_code, 404)
        with patch.dict(config['apache'], error_log=''):
            self.assertEqual(self.client.get('/api/log-tail').status_code, 503)
        with patch('apachewatch_app.routes._tail_file', side_effect=PermissionError):
            response = self.client.get('/api/log-tail')
            self.assertEqual(response.status_code, 403)
            self.assertIn('permissions', response.get_json()['error'])


if __name__ == '__main__':
    unittest.main()
