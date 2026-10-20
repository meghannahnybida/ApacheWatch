import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apachewatch_app import create_app
from apachewatch_app.guidance import finding_guidance


class FindingGuidanceTests(unittest.TestCase):
    def test_threshold_guidance_uses_recorded_values_and_relevant_destination(self):
        cases = [
            ('disk_percent', 'overview', None, 'all'),
            ('server_errors_5xx', 'logs', 'access', '5'),
            ('client_errors_4xx', 'logs', 'access', '4'),
            ('requests_per_ip', 'logs', 'access', 'all'),
            ('bot_percentage', 'analytics', None, 'all'),
        ]
        for kind, view, source, status in cases:
            with self.subTest(kind=kind):
                guidance = finding_guidance({'source': 'alert', 'evidence': {
                    'alert_type': kind, 'value': 92, 'threshold': 85, 'ip': '192.0.2.10',
                }})
                self.assertIn('92', guidance['trigger'])
                self.assertIn('85', guidance['trigger'])
                self.assertTrue(guidance['impact'])
                self.assertEqual(len(guidance['steps']), 3)
                action = guidance['action']
                self.assertEqual((action['view'], action['source'], action['status']), (view, source, status))
                if kind == 'requests_per_ip':
                    self.assertEqual(action['query'], '192.0.2.10')

    def test_error_message_changes_the_investigation_without_claiming_a_root_cause(self):
        cases = [
            ('Permission denied: /private', 'intended', 'permissions'),
            ('AH00035: access to /private denied because search permissions are missing', 'intended', 'permissions'),
            ('AH00957: connection refused to backend', 'communication', 'reachable'),
            ('Request timed out', 'waited', 'load'),
            ('File does not exist: /missing', 'could not be found', 'deployed files'),
            ('proxy_fcgi: PHP Fatal error: uncaught exception', 'application error', 'exception'),
        ]
        for message, impact, step in cases:
            with self.subTest(message=message):
                guidance = finding_guidance({'source': 'error', 'related_query': '/problem',
                    'evidence': {'message': message, 'count': 7, 'level': 'error'}})
                self.assertIn('7 times', guidance['trigger'])
                self.assertIn(impact, guidance['impact'])
                self.assertIn(step, ' '.join(guidance['steps']))
                self.assertEqual(guidance['action']['source'], 'error')
                self.assertEqual(guidance['action']['query'], '/problem')

    def test_security_range_and_ip_have_different_scope_and_destinations(self):
        for target_type, target in [('range', '192.0.2.0/24'), ('ip', '192.0.2.10')]:
            with self.subTest(target_type=target_type):
                guidance = finding_guidance({'source': 'security', 'evidence': {
                    'target_type': target_type, 'target': target, 'reasons': ['Repeated probes', None],
                }})
                self.assertIn('Repeated probes', guidance['trigger'])
                self.assertIn('legitimate', guidance['impact'] + ' '.join(guidance['steps']))
                self.assertEqual(guidance['action']['view'], 'security' if target_type == 'range' else 'logs')
                self.assertEqual(guidance['action']['query'], '' if target_type == 'range' else target)

    def test_legacy_or_invalid_evidence_keeps_summary_without_fabricating_values(self):
        for evidence in [None, [], 'old evidence', {}, {'alert_type': 'future_rule'},
                         {'alert_type': 'disk_percent', 'value': float('nan'), 'threshold': 85},
                         {'alert_type': 'disk_percent', 'value': True, 'threshold': 85}]:
            with self.subTest(evidence=evidence):
                guidance = finding_guidance({'source': 'alert', 'summary': 'Saved finding', 'evidence': evidence})
                self.assertEqual(guidance['trigger'], 'Saved finding')
                self.assertTrue(guidance['steps'])
        guidance = finding_guidance({'source': 'alert', 'evidence': {'alert_type': 'requests_per_ip'}})
        self.assertEqual(guidance['action']['query'], '')

    def test_api_guidance_survives_note_and_status_updates_and_missing_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            access = path / 'access.log'
            line = '192.0.2.10 - - [20/Oct/2026:10:00:00 +0000] "GET /example HTTP/1.1" 200 123 "-" "Mozilla/5.0"\n'
            access.write_text(line * 3)
            app = create_app({'database': str(path / 'test.db'),
                'apache': {'access_log': str(access), 'error_log': ''},
                'alerts': {'thresholds': {'requests_per_ip': 2}}})
            client = app.test_client()
            with patch('apachewatch_app.actions.collect_metrics', return_value={}), \
                    patch('apachewatch_app.traffic.IP_ANALYSIS_AVAILABLE', False):
                response = client.get('/api/action-items?status=all')
                self.assertEqual(response.status_code, 200)
                item = response.get_json()['items'][0]
                self.assertEqual(item['evidence']['ip'], '192.0.2.10')
                self.assertIn('3 requests', item['guidance']['trigger'])
                self.assertEqual(item['guidance']['action']['query'], '192.0.2.10')
                url = f"/api/action-items/{item['id']}"
                self.assertEqual(client.patch(url, json={'status': 'snoozed', 'snooze_minutes': 60}).status_code, 200)
                before = client.get('/api/action-items?status=all').get_json()['items'][0]
                self.assertEqual(client.patch(url, json={'note': 'Investigating this client'}).status_code, 200)
                access.write_text('')
                saved = client.get('/api/action-items?status=all').get_json()['items'][0]
                self.assertEqual(saved['guidance'], before['guidance'])
                self.assertEqual(saved['note'], 'Investigating this client')
                self.assertEqual(saved['status'], 'snoozed')
                self.assertEqual(saved['snoozed_until'], before['snoozed_until'])
                self.assertFalse(saved['currently_observed'])


if __name__ == '__main__':
    unittest.main()
