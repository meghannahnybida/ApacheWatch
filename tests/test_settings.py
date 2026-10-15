import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

import notifications
from apachewatch_app import create_app
from apachewatch_app.actions import get_action_items
from apachewatch_app.alerts import evaluate_alerts
from apachewatch_app.monitoring import run_monitoring_cycle


class ServerSettingsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name)
        self.source = {
            'database': str(self.path / 'settings.db'),
            'apache': {'access_log': str(self.path / 'access.log'), 'error_log': str(self.path / 'error.log')},
            'notifications': {'email': {'enabled': False, 'recipients': ['owner@example.test']}},
        }
        self.app = create_app(self.source)
        self.client = self.app.test_client()
        self.config = self.app.config['APACHEWATCH']
        env = patch.dict(os.environ, {
            'APACHEWATCH_SMTP_HOST': 'smtp.example.test', 'APACHEWATCH_SMTP_USERNAME': 'sender@example.test',
            'APACHEWATCH_SMTP_PASSWORD': 'private-test-key', 'APACHEWATCH_EMAIL_FROM': 'sender@example.test',
            'APACHEWATCH_SMTP_PORT': '587', 'APACHEWATCH_SMTP_SECURITY': 'starttls',
        })
        env.start()
        self.addCleanup(env.stop)

    def thresholds(self):
        return self.client.get('/api/settings/thresholds').get_json()['thresholds']

    def test_thresholds_persist_across_apps_and_change_rule_evaluation(self):
        self.assertEqual(self.thresholds()['disk_percent'], 85)
        metrics = {'disk': {'percent': 90}}
        self.assertTrue(evaluate_alerts(metrics, {}, self.config))
        response = self.client.patch('/api/settings/thresholds', json={'thresholds': {'disk_percent': 95.5, 'server_errors_5xx': 12}})
        self.assertEqual(response.status_code, 200)
        restarted = create_app(self.source)
        self.assertEqual(restarted.test_client().get('/api/settings/thresholds').get_json()['thresholds']['disk_percent'], 95.5)
        self.assertEqual(self.config['alerts']['thresholds']['disk_percent'], 85)
        self.assertEqual(evaluate_alerts(metrics, {}, self.config), [])

    def test_background_worker_uses_saved_thresholds_without_restart(self):
        metrics = {'timestamp': '2026-10-14T12:00:00', 'cpu_percent': 10,
                   'disk': {'percent': 90, 'used_gb': 90, 'total_gb': 100},
                   'memory': {'percent': 20, 'used_gb': 2, 'total_gb': 10}}
        self.client.patch('/api/settings/thresholds', json={'thresholds': {'disk_percent': 95}})
        with patch('apachewatch_app.monitoring.collect_metrics', return_value=metrics), patch('notifications.send_email') as send:
            run_monitoring_cycle(self.config)
            self.assertEqual(get_action_items(self.config['database'])[0], [])
            self.client.patch('/api/settings/thresholds', json={'thresholds': {'disk_percent': 80}})
            run_monitoring_cycle(self.config)
            self.assertEqual(get_action_items(self.config['database'])[0][0]['evidence']['threshold'], 80)
            send.assert_not_called()

    def test_threshold_validation_is_atomic(self):
        before = self.thresholds()
        invalid = [{}, {'unknown': 5}, {'disk_percent': 0}, {'disk_percent': 101},
                   {'disk_percent': True}, {'disk_percent': None}, {'disk_percent': '85'},
                   {'disk_percent': float('nan')}, {'disk_percent': float('inf')},
                   {'server_errors_5xx': 1.5}, {'requests_per_ip': 1000000001},
                   {'disk_percent': 90, 'client_errors_4xx': 0}]
        for values in invalid:
            with self.subTest(values=values):
                response = self.client.patch('/api/settings/thresholds', json={'thresholds': values})
                self.assertEqual(response.status_code, 400)
                self.assertEqual(self.thresholds(), before)

    def test_recipient_changes_persist_and_preserve_email_preferences(self):
        notifications.update_preferences(self.config, severity='all')
        response = self.client.patch('/api/notifications/email', json={'recipients': [' owner@example.test ', 'second@example.test', 'SECOND@example.test']})
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertEqual(result['recipients'], ['owner@example.test', 'second@example.test'])
        self.assertFalse(result['enabled'])
        self.assertEqual(result['severity'], 'all')
        restarted = create_app(self.source).test_client().get('/api/notifications/email').get_json()
        self.assertEqual(restarted['recipients'], result['recipients'])
        self.assertFalse(restarted['enabled'])
        self.assertNotIn('private-test-key', response.get_data(as_text=True))

    def test_all_recipients_can_be_removed_without_enabling_delivery(self):
        response = self.client.patch('/api/notifications/email', json={'recipients': []})
        self.assertEqual(response.status_code, 200)
        status = response.get_json()
        self.assertEqual(status['recipients'], [])
        self.assertFalse(status['enabled'])
        self.assertFalse(status['configured'])
        self.assertIn('recipient address', status['missing'])

    def test_invalid_recipient_update_does_not_change_other_preferences(self):
        for values in ('owner@example.test', None, ['bad address'], ['one,two@example.test'], ['x\r\n@example.test'], [True], ['x' * 255 + '@example.test'], [f'user{i}@example.test' for i in range(21)]):
            with self.subTest(values=values):
                response = self.client.patch('/api/notifications/email', json={'enabled': True, 'recipients': values})
                self.assertEqual(response.status_code, 400)
                status = self.client.get('/api/notifications/email').get_json()
                self.assertFalse(status['enabled'])
                self.assertEqual(status['recipients'], ['owner@example.test'])
        self.assertEqual(self.client.patch('/api/notifications/email', json={'severity': []}).status_code, 400)

    def test_waiting_emails_follow_recipient_changes(self):
        now = datetime(2026, 10, 14, 12)
        notifications.queue_test(self.config, now)
        self.client.patch('/api/notifications/email', json={'recipients': ['second@example.test']})
        with sqlite3.connect(self.config['database']) as conn:
            self.assertEqual(json.loads(conn.execute('SELECT recipients FROM email_outbox').fetchone()[0]), ['second@example.test'])
        with patch('notifications.send_email') as send:
            notifications.deliver_pending(self.config, now)
            self.assertEqual(json.loads(send.call_args.args[1]['recipients']), ['second@example.test'])

    def test_recipient_changes_during_delivery_apply_to_remaining_jobs(self):
        now = datetime(2026, 10, 14, 12)
        notifications.queue_test(self.config, now)
        notifications.queue_test(self.config, now + timedelta(minutes=2))
        delivered = []

        def send(settings, job):
            delivered.append(json.loads(job['recipients']))
            if len(delivered) == 1:
                notifications.update_preferences(self.config, recipients=['second@example.test'])

        with patch('notifications.send_email', side_effect=send):
            notifications.deliver_pending(self.config, now + timedelta(minutes=3))
        self.assertEqual(delivered, [['owner@example.test'], ['second@example.test']])

    def test_existing_email_preference_table_needs_no_manual_migration(self):
        with sqlite3.connect(self.config['database']) as conn:
            conn.execute('CREATE TABLE email_preferences (id INTEGER PRIMARY KEY, enabled INTEGER NOT NULL, severity TEXT NOT NULL)')
            conn.execute("INSERT INTO email_preferences VALUES (1, 0, 'all')")
        response = self.client.patch('/api/notifications/email', json={'recipients': ['second@example.test']})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()['enabled'])
        self.assertEqual(response.get_json()['severity'], 'all')


if __name__ == '__main__':
    unittest.main()
