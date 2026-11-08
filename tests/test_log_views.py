import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apachewatch_app import create_app
from apachewatch_app.database import init_database


class SavedLogViewTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.database = self.root / 'nested' / 'views.db'
        self.config = {'database': str(self.database), 'apache': {
            'error_log': str(self.root / 'error.log'), 'access_log': str(self.root / 'access.log')}}
        self.client = create_app(self.config).test_client()

    def views(self):
        response = self.client.get('/api/log-views')
        self.assertEqual(response.status_code, 200)
        return response.get_json()['views']

    def save(self, name='Checkout errors', state=None):
        response = self.client.post('/api/log-views', json={'name': name, 'state': state or {}})
        self.assertEqual(response.status_code, 201, response.get_json())
        return response.get_json()['view']

    def test_reading_empty_views_needs_no_database_or_log_files(self):
        self.assertEqual(self.views(), [])
        self.assertFalse(self.database.exists())

    def test_saved_filters_survive_new_apps_without_starting_monitoring(self):
        state = {'source': 'access', 'format': 'terminal', 'limit': 500, 'q': ' POST ',
                 'ip': '2001:db8::1', 'url': '/checkout', 'status': '5',
                 'from': '2026-11-08T10:00', 'to': '2026-11-08T11:00'}
        view = self.save('  Checkout errors  ', state)
        self.assertEqual(view['name'], 'Checkout errors')
        self.assertEqual(view['state'], {**state, 'q': 'POST', 'level': ''})
        other = create_app(self.config).test_client().get('/api/log-views').get_json()['views']
        self.assertEqual(other, [view])
        self.assertFalse((self.root / 'access.log').exists())
        different = create_app({'database': str(self.root / 'other.db')}).test_client()
        self.assertEqual(different.get('/api/log-views').get_json()['views'], [])

    def test_names_are_unique_case_insensitively_without_overwriting(self):
        original = self.save('Straße')
        response = self.client.post('/api/log-views', json={'name': ' STRASSE ', 'state': {'q': 'other'}})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.views(), [original])
        second = self.save('Other')
        response = self.client.patch(f"/api/log-views/{second['id']}", json={'name': 'straße', 'state': {'q': 'changed'}})
        self.assertEqual(response.status_code, 409)
        self.assertCountEqual(self.views(), [original, second])

    def test_update_renames_and_replaces_filters_and_delete_only_removes_view(self):
        init_database(str(self.database))
        with sqlite3.connect(self.database) as conn:
            conn.execute("INSERT INTO metrics(timestamp, cpu_percent) VALUES ('2026-11-08T10:00', 12)")
        view = self.save()
        state = {'source': 'error', 'format': 'terminal', 'limit': 100,
                 'level': 'diagnostics', 'q': 'TLS', 'url': '/private'}
        response = self.client.patch(f"/api/log-views/{view['id']}", json={'name': 'TLS details', 'state': state})
        self.assertEqual(response.status_code, 200)
        updated = response.get_json()['view']
        self.assertEqual(updated['id'], view['id'])
        self.assertEqual(updated['name'], 'TLS details')
        self.assertEqual(updated['state']['level'], 'diagnostics')
        self.assertEqual(self.views(), [updated])
        self.assertEqual(self.client.delete(f"/api/log-views/{view['id']}").status_code, 204)
        self.assertEqual(self.views(), [])
        with sqlite3.connect(self.database) as conn:
            self.assertEqual(conn.execute('SELECT cpu_percent FROM metrics').fetchone()[0], 12)

    def test_invalid_names_and_filters_do_not_change_saved_views(self):
        view = self.save()
        invalid = [None, [], {}, {'name': 'Only name'}, {'name': 'x', 'state': {}, 'extra': 1}]
        for name in ('', '   ', 'x' * 81, 'two\nlines', 4, True, None):
            invalid.append({'name': name, 'state': {}})
        states = [None, [], {'source': '../../etc/passwd'}, {'source': []}, {'format': 'shell'},
                  {'limit': True}, {'limit': '20'}, {'limit': 21}, {'limit': 500},
                  {'q': 'x' * 1001}, {'q': None}, {'ip': 'invalid'}, {'from': 'yesterday'},
                  {'from': '2026-11-08'}, {'from': '2026-11-08 10:00'}, {'from': '2026-W45-7T10:00'},
                  {'from': '2026-11-09', 'to': '2026-11-08'}, {'from': '2026-11-08T10:00Z'},
                  {'level': 'trace8'}, {'level': []}, {'status': '9'}, {'status': '5'},
                  {'source': 'access', 'level': 'errors'}, {'cursor': 'old-page'}, {'path': '/etc/passwd'}]
        invalid.extend({'name': 'Invalid', 'state': state} for state in states)
        for payload in invalid:
            with self.subTest(payload=payload):
                response = self.client.post('/api/log-views', json=payload)
                self.assertEqual(response.status_code, 400)
                self.assertTrue(response.get_json()['error'])
                response = self.client.patch(f"/api/log-views/{view['id']}", json=payload)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(self.views(), [view])

    def test_missing_views_return_not_found_and_never_create_records(self):
        self.assertEqual(self.client.delete('/api/log-views/999').status_code, 404)
        response = self.client.patch('/api/log-views/999', json={'name': 'Missing', 'state': {}})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.views(), [])

    def test_view_limit_is_atomic_but_updates_and_replacement_are_allowed(self):
        with patch('apachewatch_app.log_views.MAX_VIEWS', 2):
            first = self.save('First')
            second = self.save('Second')
            response = self.client.post('/api/log-views', json={'name': 'Third', 'state': {}})
            self.assertEqual(response.status_code, 409)
            self.assertEqual(len(self.views()), 2)
            response = self.client.patch(f"/api/log-views/{first['id']}", json={'name': 'Renamed', 'state': {'q': 'new'}})
            self.assertEqual(response.status_code, 200)
            self.client.delete(f"/api/log-views/{second['id']}")
            self.save('Replacement')
            self.assertEqual(len(self.views()), 2)

    def test_existing_database_upgrade_keeps_saved_views_and_other_settings(self):
        self.database.parent.mkdir(parents=True)
        with sqlite3.connect(self.database) as conn:
            conn.execute('CREATE TABLE alert_thresholds (name TEXT PRIMARY KEY, value REAL NOT NULL)')
            conn.execute("INSERT INTO alert_thresholds VALUES ('disk_percent', 92)")
        self.assertEqual(self.views(), [])
        view = self.save()
        init_database(str(self.database))
        init_database(str(self.database))
        self.assertEqual(self.views(), [view])
        self.assertEqual(self.client.get('/api/settings/thresholds').get_json()['thresholds']['disk_percent'], 92)

    def test_literal_names_and_filters_are_not_interpreted_as_sql_or_html(self):
        name = '<img src=x onerror=alert(1)>'
        query = "'; DROP TABLE saved_log_views; --"
        view = self.save(name, {'q': query})
        self.assertEqual(self.views(), [view])
        self.assertEqual(view['state']['q'], query)
        self.save('Still available')
        self.assertEqual(len(self.views()), 2)


if __name__ == '__main__':
    unittest.main()
