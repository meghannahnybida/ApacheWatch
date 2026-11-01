import os
import sqlite3
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from apachewatch_app import create_app
from apachewatch_app.database import init_database
from apachewatch_app.resource_history import get_resource_history


class ResourceHistoryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.db = str(Path(directory.name) / 'history.db')
        init_database(self.db)
        self.now = datetime(2026, 10, 26, 12, tzinfo=timezone.utc)
        self.client = create_app({'database': self.db}).test_client()

    def insert(self, timestamp, cpu=20, memory=50, disk=70):
        with sqlite3.connect(self.db) as conn:
            conn.execute('INSERT INTO metrics (timestamp, cpu_percent, memory_percent, disk_percent) VALUES (?, ?, ?, ?)',
                         (timestamp, cpu, memory, disk))

    def history(self, resource='cpu', hours='24'):
        return get_resource_history(self.db, resource, hours, now=self.now)

    def test_each_resource_uses_its_own_recorded_values(self):
        self.insert((self.now - timedelta(minutes=5)).isoformat(), 10, 40, 80)
        self.insert(self.now.isoformat(), 30, 60, 90)
        for resource, latest, average, peak in [('cpu', 30, 20, 30), ('memory', 60, 50, 60), ('disk', 90, 85, 90)]:
            with self.subTest(resource=resource):
                data = self.history(resource)
                self.assertEqual(data['samples'], 2)
                self.assertEqual(data['summary']['latest'], latest)
                self.assertEqual(data['summary']['average'], average)
                self.assertEqual(data['summary']['peak'], peak)
                self.assertEqual(data['summary']['latest_at'], self.now.isoformat())

    def test_ranges_use_actual_time_including_boundaries_and_exclude_future_readings(self):
        for delta in (-86401, -86400, -3601, -3600, 0, 1):
            self.insert((self.now + timedelta(seconds=delta)).isoformat())
        self.assertEqual(self.history(hours='1')['samples'], 2)
        self.assertEqual(self.history(hours='24')['samples'], 4)
        self.assertEqual(self.history(hours='168')['samples'], 5)
        self.assertEqual(self.history(hours='all')['samples'], 5)

    def test_all_history_is_chronological_across_years_and_timezone_offsets(self):
        for timestamp, value in [('2026-10-25T08:00:00Z', 40), ('2025-12-31T12:00:00Z', 10),
                                 ('2026-01-02T12:00:00Z', 15), ('2026-10-25T09:00:00+02:00', 20)]:
            self.insert(timestamp, cpu=value)
        data = self.history(hours='all')
        self.assertEqual([point['average'] for point in data['points']], [10, 15, 30])
        dates = [datetime.fromisoformat(point['timestamp']) for point in data['points']]
        self.assertEqual(dates, sorted(dates))
        self.assertTrue(all(value.tzinfo is not None for value in dates))
        self.assertEqual(data['summary']['latest'], 40)
        self.assertEqual([point['average'] for point in self.history(hours='168')['points']], [20, 40])

    def test_bucket_range_preserves_brief_spikes_and_summary_is_sample_weighted(self):
        for seconds, value in [(-60, 100), (-50, 10), (-600, 40)]:
            self.insert((self.now + timedelta(seconds=seconds)).isoformat(), cpu=value)
        data = self.history()
        self.assertEqual(data['summary']['average'], 50)
        self.assertEqual(data['summary']['peak'], 100)
        self.assertEqual(data['points'][-1]['average'], 55)
        self.assertEqual((data['points'][-1]['min'], data['points'][-1]['max'], data['points'][-1]['samples']), (10, 100, 2))

    def test_all_samples_are_included_without_the_old_thousand_row_limit(self):
        with sqlite3.connect(self.db) as conn:
            conn.executemany('INSERT INTO metrics (timestamp, cpu_percent) VALUES (?, ?)',
                [((self.now - timedelta(seconds=index)).isoformat(), 100 if index == 1499 else 0) for index in range(1500)])
        data = self.history()
        self.assertEqual(data['samples'], 1500)
        self.assertEqual(sum(point['samples'] for point in data['points']), 1500)
        self.assertEqual(data['summary']['peak'], 100)
        self.assertEqual(max(point['max'] for point in data['points']), 100)
        self.assertLessEqual(len(data['points']), 300)

    def test_high_usage_counts_original_readings_including_equality_not_bucket_averages(self):
        for seconds, value in [(-60, 100), (-50, 90), (-40, 0)]:
            self.insert((self.now + timedelta(seconds=seconds)).isoformat(), cpu=value, memory=value)
        # An old high reading and an invalid reading must not affect this range.
        self.insert((self.now - timedelta(days=2)).isoformat(), cpu=99, memory=99)
        self.insert(self.now.isoformat(), cpu=101, memory=101)
        for resource in ('cpu', 'memory'):
            data = self.history(resource)
            self.assertLess(data['points'][0]['average'], 90)
            self.assertEqual(data['threshold'], {'value': 90, 'kind': 'guide', 'readings_at_or_above': 2})
            self.assertEqual(data['samples'], 3)

    def test_disk_history_uses_current_saved_threshold_without_changing_alert_rules(self):
        self.insert((self.now - timedelta(minutes=2)).isoformat(), disk=85)
        self.insert((self.now - timedelta(minutes=1)).isoformat(), disk=95)
        self.assertEqual(self.client.patch('/api/settings/thresholds', json={
            'thresholds': {'disk_percent': 95.5}}).status_code, 200)
        data = self.client.get('/api/resource-history?resource=disk&hours=all').get_json()
        self.assertEqual(data['threshold'], {'value': 95.5, 'kind': 'alert', 'enabled': True, 'readings_at_or_above': 0})
        self.client.patch('/api/settings/thresholds', json={'thresholds': {'disk_percent': 85}})
        data = self.client.get('/api/resource-history?resource=disk&hours=all').get_json()
        self.assertEqual(data['threshold']['readings_at_or_above'], 2)
        self.assertEqual(data['threshold']['value'], 85)
        # The guide on CPU/memory does not add new alert settings or rules.
        self.assertNotIn('cpu_percent', self.client.get('/api/settings/thresholds').get_json()['thresholds'])

    def test_disabled_disk_alerts_are_identified_and_empty_history_has_no_high_readings(self):
        self.client.application.config['APACHEWATCH']['alerts']['enabled'] = False
        data = self.client.get('/api/resource-history?resource=disk').get_json()
        self.assertFalse(data['threshold']['enabled'])
        self.assertEqual(data['threshold']['readings_at_or_above'], 0)
        self.assertEqual(data['samples'], 0)

    def test_missing_or_invalid_threshold_does_not_invent_a_disk_alert_line(self):
        for threshold in (None, float('nan'), float('inf'), -1, 101, True):
            with self.subTest(threshold=threshold):
                data = get_resource_history(self.db, 'disk', now=self.now, threshold=threshold)
                self.assertIsNone(data['threshold'])

    def test_large_all_history_is_bounded_and_does_not_fill_gaps_with_zeroes(self):
        with sqlite3.connect(self.db) as conn:
            conn.executemany('INSERT INTO metrics (timestamp, cpu_percent) VALUES (?, ?)',
                [((self.now - timedelta(hours=index)).isoformat(), index % 100) for index in range(5000)])
        data = self.history(hours='all')
        self.assertLessEqual(len(data['points']), 402)
        self.assertEqual(sum(point['samples'] for point in data['points']), 5000)
        with sqlite3.connect(self.db) as conn:
            conn.execute('DELETE FROM metrics')
        self.insert((self.now - timedelta(hours=8)).isoformat(), cpu=20)
        self.insert(self.now.isoformat(), cpu=30)
        data = self.history()
        self.assertEqual(len(data['points']), 2)
        self.assertEqual([point['average'] for point in data['points']], [20, 30])

    def test_latest_uses_last_sample_when_timestamps_are_equal(self):
        self.insert(self.now.isoformat(), cpu=10)
        self.insert(self.now.isoformat(), cpu=90)
        data = self.history()
        self.assertEqual(data['summary']['latest'], 90)
        self.assertEqual(data['summary']['average'], 50)

    def test_empty_old_or_invalid_data_is_not_misrepresented_as_zero_usage(self):
        self.insert('not a timestamp', cpu=30)
        for value in (None, float('nan'), float('inf'), -1, 101):
            self.insert(self.now.isoformat(), cpu=value, memory=44)
        self.insert((self.now - timedelta(days=3)).isoformat(), cpu=70)
        data = self.history()
        self.assertEqual(data['samples'], 0)
        self.assertEqual(data['points'], [])
        self.assertEqual(data['summary'], {'latest': None, 'latest_at': None, 'average': None, 'peak': None})
        self.assertEqual(self.history(hours='all')['samples'], 1)
        self.assertEqual(self.history('memory')['summary']['average'], 44)

    @unittest.skipUnless(hasattr(time, 'tzset'), 'requires process timezone support')
    def test_legacy_server_local_timestamps_and_explicit_offsets_are_equivalent(self):
        try:
            with patch.dict(os.environ, TZ='America/Chicago'):
                time.tzset()
                self.insert('2026-10-26T06:00:00', cpu=20)
                self.insert('2026-10-26T11:00:00+00:00', cpu=40)
                data = self.history()
                self.assertEqual(len(data['points']), 1)
                self.assertEqual(data['points'][0]['samples'], 2)
                self.assertEqual(data['points'][0]['timestamp'], '2026-10-26T11:00:00+00:00')
                self.assertEqual(data['summary']['latest'], 40)
        finally:
            time.tzset()

    def test_api_is_read_only_and_rejects_invalid_resources_or_time_ranges(self):
        self.insert(self.now.isoformat(), cpu=10)
        response = self.client.get('/api/resource-history?resource=cpu&hours=all')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['resource'], 'cpu')
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM metrics').fetchone()[0], 1)
        for query in ('resource=other', 'resource=cpu_percent', 'resource=cpu%3BDROP+TABLE+metrics',
                      'hours=0', 'hours=-1', 'hours=abc', 'hours=999999999999999999999'):
            with self.subTest(query=query):
                response = self.client.get('/api/resource-history?' + query)
                self.assertEqual(response.status_code, 400)
                self.assertIn('error', response.get_json())
        self.assertEqual(self.client.get('/api/history').get_json()['count'], 1)


if __name__ == '__main__':
    unittest.main()
