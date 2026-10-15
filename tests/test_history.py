import sqlite3
import tempfile
import unittest
from pathlib import Path

from apachewatch_app import create_app
from apachewatch_app.database import init_database
from apachewatch_app.history import get_traffic_chart_data


class TrafficHistoryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.db_path = str(Path(directory.name) / 'history.db')
        init_database(self.db_path)
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                'INSERT INTO access_logs_hourly '
                '(hour_timestamp, request_count, status_success, unique_ips) '
                'VALUES (?, ?, ?, ?)',
                [
                    ('2026-10-14 18:00:00', 7, 7, 3),
                    ('2026-01-03 09:00:00', 3, 3, 1),
                    ('2025-12-31 09:00:00', 2, 2, 1),
                    ('2026-05-01 09:00:00', 4, 4, 2),
                    ('2026-07-01 09:00:00', 6, 6, 2),
                    ('2026-06-01 09:00:00', 5, 5, 2),
                    ('2026-10-14 08:00:00', 8, 8, 4),
                ],
            )

    def test_all_history_api_returns_oldest_to_newest_across_years(self):
        app = create_app({'database': self.db_path})
        response = app.test_client().get('/api/traffic-chart?hours=10000')
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertEqual(result['resolution'], 'daily')
        self.assertEqual(result['count'], 6)
        self.assertEqual([row['hour'] for row in result['data']], [
            '2025-12-31', '2026-01-03', '2026-05-01',
            '2026-06-01', '2026-07-01', '2026-10-14',
        ])
        self.assertEqual([row['requests'] for row in result['data']], [2, 3, 4, 5, 6, 15])
        self.assertEqual(result['data'][-1]['status_success'], 15)
        self.assertEqual(result['data'][-1]['unique_ips'], 4)

    def test_limited_daily_history_returns_latest_days_in_chronological_order(self):
        data, resolution = get_traffic_chart_data(self.db_path, hours=96)
        self.assertEqual(resolution, 'daily')
        self.assertEqual([row['hour'] for row in data], [
            '2026-05-01', '2026-06-01', '2026-07-01', '2026-10-14',
        ])
        self.assertEqual([row['requests'] for row in data], [4, 5, 6, 15])

    def test_hourly_history_returns_latest_hours_in_chronological_order(self):
        data, resolution = get_traffic_chart_data(self.db_path, hours=2)
        self.assertEqual(resolution, 'hourly')
        self.assertEqual([row['hour'] for row in data], [
            '2026-10-14 08:00:00', '2026-10-14 18:00:00',
        ])
        self.assertEqual([row['requests'] for row in data], [8, 7])


if __name__ == '__main__':
    unittest.main()
