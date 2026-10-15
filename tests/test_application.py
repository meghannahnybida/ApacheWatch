import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml
from flask import render_template
from jinja2 import FileSystemLoader

from apachewatch_app import create_app
from apachewatch_app.cli import main


PROJECT_ROOT = Path(__file__).resolve().parent.parent
METRICS = {
    "timestamp": "2026-10-14T12:00:00", "cpu_percent": 12,
    "memory": {"percent": 30, "used_gb": 3, "total_gb": 10},
    "disk": {"percent": 92, "used_gb": 92, "total_gb": 100},
}


class ApplicationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.settings = {
            "server_name": "refactor-test",
            "database": str(self.directory / "watch.db"),
            "apache": {"error_log": "", "access_log": ""},
        }

    def test_apps_have_independent_configuration_and_log_sources(self):
        error_a = self.directory / "a.log"
        error_b = self.directory / "b.log"
        error_a.write_text("first server\n")
        error_b.write_text("second server\n")
        self.settings["apache"]["error_log"] = str(error_a)
        first = create_app(self.settings)
        self.settings["apache"]["error_log"] = str(error_b)
        second = create_app(self.settings)

        self.assertEqual(first.test_client().get('/api/log-tail').get_json()['lines'], ["first server"])
        self.assertEqual(second.test_client().get('/api/log-tail').get_json()['lines'], ["second server"])
        first.config["APACHEWATCH"]["notifications"]["email"]["enabled"] = True
        self.assertFalse(second.config["APACHEWATCH"]["notifications"]["email"]["enabled"])
        self.assertNotIn("notifications", self.settings)

    def test_dashboard_and_assets_work_from_another_directory(self):
        error_log = self.directory / "error.log"
        error_log.write_text("[Wed Oct 14 12:00:00 2026] [core:error] test failure\n")
        self.settings["apache"]["error_log"] = str(error_log)
        (self.directory / "config.yaml").write_text(yaml.safe_dump(self.settings))
        previous_directory = Path.cwd()
        try:
            os.chdir(self.directory)
            app = create_app()
            app.testing = True
            client = app.test_client()
            with patch('apachewatch_app.routes.collect_metrics', return_value=METRICS):
                response = client.get('/')
            self.assertEqual(response.status_code, 200)
            self.assertIn("refactor-test", response.get_data(as_text=True))
            self.assertEqual(client.get('/api/history').get_json()['count'], 1)
            self.assertEqual(client.get('/api/alerts').get_json()['count'], 1)
            for asset in ('css/style.css', 'js/dashboard.js', 'js/theme.js', 'js/action-notes.js'):
                with self.subTest(asset=asset):
                    response = client.get(f'/static/{asset}')
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.data, (PROJECT_ROOT / 'static' / asset).read_bytes())
                    response.close()
        finally:
            os.chdir(previous_directory)

    def test_wsgi_import_does_not_start_monitoring_or_create_database(self):
        env = {**os.environ, 'PYTHONPATH': str(PROJECT_ROOT)}
        result = subprocess.run(
            [sys.executable, '-c',
             'import apachewatch, threading; '
             'assert not any(t.name == "apachewatch-monitor" for t in threading.enumerate()); '
             'assert apachewatch.app.test_client().get("/api/metrics").status_code == 200'],
            cwd=self.directory, env=env, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.directory / 'data').exists())

    def test_template_and_asset_edits_are_visible_without_restarting(self):
        app = create_app(self.settings)
        app.jinja_loader = FileSystemLoader(self.directory)
        app.static_folder = str(self.directory / 'static')
        asset = Path(app.static_folder) / 'dashboard.js'
        asset.parent.mkdir()
        asset.write_text('first script')
        template = self.directory / 'dashboard.html'
        template.write_text('First page {{ asset_url("dashboard.js") }}')
        with app.test_request_context('/'):
            first = render_template('dashboard.html')

        template.write_text('Updated page {{ asset_url("dashboard.js") }}')
        asset.write_text('updated script')
        for path in (template, asset):
            modified = path.stat().st_mtime + 2
            os.utime(path, (modified, modified))
        with app.test_request_context('/'):
            updated = render_template('dashboard.html')

        self.assertTrue(first.startswith('First page '))
        self.assertTrue(updated.startswith('Updated page '))
        self.assertNotEqual(first.split()[-1], updated.split()[-1])
        response = app.test_client().get(updated.split()[-1])
        self.assertEqual(response.data, b'updated script')
        response.close()

    def test_web_failure_stops_the_monitoring_worker(self):
        app = create_app(self.settings)
        with patch('apachewatch_app.cli.MonitoringWorker') as worker_class:
            with patch.object(app, 'run', side_effect=RuntimeError('web startup failed')):
                with self.assertRaisesRegex(RuntimeError, 'web startup failed'):
                    main(app, [])
            worker_class.assert_called_once_with(app.config['APACHEWATCH'], logger=app.logger)
            worker_class.return_value.start.assert_called_once()
            worker_class.return_value.stop.assert_called_once()

    def test_debug_starts_monitoring_only_in_reload_child(self):
        for reload_child, expected_starts in (('', 0), ('true', 1)):
            with self.subTest(reload_child=reload_child):
                app = create_app(self.settings)
                with patch.dict(os.environ, WERKZEUG_RUN_MAIN=reload_child):
                    with patch('apachewatch_app.cli.MonitoringWorker') as worker_class, patch.object(app, 'run') as run:
                        main(app, ['--debug'])
                        self.assertEqual(worker_class.return_value.start.call_count, expected_starts)
                        worker_class.return_value.stop.assert_called_once()
                        self.assertTrue(run.call_args.kwargs['debug'])

    def test_monitor_only_runs_without_starting_the_web_server(self):
        app = create_app(self.settings)
        with patch('apachewatch_app.cli.MonitoringWorker') as worker_class, patch.object(app, 'run') as run:
            worker_class.return_value.run.side_effect = KeyboardInterrupt
            with self.assertRaises(SystemExit) as exited:
                main(app, ['--monitor-only'])
            self.assertEqual(exited.exception.code, 0)
            worker_class.return_value.run.assert_called_once()
            worker_class.return_value.stopped.set.assert_called_once()
            worker_class.return_value.start.assert_not_called()
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
