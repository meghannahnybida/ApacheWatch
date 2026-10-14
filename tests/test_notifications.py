import json
import os
import smtplib
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import notifications
from apachewatch import (
    MonitoringWorker, app, apply_config_defaults, config, get_action_items,
    init_database, run_monitoring_cycle, sync_action_items, update_action_item,
)


def finding(key="disk", severity="critical"):
    return {
        "source": "alert", "source_key": key, "severity": severity,
        "title": "Disk usage is high", "summary": "Disk usage is 92%, threshold is 85%",
        "evidence": {"value": 92, "threshold": 85}, "related_view": "overview",
        "related_query": "", "occurrence_count": 1,
    }


class EmailNotificationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.settings = apply_config_defaults({
            "database": str(Path(directory.name) / "notifications.db"),
            "server_name": "test-server",
            "apache": {"error_log": str(Path(directory.name) / "error.log"), "access_log": str(Path(directory.name) / "access.log")},
            "notifications": {"email": {"enabled": True, "recipients": ["recipient@example.test"], "severity": "critical"}},
        })
        self.env = patch.dict(os.environ, {
            "APACHEWATCH_SMTP_HOST": "smtp.example.test", "APACHEWATCH_SMTP_PORT": "587",
            "APACHEWATCH_SMTP_SECURITY": "starttls", "APACHEWATCH_SMTP_USERNAME": "sender@example.test",
            "APACHEWATCH_SMTP_PASSWORD": "private-test-secret", "APACHEWATCH_EMAIL_FROM": "sender@example.test",
            "APACHEWATCH_PUBLIC_URL": "https://watch.example.test",
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        self.now = datetime(2026, 10, 14, 12, 0)
        init_database(self.settings["database"])

    def items(self):
        return get_action_items(self.settings["database"], status="all", limit=500)[0]

    def outbox(self):
        with sqlite3.connect(self.settings["database"]) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute("SELECT * FROM email_outbox ORDER BY id")]

    def test_no_sender_does_not_queue_or_claim_delivery(self):
        sync_action_items(self.settings["database"], [finding()])
        with patch.dict(os.environ, APACHEWATCH_SMTP_HOST="", APACHEWATCH_EMAIL_FROM="", APACHEWATCH_SMTP_USERNAME="", APACHEWATCH_SMTP_PASSWORD=""):
            status = notifications.public_status(self.settings)
            self.assertFalse(status["configured"])
            self.assertEqual(status["recipients"], ["recipient@example.test"])
            self.assertEqual(notifications.queue_alerts(self.settings, self.items()), 0)
            with self.assertRaises(ValueError):
                notifications.queue_test(self.settings)
            with patch("notifications.send_email") as send:
                self.assertEqual(notifications.deliver_pending(self.settings)["sent"], 0)
                send.assert_not_called()

    def test_default_filter_and_duplicate_cooldown(self):
        sync_action_items(self.settings["database"], [finding(), finding("warning", "warning")])
        self.assertEqual(notifications.queue_alerts(self.settings, self.items(), self.now), 1)
        self.assertEqual(notifications.queue_alerts(self.settings, self.items(), self.now), 0)
        with patch("notifications.send_email") as send:
            self.assertEqual(notifications.deliver_pending(self.settings, self.now)["sent"], 1)
            self.assertEqual(notifications.deliver_pending(self.settings, self.now)["sent"], 0)
            send.assert_called_once()
        self.assertEqual(notifications.queue_alerts(self.settings, self.items(), self.now + timedelta(minutes=29)), 0)
        self.assertEqual(notifications.queue_alerts(self.settings, self.items(), self.now + timedelta(minutes=31)), 1)
        job = self.outbox()[0]
        self.assertEqual(json.loads(job["recipients"]), ["recipient@example.test"])
        self.assertIn("test-server", job["subject"])
        self.assertIn("https://watch.example.test/#actions", job["body"])

    def test_workflow_decisions_cancel_pending_notifications(self):
        for status in ("snoozed", "resolved", "dismissed"):
            with self.subTest(status=status):
                sync_action_items(self.settings["database"], [finding(status)])
                item = next(item for item in self.items() if item["source_key"] == status)
                notifications.queue_alerts(self.settings, [item], self.now)
                update_action_item(self.settings["database"], item["id"], status)
                with patch("notifications.send_email") as send:
                    notifications.deliver_pending(self.settings, self.now)
                    send.assert_not_called()
                self.assertEqual(self.outbox()[-1]["status"], "cancelled")

    def test_disappeared_finding_is_not_emailed(self):
        sync_action_items(self.settings["database"], [finding()])
        notifications.queue_alerts(self.settings, self.items(), self.now)
        sync_action_items(self.settings["database"], [])
        with patch("notifications.send_email") as send:
            notifications.deliver_pending(self.settings, self.now)
            send.assert_not_called()
        self.assertEqual(self.outbox()[0]["status"], "cancelled")

    def test_server_preferences_persist_and_disable_pending_emails(self):
        sync_action_items(self.settings["database"], [finding(), finding("warning", "warning")])
        notifications.update_preferences(self.settings, True, "all")
        self.assertEqual(notifications.queue_alerts(self.settings, self.items(), self.now), 2)
        notifications.update_preferences(self.settings, False, "all")
        self.assertFalse(notifications.public_status(self.settings)["enabled"])
        with patch("notifications.send_email") as send:
            notifications.deliver_pending(self.settings, self.now)
            send.assert_not_called()
        self.assertTrue(all(job["status"] == "cancelled" for job in self.outbox()))

    def test_retries_survive_restart_and_cooldown_uses_success_time(self):
        sync_action_items(self.settings["database"], [finding()])
        notifications.queue_alerts(self.settings, self.items(), self.now)
        with patch("notifications.send_email", side_effect=smtplib.SMTPAuthenticationError(535, b"private-test-secret")):
            result = notifications.deliver_pending(self.settings, self.now)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(self.outbox()[0]["attempts"], 1)
        self.assertNotIn("private-test-secret", json.dumps(self.outbox()))
        self.assertNotIn("private-test-secret", json.dumps(notifications.public_status(self.settings)))
        init_database(self.settings["database"])
        with patch("notifications.send_email") as send:
            notifications.deliver_pending(self.settings, self.now + timedelta(seconds=30))
            send.assert_not_called()
            notifications.deliver_pending(self.settings, self.now + timedelta(minutes=20))
            send.assert_called_once()
        self.assertEqual(notifications.queue_alerts(self.settings, self.items(), self.now + timedelta(minutes=40)), 0)
        self.assertEqual(notifications.queue_alerts(self.settings, self.items(), self.now + timedelta(minutes=51)), 1)

    def test_retry_limit_and_expired_claim_recovery(self):
        test_id = notifications.queue_test(self.settings, self.now)
        with sqlite3.connect(self.settings["database"]) as conn:
            conn.execute("UPDATE email_outbox SET status = 'sending', lease_until = ? WHERE id = ?", ((self.now - timedelta(minutes=1)).isoformat(), test_id))
        with patch("notifications.send_email", side_effect=OSError("connection unavailable")) as send:
            for minute in (0, 1, 3, 7, 15):
                notifications.deliver_pending(self.settings, self.now + timedelta(minutes=minute))
            self.assertEqual(send.call_count, 5)
            notifications.deliver_pending(self.settings, self.now + timedelta(days=1))
            self.assertEqual(send.call_count, 5)
        self.assertEqual(self.outbox()[0]["status"], "failed")

    def test_concurrent_workers_do_not_send_the_same_claim(self):
        notifications.queue_test(self.settings, self.now)
        started, release = threading.Event(), threading.Event()

        def send(settings, job):
            started.set()
            self.assertTrue(release.wait(3))

        with patch("notifications.send_email", side_effect=send) as transport:
            with ThreadPoolExecutor(max_workers=1) as pool:
                first = pool.submit(notifications.deliver_pending, self.settings, self.now)
                self.assertTrue(started.wait(3))
                second = notifications.deliver_pending(self.settings, self.now)
                release.set()
                self.assertEqual(first.result(timeout=3)["sent"], 1)
                self.assertEqual(second["sent"], 0)
            transport.assert_called_once()

    def test_smtp_uses_tls_and_keeps_sender_and_recipient_separate(self):
        test_id = notifications.queue_test(self.settings, self.now)
        with patch("notifications.smtplib.SMTP") as smtp_class:
            smtp = smtp_class.return_value.__enter__.return_value
            smtp.send_message.return_value = {}
            self.assertEqual(notifications.deliver_pending(self.settings, self.now, job_id=test_id)["sent"], 1)
            smtp.starttls.assert_called_once()
            smtp.login.assert_called_once_with("sender@example.test", "private-test-secret")
            message = smtp.send_message.call_args.args[0]
            self.assertEqual(message["From"], "sender@example.test")
            self.assertEqual(message["To"], "recipient@example.test")
            self.assertEqual(smtp.send_message.call_args.kwargs["to_addrs"], ["recipient@example.test"])
            self.assertIn("Test email", message["Subject"])

    def test_implicit_tls_and_partial_recipient_refusal(self):
        notifications.queue_test(self.settings, self.now)
        with patch.dict(os.environ, APACHEWATCH_SMTP_SECURITY="ssl", APACHEWATCH_SMTP_PORT="465"):
            with patch("notifications.smtplib.SMTP_SSL") as smtp_class:
                smtp = smtp_class.return_value.__enter__.return_value
                smtp.send_message.return_value = {"recipient@example.test": (550, b"not accepted")}
                self.assertEqual(notifications.deliver_pending(self.settings, self.now)["failed"], 1)
                smtp.starttls.assert_not_called()
        self.assertEqual(self.outbox()[0]["status"], "pending")

    def test_test_email_is_rate_limited_and_does_not_send_pending_alerts(self):
        sync_action_items(self.settings["database"], [finding()])
        notifications.queue_alerts(self.settings, self.items(), self.now)
        test_id = notifications.queue_test(self.settings, self.now)
        with self.assertRaises(ValueError):
            notifications.queue_test(self.settings, self.now + timedelta(seconds=10))
        with patch("notifications.send_email") as send:
            notifications.deliver_pending(self.settings, self.now, job_id=test_id)
            self.assertEqual(send.call_args.args[1]["kind"], "test")
        self.assertEqual([job["status"] for job in self.outbox()], ["pending", "sent"])

    def test_settings_api_and_test_status_never_expose_credentials(self):
        with patch.dict(config, self.settings, clear=True):
            client = app.test_client()
            response = client.get('/api/notifications/email')
            self.assertTrue(response.get_json()["configured"])
            self.assertNotIn("private-test-secret", response.get_data(as_text=True))
            self.assertEqual(client.patch('/api/notifications/email', json={"enabled":False, "severity":"all"}).status_code, 200)
            self.assertFalse(client.get('/api/notifications/email').get_json()["enabled"])
            self.assertEqual(client.patch('/api/notifications/email', json={"enabled":"yes", "severity":"all"}).status_code, 400)
            self.assertEqual(client.post('/api/notifications/email/test', json={}).status_code, 409)
            notifications.record_monitor_check(config)
            response = client.post('/api/notifications/email/test', json={})
            self.assertEqual(response.status_code, 202)
            self.assertEqual(client.get('/api/notifications/email').get_json()["test"]["status"], "pending")
            self.assertEqual(client.post('/api/notifications/email/test').status_code, 400)

    def test_background_cycle_collects_and_notifies_without_page_requests(self):
        metrics = {
            "timestamp":"2026-10-14T12:00:00", "cpu_percent":12,
            "memory":{"percent":30, "used_gb":3, "total_gb":10},
            "disk":{"percent":92, "used_gb":92, "total_gb":100},
        }
        with patch.dict(config, self.settings, clear=True), patch('apachewatch.collect_metrics', return_value=metrics), patch('notifications.send_email') as send:
            result = run_monitoring_cycle()
            self.assertEqual(result["sent"], 1)
            send.assert_called_once()
            with sqlite3.connect(self.settings["database"]) as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM metrics").fetchone()[0], 1)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 1)
            self.assertTrue(notifications.public_status(self.settings)["monitoring_active"])

    def test_worker_continues_after_a_failed_cycle(self):
        worker = MonitoringWorker()
        with patch('apachewatch.run_monitoring_cycle', side_effect=[RuntimeError('test'), {}]) as cycle, patch('notifications.record_monitor_check') as record, patch.object(app.logger, 'exception'):
            with patch.object(worker.stopped, 'wait', side_effect=[False, True]):
                with patch.object(worker.stopped, 'is_set', side_effect=[False, False, True]):
                    worker.run()
            self.assertEqual(cycle.call_count, 2)
            record.assert_called_once()


if __name__ == '__main__':
    unittest.main()
