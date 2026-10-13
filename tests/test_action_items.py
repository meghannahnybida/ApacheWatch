import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from apachewatch import (
    app,
    build_action_candidates,
    config,
    get_action_items,
    sync_action_items,
    update_action_item,
)


def candidate(summary="Disk usage is 91%, threshold is 85%", value=91):
    return {
        "source": "alert",
        "source_key": "alert:disk_percent",
        "severity": "critical",
        "title": "Disk usage is above threshold",
        "summary": summary,
        "evidence": {"alert_type": "disk_percent", "value": value, "threshold": 85},
        "related_view": "overview",
        "related_query": "",
        "occurrence_count": 1,
    }


class ActionItemStorageTests(unittest.TestCase):
    def test_only_repeated_error_groups_enter_action_center(self):
        metrics = {
            "disk": {"percent": 1},
            "memory": {"percent": 1},
            "cpu_percent": 1,
        }
        errors = [
            {"timestamp": "2026-09-20T12:00:00", "level": "error", "message": "[pid 1] recurring failure"},
            {"timestamp": "2026-09-20T12:01:00", "level": "error", "message": "[pid 2] recurring failure"},
            {"timestamp": "2026-09-20T12:02:00", "level": "error", "message": "one-off failure"},
        ]

        items = build_action_candidates(metrics=metrics, access_entries=[], error_entries=errors)
        error_items = [item for item in items if item["source"] == "error"]

        self.assertEqual(len(error_items), 1)
        self.assertEqual(error_items[0]["occurrence_count"], 2)

    def test_refreshes_evidence_without_losing_workflow_state(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "actions.db")
            sync_action_items(db_path, [candidate()])
            items, _ = get_action_items(db_path, status="all")
            item_id = items[0]["id"]

            update_action_item(db_path, item_id, "acknowledged", note="Checking disk cleanup")
            sync_action_items(db_path, [candidate("Disk usage is 94%, threshold is 85%", 94)])
            items, summary = get_action_items(db_path, status="all")

        self.assertEqual(items[0]["status"], "acknowledged")
        self.assertEqual(items[0]["note"], "Checking disk cleanup")
        self.assertEqual(items[0]["evidence"]["value"], 94)
        self.assertEqual(summary["acknowledged"], 1)

    def test_expired_snooze_returns_to_new(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "actions.db")
            sync_action_items(db_path, [candidate()])
            items, _ = get_action_items(db_path, status="all")
            update_action_item(db_path, items[0]["id"], "snoozed", snooze_minutes=60)

            conn = sqlite3.connect(db_path)
            conn.execute(
                "UPDATE action_items SET snoozed_until = ?",
                ((datetime.now() - timedelta(minutes=1)).isoformat(),),
            )
            conn.commit()
            conn.close()
            items, summary = get_action_items(db_path, status="all")

        self.assertEqual(items[0]["status"], "new")
        self.assertEqual(summary["new"], 1)

    def test_sync_marks_findings_missing_from_latest_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "actions.db")
            sync_action_items(db_path, [candidate()])
            sync_action_items(db_path, [])
            items, _ = get_action_items(db_path, status="all")

        self.assertFalse(items[0]["currently_observed"])

    def test_resolved_finding_reopens_only_after_it_disappears_and_returns(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "actions.db")
            sync_action_items(db_path, [candidate()])
            items, _ = get_action_items(db_path, status="all")
            update_action_item(db_path, items[0]["id"], "resolved")

            sync_action_items(db_path, [candidate()])
            items, _ = get_action_items(db_path, status="all")
            self.assertEqual(items[0]["status"], "resolved")

            sync_action_items(db_path, [])
            sync_action_items(db_path, [candidate()])
            items, _ = get_action_items(db_path, status="all")

        self.assertEqual(items[0]["status"], "new")


class ActionItemApiTests(unittest.TestCase):
    def test_can_acknowledge_and_retain_note(self):
        with tempfile.TemporaryDirectory() as directory:
            previous_database = config["database"]
            config["database"] = str(Path(directory) / "actions.db")
            try:
                with patch("apachewatch.build_action_candidates", return_value=[candidate()]):
                    response = app.test_client().get("/api/action-items?status=all")
                    item_id = response.get_json()["items"][0]["id"]
                    update_response = app.test_client().patch(
                        f"/api/action-items/{item_id}",
                        json={"status": "acknowledged", "note": "Assigned to Meghan"},
                    )
                    refreshed = app.test_client().get("/api/action-items?status=all")
            finally:
                config["database"] = previous_database

        self.assertEqual(response.status_code, 200)
        self.assertEqual(update_response.status_code, 200)
        item = refreshed.get_json()["items"][0]
        self.assertEqual(item["status"], "acknowledged")
        self.assertEqual(item["note"], "Assigned to Meghan")

    def test_rejects_invalid_status(self):
        with tempfile.TemporaryDirectory() as directory:
            previous_database = config["database"]
            config["database"] = str(Path(directory) / "actions.db")
            try:
                sync_action_items(config["database"], [candidate()])
                items, _ = get_action_items(config["database"], status="all")
                response = app.test_client().patch(
                    f"/api/action-items/{items[0]['id']}",
                    json={"status": "deleted"},
                )
            finally:
                config["database"] = previous_database

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "invalid action item status")


if __name__ == "__main__":
    unittest.main()
