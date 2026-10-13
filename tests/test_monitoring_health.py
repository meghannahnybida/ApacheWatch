import tempfile
import unittest
from pathlib import Path

from apachewatch import app, collect_monitoring_health


class MonitoringHealthTests(unittest.TestCase):
    def test_reports_readable_and_missing_log_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            error_log = Path(directory) / "error.log"
            error_log.write_text("test entry\n")
            missing_access_log = Path(directory) / "access.log"
            health = collect_monitoring_health({
                "apache": {
                    "error_log": str(error_log),
                    "access_log": str(missing_access_log),
                }
            })

        self.assertIn("detected", health["apache"])
        self.assertIsInstance(health["apache"]["containerized"], bool)
        self.assertEqual(health["logs"][0]["status"], "ready")
        self.assertEqual(health["logs"][0]["size_bytes"], 11)
        self.assertEqual(health["logs"][1]["status"], "missing")

    def test_health_endpoint_returns_all_sources(self):
        response = app.test_client().get("/api/monitoring-health")

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual([item["label"] for item in data["logs"]], ["Error log", "Access log"])


if __name__ == "__main__":
    unittest.main()
