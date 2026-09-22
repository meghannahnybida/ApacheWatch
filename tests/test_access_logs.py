import tempfile
import unittest
from pathlib import Path

from apachewatch import app, config


class AccessLogApiTests(unittest.TestCase):
    def test_returns_recent_requests_newest_first_with_summary(self):
        lines = [
            '192.0.2.10 - - [21/Sep/2026:10:00:00 +0000] "GET /first HTTP/1.1" 200 123 "-" "Mozilla/5.0"',
            '192.0.2.11 - - [21/Sep/2026:10:01:00 +0000] "POST /missing HTTP/1.1" 404 25 "https://example.com" "curl/8.0"',
            '192.0.2.10 - - [21/Sep/2026:10:02:00 +0000] "GET /broken HTTP/1.1" 500 0 "-" "Mozilla/5.0"',
        ]

        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "access.log"
            log_path.write_text("\n".join(lines) + "\n")
            previous_path = config["apache"].get("access_log")
            config["apache"]["access_log"] = str(log_path)
            try:
                response = app.test_client().get("/api/access-logs?limit=10")
            finally:
                config["apache"]["access_log"] = previous_path

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual([entry["path"] for entry in data["entries"]], ["/broken", "/missing", "/first"])
        self.assertEqual(data["summary"]["total"], 3)
        self.assertEqual(data["summary"]["unique_ips"], 2)
        self.assertEqual(data["summary"]["success"], 1)
        self.assertEqual(data["summary"]["client_errors"], 1)
        self.assertEqual(data["summary"]["server_errors"], 1)

    def test_rejects_invalid_limit(self):
        response = app.test_client().get("/api/access-logs?limit=many")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "limit must be an integer")


if __name__ == "__main__":
    unittest.main()
