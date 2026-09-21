import unittest

from apachewatch import app, group_error_incidents


class IncidentGroupingTests(unittest.TestCase):
    def test_groups_variable_request_context_and_collects_urls(self):
        entries = [
            {
                "timestamp": "Wed Dec 18 15:00:00.000001 2024",
                "level": "error",
                "message": "[pid 1] [client 10.0.0.1:123] AH001: access to /one denied",
            },
            {
                "timestamp": "Wed Dec 18 15:05:00.000001 2024",
                "level": "error",
                "message": "[pid 2] [client 10.0.0.2:456] AH001: access to /two denied",
            },
            {
                "timestamp": "Wed Dec 18 15:10:00.000001 2024",
                "level": "error",
                "message": "[pid 3] [client 10.0.0.3:789] AH001: access to /one denied",
            },
        ]

        incidents = group_error_incidents(entries)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["count"], 3)
        self.assertEqual(incidents[0]["affected_urls"], ["/one", "/two"])
        self.assertEqual(incidents[0]["trend"], [1, 0, 1, 0, 1])
        self.assertIn("pid 3", incidents[0]["occurrences"][0]["message"])
        self.assertFalse(incidents[0]["occurrences_truncated"])

    def test_retains_only_ten_latest_occurrences(self):
        entries = [
            {
                "timestamp": f"2024-12-18T15:{minute:02d}:00",
                "level": "warn",
                "message": f"[pid {minute}] same warning",
            }
            for minute in range(12)
        ]

        incident = group_error_incidents(entries)[0]

        self.assertEqual(incident["count"], 12)
        self.assertEqual(len(incident["occurrences"]), 10)
        self.assertIn("pid 11", incident["occurrences"][0]["message"])
        self.assertTrue(incident["occurrences_truncated"])

    def test_incident_api_rejects_invalid_numeric_options(self):
        response = app.test_client().get("/api/incidents?limit=lots")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "limit and scan must be integers")


if __name__ == "__main__":
    unittest.main()
