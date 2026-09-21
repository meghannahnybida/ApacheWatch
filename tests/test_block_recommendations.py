import unittest

from apachewatch import analyze_block_recommendations, app


def access_entry(ip, minute, path="/", status=200, user_agent="Mozilla/5.0"):
    return {
        "ip": ip,
        "timestamp": f"20/Sep/2026:12:{minute:02d}:00 +0000",
        "method": "GET",
        "path": path,
        "status": status,
        "user_agent": user_agent,
    }


class BlockRecommendationTests(unittest.TestCase):
    def test_benign_traffic_is_not_recommended(self):
        entries = [access_entry("192.0.2.10", minute % 60) for minute in range(50)]

        self.assertEqual(analyze_block_recommendations(entries), [])

    def test_scanner_is_recommended_with_evidence_and_rules(self):
        entries = [
            access_entry("192.0.2.10", 0, f"/.env?attempt={index}", 404, "curl/8.0")
            for index in range(12)
        ]

        recommendations = analyze_block_recommendations(entries)
        ip_result = next(item for item in recommendations if item["target_type"] == "ip")

        self.assertEqual(ip_result["action"], "block_ip")
        self.assertGreaterEqual(ip_result["score"], 60)
        self.assertEqual(ip_result["peak_requests_per_minute"], 12)
        self.assertIn("Require not ip 192.0.2.10", ip_result["rules"]["apache"])
        self.assertTrue(ip_result["suspicious_paths"])

    def test_allowlist_excludes_matching_network(self):
        entries = [
            access_entry("10.20.30.40", 0, "/.git/config", 404, "sqlmap")
            for _ in range(40)
        ]

        recommendations = analyze_block_recommendations(entries, {
            "allowlist": ["10.0.0.0/8"],
            "minimum_score": 35,
        })

        self.assertEqual(recommendations, [])

    def test_clustered_attackers_produce_range_review(self):
        entries = []
        for ip in ("192.0.2.10", "192.0.2.11"):
            entries.extend(access_entry(ip, 0, "/wp-login.php", 404, "curl/8.0") for _ in range(12))

        recommendations = analyze_block_recommendations(entries)
        range_result = next(item for item in recommendations if item["target_type"] == "range")

        self.assertEqual(range_result["target"], "192.0.2.0/24")
        self.assertEqual(range_result["action"], "consider_range")
        self.assertEqual(range_result["member_ips"], ["192.0.2.10", "192.0.2.11"])

    def test_api_rejects_invalid_scan_value(self):
        response = app.test_client().get("/api/block-recommendations?scan=many")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "scan must be an integer")


if __name__ == "__main__":
    unittest.main()
