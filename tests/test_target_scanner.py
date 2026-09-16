import json
import tempfile
import unittest
from pathlib import Path

from target_scanner import assess_target, load_targets, scan_targets


class TargetScannerTest(unittest.TestCase):
    def test_load_targets_supports_discovery_document_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.json"
            path.write_text(
                json.dumps(
                    {
                        "candidates": [
                            {"url": "https://Example.com/mcp/", "sources": ["github"]},
                            {"url": "https://example.com/mcp", "sources": ["npm"]},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            targets = load_targets(path)
        self.assertEqual(targets, [{"url": "https://example.com/mcp", "sources": ["github", "npm"]}])

    def test_assessment_marks_unauthenticated_sql_as_severe(self):
        record = assess_target(
            {"url": "https://example.com/mcp", "sources": ["test"]},
            {
                "status": "success",
                "endpoint": "https://example.com/mcp",
                "transport": "streamable-http",
                "tools": [
                    {
                        "name": "execute_sql",
                        "description": "Execute a SQL query",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"sql": {"type": "string"}},
                        },
                    }
                ],
            },
        )
        self.assertEqual(record["risk_level"], "严重")
        self.assertEqual(record["auth_state"], "none")
        self.assertGreaterEqual(record["priority_score"], 95)
        self.assertEqual(len(record["high_risk_candidates"]), 1)

    def test_failed_authentication_is_not_reported_as_no_auth(self):
        record = assess_target(
            {"url": "https://example.com/mcp", "sources": []},
            {
                "status": "failed",
                "tools": [],
                "attempts": [{"status": "failed", "error": "HTTP 401 Unauthorized"}],
            },
        )
        self.assertEqual(record["auth_state"], "required")
        self.assertFalse(record["confirmed_mcp"])

    def test_scan_targets_preserves_input_order_and_contains_probe_errors(self):
        targets = [
            {"url": "https://a.example", "sources": []},
            {"url": "https://b.example", "sources": []},
        ]

        def probe(url):
            if url == "https://a.example":
                return {"status": "no_tools", "tools": []}
            raise RuntimeError("offline")

        records = scan_targets(targets, probe, concurrency=2)
        self.assertEqual([item["url"] for item in records], ["https://a.example", "https://b.example"])
        self.assertTrue(records[0]["confirmed_mcp"])
        self.assertIn("offline", records[1]["error"])


if __name__ == "__main__":
    unittest.main()
