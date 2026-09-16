import unittest
import tempfile
import json
from pathlib import Path

from target_reporting import compare_scans, load_scan, markdown_report, summarize_scan


def record(url, risk="高", tools=None):
    tools = tools or []
    return {
        "url": url,
        "confirmed_mcp": True,
        "risk_level": risk,
        "priority_score": 75,
        "auth_state": "none",
        "transport": "streamable-http",
        "platform": "unknown",
        "tool_count": len(tools),
        "tools": [{"name": name} for name in tools],
        "high_risk_candidates": [{}] if risk in {"严重", "高"} else [],
    }


class TargetReportingTest(unittest.TestCase):
    def test_load_scan_accepts_jsonl(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan.jsonl"
            path.write_text("\n".join(json.dumps(item) for item in [record("https://a.example"), record("https://b.example")]), encoding="utf-8")
            loaded = load_scan(path)
        self.assertEqual(len(loaded["records"]), 2)

    def test_summary_counts_confirmed_records_and_tools(self):
        document = {
            "records": [
                record("https://a.example", "严重", ["execute_sql"]),
                record("https://b.example", "未发现高风险工具", ["search_docs"]),
                {"url": "https://down.example", "confirmed_mcp": False},
            ]
        }
        summary = summarize_scan(document)
        self.assertEqual(summary["scanned_target_count"], 3)
        self.assertEqual(summary["confirmed_mcp_count"], 2)
        self.assertEqual(summary["high_risk_target_count"], 1)
        self.assertEqual(summary["top_tools"][0]["count"], 1)

    def test_markdown_report_contains_sorted_server_table(self):
        markdown = markdown_report(
            {"records": [record("https://low.example", "未发现高风险工具"), record("https://critical.example", "严重")]}
        )
        self.assertLess(markdown.index("https://critical.example"), markdown.index("https://low.example"))
        self.assertIn("| Confirmed MCP | 2 |", markdown)

    def test_diff_tracks_targets_risk_and_tool_changes(self):
        old = {
            "records": [
                record("https://gone.example", "高", ["write_file"]),
                record("https://same.example", "高", ["read_file"]),
            ]
        }
        new = {
            "records": [
                record("https://new.example", "严重", ["execute_sql"]),
                record("https://same.example", "严重", ["read_file", "fetch_url"]),
            ]
        }
        result = compare_scans(old, new)
        self.assertEqual(result["new_targets"], ["https://new.example"])
        self.assertEqual(result["disappeared_targets"], ["https://gone.example"])
        self.assertEqual(result["risk_changes"][0]["new"], "严重")
        self.assertEqual(result["tool_changes"][0]["added"], ["fetch_url"])


if __name__ == "__main__":
    unittest.main()
