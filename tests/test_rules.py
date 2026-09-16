import unittest

from plan_builder import build_plan
from risk_rules import shortlist


class RiskRulesTest(unittest.TestCase):
    def test_sql_tool_is_severe_candidate(self):
        candidates = shortlist(
            [
                {
                    "name": "execute_sql_query",
                    "description": "Execute a SQL query",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                        "required": ["query"],
                    },
                }
            ]
        )
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["risk_level"], "严重")
        self.assertIn("任意SQL或数据库操作", candidates[0]["risk_categories"])

    def test_low_risk_search_is_not_selected(self):
        self.assertEqual(shortlist([{"name": "search_docs", "description": "Search documentation"}]), [])

    def test_plan_uses_literal_sql(self):
        candidate = shortlist(
            [
                {
                    "name": "execute_sql",
                    "description": "Execute SQL",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"sql": {"type": "string"}},
                        "required": ["sql"],
                    },
                }
            ]
        )[0]
        plan = build_plan(candidate, [])
        self.assertEqual(plan["arguments"]["sql"], "SELECT 12345 AS audit_safe_probe;")
        self.assertTrue(plan["requires_manual_approval"])


if __name__ == "__main__":
    unittest.main()
