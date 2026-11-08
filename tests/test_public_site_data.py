import importlib.util
import json
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "build_public_site_data.py"
SPEC = importlib.util.spec_from_file_location("build_public_site_data", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PublicSiteDataTest(unittest.TestCase):
    def test_summary_counts_services_and_evidence_without_raw_targets(self):
        vulnerabilities = [
            {
                "mcp_id": "1",
                "工具名称 (Tool Name)": "shell",
                "工具功能分类": "主机与代码执行",
                "数据来源": "无认证扫描累计",
            },
            {
                "mcp_id": "2",
                "工具名称 (Tool Name)": "read_file",
                "工具功能分类": "文件与内容存储",
                "数据来源": "IP地址工具数据",
            },
        ]

        result = MODULE.build_summary(vulnerabilities)
        MODULE.validate_public_summary(result)

        self.assertEqual(result["headline"]["services"], 2)
        self.assertEqual(result["headline"]["findings"], 2)
        self.assertEqual(result["headline"]["unique_tools"], 2)
        self.assertEqual(sum(item["value"] for item in result["record_sources"]), 2)
        self.assertFalse(result["publication"]["raw_targets_published"])

        records = MODULE.build_public_records(vulnerabilities)
        MODULE.validate_public_records(records)
        self.assertEqual(len(records["records"]), 2)
        self.assertTrue(all("***" in item["masked_tool_name"] for item in records["records"]))
        self.assertNotIn("shell", json.dumps(records, ensure_ascii=False))

    def test_redaction_guard_rejects_network_addresses(self):
        with self.assertRaises(ValueError):
            MODULE.validate_public_summary({"case": "https://target.example/mcp"})


if __name__ == "__main__":
    unittest.main()
