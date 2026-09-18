import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "build_public_site_data.py"
SPEC = importlib.util.spec_from_file_location("build_public_site_data", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PublicSiteDataTest(unittest.TestCase):
    def test_summary_counts_services_and_evidence_without_raw_targets(self):
        candidates = [
            {
                "mcp_id": "1",
                "工具名称 (Tool Name)": "shell",
                "候选风险等级": "严重",
                "高危风险类型": "命令或代码执行",
                "手动测试状态": "已测试",
                "是否已确认漏洞": "是",
            },
            {
                "mcp_id": "2",
                "工具名称 (Tool Name)": "read_file",
                "候选风险等级": "高",
                "高危风险类型": "文件系统访问或破坏",
                "手动测试状态": "已测试（鉴权拦截）",
                "是否已确认漏洞": "否",
            },
        ]
        classified = [
            {
                "primary_category": "remote code execution",
                "evidence_scope": "operation or impact evidence",
            }
        ]

        result = MODULE.build_summary(candidates, classified)
        MODULE.validate_public_summary(result)

        self.assertEqual(result["headline"]["services"], 2)
        self.assertEqual(result["headline"]["findings"], 1)
        self.assertEqual(result["headline"]["operation_evidence"], 1)
        self.assertFalse(result["publication"]["raw_targets_published"])

    def test_redaction_guard_rejects_network_addresses(self):
        with self.assertRaises(ValueError):
            MODULE.validate_public_summary({"case": "https://target.example/mcp"})


if __name__ == "__main__":
    unittest.main()
