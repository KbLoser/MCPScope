import unittest

from target_discovery import CandidateCollection, PublicIndexDiscovery, normalize_url


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, routes):
        self.routes = routes
        self.headers = {}

    def get(self, url, **kwargs):
        return FakeResponse(self.routes[url])


class TargetDiscoveryTest(unittest.TestCase):
    def test_normalize_url_removes_credentials_query_and_default_port(self):
        self.assertEqual(
            normalize_url("HTTPS://Example.COM:443/mcp/?token=secret#fragment"),
            "https://example.com/mcp",
        )
        self.assertIsNone(normalize_url("https://user:password@example.com/mcp"))
        self.assertIsNone(normalize_url("file:///tmp/server"))

    def test_collection_merges_sources_without_duplicates(self):
        values = CandidateCollection()
        values.add("https://EXAMPLE.com/mcp/", "github", "repository:demo/a")
        values.add("https://example.com/mcp", "npm", "package:demo")
        self.assertEqual(len(values.values()), 1)
        self.assertEqual(values.values()[0]["sources"], ["github", "npm"])

    def test_public_indexes_are_parsed_without_contacting_candidates(self):
        session = FakeSession(
            {
                "https://crt.sh/": [{"name_value": "*.mcp.example.com\nunrelated.example.com"}],
                "https://huggingface.co/api/spaces": [{"id": "owner/MCP_Demo"}],
                "https://api.github.com/search/repositories": {
                    "items": [
                        {"full_name": "demo/server", "homepage": "https://demo.example/mcp"},
                        {"full_name": "demo/source", "homepage": "https://github.com/demo/source"},
                    ]
                },
                "https://registry.npmjs.org/-/v1/search": {
                    "objects": [
                        {
                            "package": {
                                "name": "demo-mcp",
                                "links": {"homepage": "https://npm-demo.example/api/mcp"},
                            }
                        }
                    ]
                },
            }
        )
        result = PublicIndexDiscovery(session=session).run(
            ["crtsh", "huggingface", "github", "npm"],
            10,
        )
        urls = {item["url"] for item in result["candidates"]}
        self.assertEqual(
            urls,
            {
                "https://mcp.example.com",
                "https://owner-mcp-demo.hf.space",
                "https://demo.example/mcp",
                "https://npm-demo.example/api/mcp",
            },
        )
        self.assertEqual(result["warnings"], [])


if __name__ == "__main__":
    unittest.main()
