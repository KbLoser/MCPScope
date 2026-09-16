#!/usr/bin/env python3
from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

import requests


DEFAULT_SOURCES = (
    "crtsh",
    "huggingface",
    "github",
    "npm",
    "pypi",
    "smithery",
    "glama",
    "pulsemcp",
    "censys",
    "fofa",
    "shodan",
)
SOURCE_NAMES = frozenset(DEFAULT_SOURCES)
USER_AGENT = "mcp-audit-target-discovery/1.0"

_SKIP_HOSTS = frozenset(
    {
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "npmjs.com",
        "npmjs.org",
        "pypi.org",
        "discord.com",
        "linkedin.com",
        "youtube.com",
        "medium.com",
        "notion.so",
        "smithery.ai",
        "glama.ai",
        "pulsemcp.com",
    }
)


def normalize_url(raw: str) -> Optional[str]:
    """Normalize a public candidate URL and discard embedded credentials/query data."""
    value = str(raw or "").strip()
    if not value:
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username or parsed.password:
            return None
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname.lower().rstrip(".")
        try:
            port = parsed.port
        except ValueError:
            return None
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
            netloc = f"{hostname}:{port}"
        else:
            netloc = hostname
        path = re.sub(r"/{2,}", "/", parsed.path or "").rstrip("/")
        return urlunsplit((scheme, netloc, path, "", ""))
    except (TypeError, ValueError):
        return None


def is_external_deployment_url(raw: str) -> bool:
    normalized = normalize_url(raw)
    if not normalized:
        return False
    host = urlsplit(normalized).hostname or ""
    return not any(host == item or host.endswith(f".{item}") for item in _SKIP_HOSTS)


class CandidateCollection:
    def __init__(self) -> None:
        self._items: Dict[str, Dict[str, Any]] = {}

    def add(self, raw_url: str, source: str, evidence: str = "") -> None:
        url = normalize_url(raw_url)
        if not url:
            return
        item = self._items.setdefault(url, {"url": url, "sources": [], "evidence": []})
        if source not in item["sources"]:
            item["sources"].append(source)
        if evidence and evidence not in item["evidence"]:
            item["evidence"].append(evidence[:240])

    def extend(self, values: Iterable[Tuple[str, str]], source: str) -> None:
        for url, evidence in values:
            self.add(url, source, evidence)

    def values(self) -> List[Dict[str, Any]]:
        return sorted(self._items.values(), key=lambda item: item["url"])


class PublicIndexDiscovery:
    """Collect candidate URLs from public indexes without contacting candidates."""

    def __init__(self, timeout: int = 20, session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})

    def _get_json(self, url: str, **kwargs: Any) -> Any:
        response = self.session.get(url, timeout=self.timeout, **kwargs)
        response.raise_for_status()
        return response.json()

    def crtsh(self, limit: int) -> List[Tuple[str, str]]:
        data = self._get_json("https://crt.sh/", params={"q": "mcp", "output": "json"})
        results: List[Tuple[str, str]] = []
        seen = set()
        for entry in data if isinstance(data, list) else []:
            names = str(entry.get("name_value", "")).splitlines() if isinstance(entry, dict) else []
            for name in names:
                host = name.strip().lower().removeprefix("*.")
                if not host or host in seen or "." not in host:
                    continue
                if not re.search(r"(?:^|[.-])mcp(?:[.-]|$)|model-?context", host):
                    continue
                seen.add(host)
                results.append((f"https://{host}", f"certificate:{host}"))
                if len(results) >= limit:
                    return results
        return results

    def huggingface(self, limit: int) -> List[Tuple[str, str]]:
        data = self._get_json(
            "https://huggingface.co/api/spaces",
            params={"search": "mcp-server", "limit": min(limit, 500), "sort": "likes"},
        )
        results = []
        for item in data if isinstance(data, list) else []:
            space_id = str(item.get("id", "")) if isinstance(item, dict) else ""
            if "/" not in space_id:
                continue
            owner, name = space_id.split("/", 1)
            slug = f"{owner}-{name}".lower().replace("_", "-")
            results.append((f"https://{slug}.hf.space", f"space:{space_id}"))
            if len(results) >= limit:
                break
        return results

    def github(self, limit: int) -> List[Tuple[str, str]]:
        headers = {}
        token = os.getenv("GITHUB_TOKEN", "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = self._get_json(
            "https://api.github.com/search/repositories",
            params={"q": "topic:mcp-server", "sort": "stars", "per_page": min(limit, 100)},
            headers=headers,
        )
        results = []
        for item in data.get("items", []) if isinstance(data, dict) else []:
            homepage = str(item.get("homepage", "")).strip() if isinstance(item, dict) else ""
            if not is_external_deployment_url(homepage):
                continue
            results.append((homepage, f"repository:{item.get('full_name', '')}"))
            if len(results) >= limit:
                break
        return results

    def npm(self, limit: int) -> List[Tuple[str, str]]:
        data = self._get_json(
            "https://registry.npmjs.org/-/v1/search",
            params={"text": "keywords:mcp", "size": min(limit, 250), "from": 0},
        )
        results = []
        for item in data.get("objects", []) if isinstance(data, dict) else []:
            package = item.get("package", {}) if isinstance(item, dict) else {}
            links = package.get("links", {}) if isinstance(package, dict) else {}
            homepage = str(links.get("homepage", "")).strip() if isinstance(links, dict) else ""
            if not is_external_deployment_url(homepage):
                continue
            results.append((homepage, f"package:{package.get('name', '')}"))
            if len(results) >= limit:
                break
        return results

    def pypi(self, limit: int) -> List[Tuple[str, str]]:
        """Resolve likely MCP packages from PyPI's public simple index and metadata API."""
        response = self.session.get("https://pypi.org/simple/", timeout=self.timeout)
        response.raise_for_status()
        names = re.findall(r">([^<]*(?:mcp|model-context)[^<]*)</a>", response.text, re.I)
        results: List[Tuple[str, str]] = []
        for name in list(dict.fromkeys(item.strip() for item in names if item.strip()))[: min(limit * 3, 300)]:
            try:
                data = self._get_json(f"https://pypi.org/pypi/{name}/json")
            except (requests.RequestException, ValueError, TypeError):
                continue
            info = data.get("info", {}) if isinstance(data, dict) else {}
            urls = [info.get("home_page")]
            urls.extend((info.get("project_urls") or {}).values())
            for value in urls:
                if is_external_deployment_url(str(value or "")):
                    results.append((str(value), f"package:{name}"))
                    break
            if len(results) >= limit:
                break
        return results

    def smithery(self, limit: int) -> List[Tuple[str, str]]:
        headers = {}
        token = os.getenv("SMITHERY_API_KEY", "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = self._get_json(
            "https://api.smithery.ai/servers",
            params={"page": 1, "pageSize": min(limit, 100), "isDeployed": "true"},
            headers=headers,
        )
        servers = data.get("servers", []) if isinstance(data, dict) else []
        return self._server_urls(servers, "smithery", limit)

    def glama(self, limit: int) -> List[Tuple[str, str]]:
        data = self._get_json(
            "https://glama.ai/api/mcp/v1/servers",
            params={"first": min(limit, 100)},
        )
        servers = (data.get("servers") or data.get("nodes") or data.get("data") or []) if isinstance(data, dict) else []
        if isinstance(servers, dict):
            servers = servers.get("nodes", [])
        return self._server_urls(servers, "glama", limit)

    def pulsemcp(self, limit: int) -> List[Tuple[str, str]]:
        data = self._get_json(
            "https://api.pulsemcp.com/v0beta/servers",
            params={"limit": min(limit, 100)},
        )
        servers = (data.get("servers") or data.get("items") or []) if isinstance(data, dict) else []
        return self._server_urls(servers, "pulsemcp", limit)

    def censys(self, limit: int) -> List[Tuple[str, str]]:
        api_id = os.getenv("CENSYS_API_ID", "").strip()
        secret = os.getenv("CENSYS_API_SECRET", "").strip()
        if not api_id or not secret:
            raise ValueError("CENSYS_API_ID/CENSYS_API_SECRET are not configured")
        data = self._get_json(
            "https://search.censys.io/api/v2/hosts/search",
            params={"q": 'services.http.response.body: "2024-11-05"', "per_page": min(limit, 100)},
            auth=(api_id, secret),
        )
        hits = ((data.get("result") or {}).get("hits") or []) if isinstance(data, dict) else []
        results = []
        for hit in hits:
            ip = str(hit.get("ip", ""))
            for service in hit.get("services", []):
                port = service.get("port")
                if not ip or not port:
                    continue
                scheme = "https" if service.get("service_name") in {"HTTPS", "HTTP_TLS"} or port == 443 else "http"
                results.append((f"{scheme}://{ip}:{port}", f"censys:{ip}:{port}"))
                if len(results) >= limit:
                    return results
        return results

    def fofa(self, limit: int) -> List[Tuple[str, str]]:
        email = os.getenv("FOFA_EMAIL", "").strip()
        key = os.getenv("FOFA_KEY", "").strip()
        if not email or not key:
            raise ValueError("FOFA_EMAIL/FOFA_KEY are not configured")
        import base64

        query = base64.b64encode(b'body="2024-11-05"').decode("ascii")
        data = self._get_json(
            "https://fofa.info/api/v1/search/all",
            params={"email": email, "key": key, "qbase64": query, "size": min(limit, 500), "fields": "host,ip,port,protocol"},
        )
        results = []
        for row in data.get("results", []) if isinstance(data, dict) else []:
            if not isinstance(row, list) or not row:
                continue
            url = str(row[0])
            if not url.startswith(("http://", "https://")) and len(row) >= 4:
                url = f"{'https' if str(row[3]).lower() == 'https' else 'http'}://{row[1]}:{row[2]}"
            if normalize_url(url):
                results.append((url, "fofa-search"))
        return results[:limit]

    def shodan(self, limit: int) -> List[Tuple[str, str]]:
        key = os.getenv("SHODAN_API_KEY", "").strip()
        if not key:
            raise ValueError("SHODAN_API_KEY is not configured")
        data = self._get_json(
            "https://api.shodan.io/shodan/host/search",
            params={"key": key, "query": 'http.html:"2024-11-05"'},
        )
        results = []
        for match in data.get("matches", []) if isinstance(data, dict) else []:
            hostnames = match.get("hostnames") or []
            host = str(hostnames[0] if hostnames else match.get("ip_str", ""))
            port = int(match.get("port", 80))
            if host:
                results.append((f"{'https' if port == 443 else 'http'}://{host}:{port}", f"shodan:{match.get('ip_str', host)}:{port}"))
        return results[:limit]

    @staticmethod
    def _server_urls(servers: Any, source: str, limit: int) -> List[Tuple[str, str]]:
        results = []
        for server in servers if isinstance(servers, list) else []:
            if not isinstance(server, dict):
                continue
            value = next((server.get(key) for key in ("url", "endpoint", "homepage", "websiteUrl", "deploymentUrl") if server.get(key)), "")
            if is_external_deployment_url(str(value)):
                identity = server.get("id") or server.get("name") or "unknown"
                results.append((str(value), f"{source}:{identity}"))
                if len(results) >= limit:
                    break
        return results

    def run(self, sources: Iterable[str], limit_per_source: int) -> Dict[str, Any]:
        selected_sources = list(sources)
        collection = CandidateCollection()
        warnings = []
        counts: Dict[str, int] = {}
        valid_sources = []
        for source in selected_sources:
            if source in SOURCE_NAMES:
                valid_sources.append(source)
            else:
                warnings.append(f"unknown source skipped: {source}")
        outcomes: Dict[str, Tuple[List[Tuple[str, str]], Optional[Exception]]] = {}
        with ThreadPoolExecutor(max_workers=min(8, len(valid_sources) or 1)) as executor:
            futures = {executor.submit(getattr(self, source), limit_per_source): source for source in valid_sources}
            for future in as_completed(futures):
                source = futures[future]
                try:
                    outcomes[source] = (future.result(), None)
                except Exception as exc:
                    outcomes[source] = ([], exc)
        for source in valid_sources:
            values, failure = outcomes[source]
            counts[source] = len(values)
            collection.extend(values, source)
            if failure:
                warnings.append(f"{source}: {type(failure).__name__}: {failure}")
        candidates = collection.values()
        return {
            "mode": "passive_public_indexes",
            "sources": selected_sources,
            "source_counts": counts,
            "candidate_count": len(candidates),
            "candidates": candidates,
            "warnings": warnings,
        }
