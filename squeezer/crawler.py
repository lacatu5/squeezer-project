import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse, parse_qs

from pydantic import BaseModel, Field as PDField

from squeezer.utils import load_static_files_config, load_keywords_config

_STATIC_CONFIG = load_static_files_config()
_KEYWORDS_CONFIG = load_keywords_config()
_STATIC_EXTENSIONS = set(ext.lstrip('.') for ext in _STATIC_CONFIG["extensions"])
_STATIC_PATHS = set(_STATIC_CONFIG["paths"])


@dataclass
class KatanaEndpoint:
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    content_length: int = 0
    source: str = "unknown"
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    query_params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "type": self._classify_type(),
            "discovery_method": "katana",
            "status_code": self.status_code,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "source": self.source,
            "timestamp": self.timestamp,
            "interesting": self._is_interesting(),
            "query_params": self.query_params,
        }

    def _classify_type(self) -> str:
        url_lower = self.url.lower()
        if any(p in url_lower for p in ["/api/", "/rest/", "/graphql"]):
            return "api"
        if any(self.url.lower().endswith(f".{ext}") for ext in _STATIC_EXTENSIONS):
            return "static"
        if any(p in url_lower for p in _KEYWORDS_CONFIG["auth"]):
            return "auth"
        if any(p in url_lower for p in _KEYWORDS_CONFIG["admin"]):
            return "admin"
        return "page"

    def _is_interesting(self) -> bool:
        url_lower = self.url.lower()
        return any(pattern in url_lower for pattern in _KEYWORDS_CONFIG["interesting"])


@dataclass
class KatanaStatistics:
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    unique_urls: int = 0
    unique_domains: int = 0
    endpoints_by_method: Dict[str, int] = field(default_factory=dict)
    endpoints_by_status: Dict[str, int] = field(default_factory=dict)
    api_endpoints: int = 0
    html_pages: int = 0
    forms_discovered: int = 0
    input_fields_discovered: int = 0
    authentication_detected: List[str] = field(default_factory=list)
    javascript_files: int = 0
    interesting_endpoints: int = 0
    start_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    end_time: Optional[str] = None
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "unique_urls": self.unique_urls,
            "unique_domains": self.unique_domains,
            "endpoints_by_method": self.endpoints_by_method,
            "endpoints_by_status": self.endpoints_by_status,
            "api_endpoints": self.api_endpoints,
            "html_pages": self.html_pages,
            "forms_discovered": self.forms_discovered,
            "input_fields_discovered": self.input_fields_discovered,
            "authentication_detected": self.authentication_detected,
            "javascript_files": self.javascript_files,
            "interesting_endpoints": self.interesting_endpoints,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
        }


class SimpleCrawlerReport(BaseModel):
    target: str
    timestamp: str
    summary: Dict[str, int]
    endpoints: List[Dict[str, Any]] = PDField(default_factory=list)
    cookies: List[str] = PDField(default_factory=list)
    discovered_params: Dict[str, List[str]] = PDField(default_factory=dict)


class KatanaCrawler:
    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        js_crawl: bool = True,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        katana_path: str = "katana",
        timeout: int = 300,
        filter_static: bool = True,
    ):
        self.base_url = base_url
        self.max_depth = max_depth
        self.js_crawl = js_crawl
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.katana_path = katana_path
        self.timeout = timeout
        self.filter_static = filter_static
        self.endpoints: List[KatanaEndpoint] = []
        self.forms: List[Dict[str, Any]] = []
        self.stats = KatanaStatistics()
        self.all_discovered_params: Dict[str, Set[str]] = {}

    def _build_katana_command(self, output_file: Optional[str] = None) -> List[str]:
        cmd = [
            self.katana_path,
            "-u", self.base_url,
            "-d", str(self.max_depth),
            "-jsonl",
            "-silent",
        ]
        if self.js_crawl:
            cmd.extend(["-jc"])
            cmd.extend(["-js-crawl"])
        cmd.extend(["-xhr"])
        cmd.extend(["-fx"])
        cmd.extend(["-aff"])
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            cmd.extend(["-H", f"Cookie: {cookie_str}"])
        return cmd

    def _parse_katana_output(self, output: str) -> List[KatanaEndpoint]:
        endpoints = []
        for line in output.strip().splitlines():
            data = json.loads(line)
            request = data.get("request", {})
            response = data.get("response", {})
            url = request.get("endpoint", "")
            query_params = self._extract_query_params(url)
            endpoint = KatanaEndpoint(
                url=url,
                method=request.get("method", "GET"),
                status_code=response.get("status_code"),
                content_type=response.get("headers", {}).get("Content-Type"),
                content_length=len(response.get("body", "")),
                source="katana",
                query_params=query_params,
            )
            endpoints.append(endpoint)
        return endpoints

    def _extract_query_params(self, url: str) -> Dict[str, Any]:
        if "?" not in url:
            return {}
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] if len(v) == 1 else v for k, v in params.items()}

    def _deduplicate_endpoints(self, endpoints: List[KatanaEndpoint]) -> List[KatanaEndpoint]:
        seen = set()
        unique = []
        for ep in endpoints:
            parsed_url = urlparse(ep.url)
            if self.filter_static:
                url_lower = ep.url.lower()
                if any(x in url_lower for x in _STATIC_PATHS):
                    continue
                path = parsed_url.path.lower()
                if any(path.endswith(f'.{ext}') for ext in _STATIC_EXTENSIONS):
                    continue
            url = ep.url.split("#")[0]
            url_without_query = url.split("?")[0]
            path = parsed_url.path
            if ep.query_params:
                if path not in self.all_discovered_params:
                    self.all_discovered_params[path] = set()
                self.all_discovered_params[path].update(ep.query_params.keys())
            if url_without_query not in seen:
                seen.add(url_without_query)
                unique.append(ep)
        return unique

    async def crawl(self) -> SimpleCrawlerReport:
        start_time = time.time()
        cmd = self._build_katana_command()
        print(f"Running: {' '.join(cmd)}")
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=self.timeout)
        output = stdout.decode("utf-8", errors="ignore")
        raw_endpoints = self._parse_katana_output(output)
        self.endpoints = self._deduplicate_endpoints(raw_endpoints)
        self.stats.total_requests = len(raw_endpoints)
        self.stats.successful_requests = sum(1 for e in self.endpoints if e.status_code and 200 <= e.status_code < 400)
        self.stats.failed_requests = sum(1 for e in self.endpoints if e.status_code and e.status_code >= 400)
        self.stats.unique_urls = len(self.endpoints)
        self.stats.unique_domains = 1
        self.stats.api_endpoints = sum(1 for e in self.endpoints if "api" in e.to_dict()["type"])
        self.stats.html_pages = sum(1 for e in self.endpoints if e.to_dict()["type"] == "page")
        self.stats.forms_discovered = len(self.forms)
        self.stats.interesting_endpoints = sum(1 for e in self.endpoints if e.to_dict()["interesting"])
        self.stats.javascript_files = sum(1 for e in self.endpoints if e.url.endswith(".js"))
        self.stats.end_time = datetime.utcnow().isoformat()
        self.stats.duration_seconds = time.time() - start_time
        return self._generate_report()

    def _generate_report(self) -> SimpleCrawlerReport:
        api_count = sum(1 for e in self.endpoints if e._classify_type() == "api")
        auth_count = sum(1 for e in self.endpoints if e._classify_type() == "auth")
        admin_count = sum(1 for e in self.endpoints if e._classify_type() == "admin")
        page_count = sum(1 for e in self.endpoints if e._classify_type() == "page")
        endpoints_simple = []
        for ep in self.endpoints:
            path = urlparse(ep.url).path
            endpoints_simple.append({
                "url": path,
                "full_url": ep.url,
                "method": ep.method,
                "type": ep._classify_type(),
                "interesting": ep._is_interesting(),
            })
        return SimpleCrawlerReport(
            target=self.base_url,
            timestamp=datetime.utcnow().isoformat(),
            summary={
                "total": len(self.endpoints),
                "api": api_count,
                "auth": auth_count,
                "admin": admin_count,
                "page": page_count,
            },
            endpoints=endpoints_simple,
            cookies=list(self.cookies.keys()) if self.cookies else [],
            discovered_params=self.get_discovered_params(),
        )

    def get_discovered_params(self) -> Dict[str, List[str]]:
        return {path: sorted(params) for path, params in self.all_discovered_params.items()}
