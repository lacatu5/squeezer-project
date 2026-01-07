import asyncio
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse, parse_qs


import time

from dast.crawler.models import KatanaEndpoint, KatanaStatistics
from dast.crawler.report import SimpleCrawlerReport


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

    def _build_katana_command(
        self,
        output_file: Optional[str] = None,
    ) -> List[str]:
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

    def _extract_query_params(self, url: str) -> Dict[str, str]:
        if "?" not in url:
            return {}
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] if len(v) == 1 else v for k, v in params.items()}

    def _deduplicate_endpoints(self, endpoints: List[KatanaEndpoint]) -> List[KatanaEndpoint]:
        seen = set()
        unique = []

        static_paths = ['/assets/', '/static/', '/images/', '/fonts/', '/media/', '/_next/static/', '/__webpack__/']
        static_extensions = {
            'js', 'css', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'woff', 'woff2', 'ttf', 'eot',
            'mp4', 'mp3', 'wav', 'avi', 'mov', 'wmv', 'flv', 'mkv', 'webp', 'bmp', 'tiff', 'tif',
            'map', 'txt', 'xml', 'swf', 'webm', 'otf'
        }

        for ep in endpoints:
            parsed_url = urlparse(ep.url)

            if self.filter_static:
                url_lower = ep.url.lower()
                if any(x in url_lower for x in static_paths):
                    continue
                path = parsed_url.path.lower()
                if any(path.endswith(f'.{ext}') for ext in static_extensions):
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

        stdout, _ = await asyncio.wait_for(
            process.communicate(),
            timeout=self.timeout,
        )

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