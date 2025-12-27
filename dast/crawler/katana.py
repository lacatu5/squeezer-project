import asyncio
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs

import httpx
from selectolax.parser import HTMLParser

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
        self.base_domain = urlparse(base_url).netloc
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
        self.discovered_cookies: Dict[str, str] = {}
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

        if self.headers:
            for key, value in self.headers.items():
                cmd.extend(["-H", f"{key}: {value}"])

        if output_file:
            cmd.extend(["-o", output_file])

        return cmd

    def _parse_katana_output(self, output: str) -> List[KatanaEndpoint]:
        endpoints = []

        for line in output.strip().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)

                if "request" in data:
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
                else:
                    url = data.get("url", data.get("endpoint", ""))
                    query_params = self._extract_query_params(url)

                    endpoint = KatanaEndpoint(
                        url=url,
                        method=data.get("method", "GET"),
                        status_code=data.get("status_code"),
                        content_type=data.get("content_type"),
                        content_length=data.get("content_length", 0),
                        source=data.get("source", "unknown"),
                        query_params=query_params,
                    )
                endpoints.append(endpoint)
            except json.JSONDecodeError:
                continue

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
            if parsed_url.netloc != self.base_domain:
                continue

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

    async def _verify_endpoints(self, endpoints: List[KatanaEndpoint]) -> List[KatanaEndpoint]:
        verified = []

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            for endpoint in endpoints[:100]:
                try:
                    response = await client.get(
                        endpoint.url,
                        headers=self.headers,
                        cookies=self.cookies,
                    )
                    endpoint.status_code = response.status_code
                    endpoint.content_type = response.headers.get("content-type")
                    endpoint.content_length = len(response.content)
                    verified.append(endpoint)
                except Exception:
                    verified.append(endpoint)

        verified.extend(endpoints[100:])
        return verified

    def _extract_forms_from_html(self, html: str, url: str) -> List[Dict[str, Any]]:
        forms = []

        tree = HTMLParser(html)

        for form_node in tree.css("form"):
            action = form_node.attrs.get("action", "")
            method = (form_node.attrs.get("method", "GET") or "GET").upper()

            if not action.startswith("http"):
                action = urljoin(url, action)

            fields = []

            for input_node in form_node.css("input"):
                field = {
                    "name": input_node.attrs.get("name", ""),
                    "type": input_node.attrs.get("type", "text"),
                    "value": input_node.attrs.get("value", ""),
                }
                if field["name"]:
                    fields.append(field)

            for textarea in form_node.css("textarea"):
                field = {
                    "name": textarea.attrs.get("name", ""),
                    "type": "textarea",
                    "value": textarea.text().strip() or textarea.attrs.get("value", ""),
                }
                if field["name"]:
                    fields.append(field)

            for select in form_node.css("select"):
                options = [
                    opt.attrs.get("value", opt.text().strip())
                    for opt in select.css("option")
                    if opt.attrs.get("value") or opt.text().strip()
                ]
                field = {
                    "name": select.attrs.get("name", ""),
                    "type": "select",
                    "value": select.attrs.get("value", options[0] if options else ""),
                    "options": options,
                }
                if field["name"]:
                    fields.append(field)

            for btn in form_node.css("button"):
                field = {
                    "name": btn.attrs.get("name", ""),
                    "type": btn.attrs.get("type", "submit"),
                    "value": btn.attrs.get("value", btn.text().strip()),
                }
                if field["name"]:
                    fields.append(field)

            forms.append({
                "action": action,
                "method": method,
                "fields": fields,
                "field_count": len(fields),
            })

        return forms

    async def crawl(self, verify: bool = False) -> SimpleCrawlerReport:
        import time

        start_time = time.time()

        try:
            cmd = self._build_katana_command()

            print(f"Running: {' '.join(cmd)}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout,
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise TimeoutError(f"Katana crawl timed out after {self.timeout} seconds")

            output = stdout.decode("utf-8", errors="ignore")
            errors = stderr.decode("utf-8", errors="ignore")

            if process.returncode != 0 and not output:
                raise RuntimeError(f"Katana failed: {errors}")

            raw_endpoints = self._parse_katana_output(output)
            self.endpoints = self._deduplicate_endpoints(raw_endpoints)

            if verify:
                self.endpoints = await self._verify_endpoints(self.endpoints)

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

        except FileNotFoundError:
            raise RuntimeError(
                "Katana binary not found. Install with:\n"
                "  go install github.com/projectdiscovery/katana/cmd/katana@latest\n"
                "Or download from: https://github.com/projectdiscovery/katana/releases"
            )

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


async def crawl_with_katana(
    url: str,
    max_depth: int = 3,
    js_crawl: bool = True,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    verify: bool = False,
    output_file: Optional[str] = None,
    filter_static: bool = True,
) -> SimpleCrawlerReport:
    crawler = KatanaCrawler(
        base_url=url,
        max_depth=max_depth,
        js_crawl=js_crawl,
        cookies=cookies,
        headers=headers,
        filter_static=filter_static,
    )

    report = await crawler.crawl(verify=verify)

    if output_file:
        report.save_yaml(output_file)

    return report
