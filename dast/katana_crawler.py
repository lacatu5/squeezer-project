"""
Katana Crawler Wrapper for DAST.

Uses ProjectDiscovery's Katana tool for intelligent endpoint discovery.
Katana is a battle-tested web crawler used by most security professionals.

Features:
- Headless browser for SPA rendering (React, Vue, etc.)
- JavaScript parsing for hidden endpoints
- Cookie-based authentication
- JSON output for easy parsing
- Same-origin filtering

Installation:
    go install github.com/projectdiscovery/katana/cmd/katana@latest

Or download binaries from: https://github.com/projectdiscovery/katana/releases
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel

from dast.config import (
    AuthConfig,
    AuthType,
    EndpointsConfig,
    TargetConfig,
)

# Pydantic Field
from pydantic import Field as PDField


class SimpleCrawlerReport(BaseModel):
    """Simple crawler report with minimal, useful data.

    Can be converted directly to TargetConfig for vulnerability scanning.
    """

    target: str
    timestamp: str
    summary: Dict[str, int]
    endpoints: List[Dict[str, Any]] = PDField(default_factory=list)
    cookies: List[str] = PDField(default_factory=list)

    # Static file extensions to blacklist
    _STATIC_EXTENSIONS: Set[str] = {
        '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.mp4', '.mp3', '.wav', '.avi', '.mov', '.wmv', '.flv', '.mkv',
        '.webp', '.bmp', '.tiff', '.tif',
        '.map', '.txt', '.xml', 'robots.txt', 'favicon.ico', '.swf',
        '.webmanifest', '.json', '.yaml', '.yml',
    }

    # Static path patterns to blacklist
    _STATIC_PATH_PATTERNS: Set[str] = {
        '/assets/', '/static/', '/images/', '/img/', '/fonts/',
        '/media/', '/_next/static/', '/__webpack__/', '/public/',
        '/node_modules/', '/vendor/', '/.well-known/',
    }

    def _is_static_asset(self, url: str) -> bool:
        """Check if a URL points to a static asset."""
        url_lower = url.lower()

        # Check extension
        for ext in self._STATIC_EXTENSIONS:
            if url_lower.endswith(ext):
                return True

        # Check static path patterns
        for pattern in self._STATIC_PATH_PATTERNS:
            if pattern in url_lower:
                return True

        return False

    def _get_endpoint_priority(self, endpoint: Dict[str, Any]) -> int:
        """Calculate priority score for an endpoint (higher = scan first)."""
        score = 0
        url_lower = endpoint.get('url', '').lower()
        ep_type = endpoint.get('type', '')
        full_url = endpoint.get('full_url', url_lower)

        # API endpoints are highest priority
        if ep_type == 'api':
            score += 100

        # Auth endpoints
        if ep_type == 'auth' or any(x in url_lower for x in ['login', 'signin', 'auth', 'logout']):
            score += 80

        # Admin endpoints
        if ep_type == 'admin' or any(x in url_lower for x in ['admin', 'dashboard', 'panel']):
            score += 70

        # Endpoints with query parameters (injection points)
        if '?' in full_url:
            score += 50

        # Known interesting paths
        interesting_keywords = [
            'user', 'profile', 'search', 'filter', 'sort',
            'api', 'rest', 'graphql', 'query',
            'upload', 'download', 'export', 'import',
            'config', 'settings', 'account',
            'cart', 'checkout', 'order', 'payment',
            'product', 'item', 'list',
        ]
        for keyword in interesting_keywords:
            if keyword in url_lower:
                score += 30
                break  # Only count once

        return score

    def _sanitize_endpoint_key(self, path: str) -> str:
        """Convert a URL path to a valid endpoint key name."""
        import re

        # Remove leading/trailing slashes and special chars
        clean = path.strip('/').replace('-', '_').replace('.', '_')

        # Replace remaining slashes with underscores
        clean = clean.replace('/', '_')

        # Remove consecutive underscores
        clean = re.sub(r'_+', '_', clean)

        # Return "root" if empty
        return clean or "root"

    def _generate_endpoint_key(self, url: str, existing_keys: Dict[str, str]) -> str:
        """Generate a unique endpoint key from a URL."""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        path = parsed.path or '/'

        base_key = self._sanitize_endpoint_key(path)
        key = base_key
        counter = 1

        # Ensure uniqueness by appending counter if needed
        while key in existing_keys:
            key = f"{base_key}_{counter}"
            counter += 1

        return key

    def to_target_config(
        self,
        config_name: Optional[str] = None,
        prioritize: bool = True,
        exclude_static: bool = True,
    ) -> TargetConfig:
        """Convert crawler report to TargetConfig for vulnerability scanning.

        Args:
            config_name: Optional name for the target (defaults to "crawled_target")
            prioritize: Sort endpoints by priority (high-value targets first)
            exclude_static: Filter out static assets (.css, .png, etc.)

        Returns:
            TargetConfig ready for vulnerability scanning
        """
        from urllib.parse import urlparse

        # Parse base URL from report
        parsed_base = urlparse(self.target)
        target_name = config_name or f"crawled_{parsed_base.netloc.replace('.', '_')}"

        # Filter and process endpoints
        filtered_endpoints: List[Dict[str, Any]] = []

        for ep in self.endpoints:
            url = ep.get('full_url', ep.get('url', ''))

            # Skip static assets if enabled
            if exclude_static and self._is_static_asset(url):
                continue

            filtered_endpoints.append(ep)

        # Sort by priority if requested
        if prioritize:
            filtered_endpoints.sort(key=self._get_endpoint_priority, reverse=True)

        # Build custom endpoints dict
        custom_endpoints: Dict[str, str] = {}
        for ep in filtered_endpoints:
            url = ep.get('full_url', ep.get('url', ''))
            key = self._generate_endpoint_key(url, custom_endpoints)
            custom_endpoints[key] = url

        # Build authentication config from cookies
        auth_config = AuthConfig()
        if self.cookies:
            # Convert cookie list to auth headers
            cookie_str = '; '.join([f"{c}=value" for c in self.cookies])
            auth_config = AuthConfig(
                type=AuthType.NONE,  # Cookies are just headers, not a specific auth type
                headers={"Cookie": cookie_str},
            )

        # Create TargetConfig
        return TargetConfig(
            name=target_name,
            base_url=self.target,
            authentication=auth_config,
            endpoints=EndpointsConfig(
                base="",
                custom=custom_endpoints,
            ),
        )

    def save_yaml(self, path: str) -> None:
        """Save report to YAML file."""
        import yaml

        data = {
            "target": self.target,
            "timestamp": self.timestamp,
            "summary": self.summary,
            "endpoints": self.endpoints,
        }
        if self.cookies:
            data["cookies"] = self.cookies

        Path(path).write_text(yaml.dump(data, sort_keys=False, default_flow_style=False))

    def model_dump(self) -> Dict[str, Any]:
        """Return dict representation."""
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "summary": self.summary,
            "endpoints": self.endpoints,
            "cookies": self.cookies,
        }


@dataclass
class KatanaEndpoint:
    """An endpoint discovered by Katana."""

    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    content_length: int = 0
    source: str = "unknown"  # katana source field
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
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
        }

    def _classify_type(self) -> str:
        """Classify endpoint type."""
        url_lower = self.url.lower()

        if any(p in url_lower for p in ["/api/", "/rest/", "/graphql"]):
            return "api"
        if url_lower.endswith((".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".ttf")):
            return "static"
        if any(p in url_lower for p in ["login", "signin", "auth", "logout"]):
            return "auth"
        if any(p in url_lower for p in ["admin", "dashboard", "panel"]):
            return "admin"
        return "page"

    def _is_interesting(self) -> bool:
        """Check if endpoint is interesting for security testing."""
        url_lower = self.url.lower()
        interesting = [
            "admin", "dashboard", "config", "settings", "upload", "download",
            "export", "import", "backup", "debug", "test", "api", "auth",
            "login", "logout", "reset", "forgot", "user", "profile", "cart",
            "checkout", "payment", "order", "basket", "admin", "manage"
        ]
        return any(pattern in url_lower for pattern in interesting)


@dataclass
class KatanaStatistics:
    """Statistics from Katana crawl."""

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    unique_urls: int = 0  # Match CrawlerStatistics naming
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
        """Convert to dictionary."""
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


class KatanaCrawler:
    """
    Katana-based crawler for DAST.

    Uses Katana (ProjectDiscovery) for intelligent endpoint discovery.
    """

    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        js_crawl: bool = False,
        headless: bool = False,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        katana_path: str = "katana",
        timeout: int = 300,
        filter_static: bool = True,
        interesting_only: bool = False,
    ):
        """Initialize the Katana crawler.

        Args:
            base_url: The base URL to crawl
            max_depth: Maximum crawl depth (default: 3)
            js_crawl: Enable JavaScript crawling (default: False, requires Chrome)
            headless: Use headless browser (default: False, requires Chrome)
            cookies: Dictionary of cookies for authentication
            headers: Custom headers to send
            katana_path: Path to Katana binary (default: "katana")
            timeout: Maximum time for crawl in seconds (default: 300)
            filter_static: Filter out static files (.js, .css, images, etc.) (default: True)
            interesting_only: Only keep interesting endpoints (api, auth, admin, etc.) (default: False)
        """
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.js_crawl = js_crawl
        self.headless = headless
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.katana_path = katana_path
        self.timeout = timeout
        self.filter_static = filter_static
        self.interesting_only = interesting_only

        # State
        self.endpoints: List[KatanaEndpoint] = []
        self.forms: List[Dict[str, Any]] = []
        self.stats = KatanaStatistics()
        self.discovered_cookies: Dict[str, str] = {}

    def _build_katana_command(
        self,
        output_file: Optional[str] = None,
    ) -> List[str]:
        """Build the Katana command."""
        cmd = [
            self.katana_path,
            "-u", self.base_url,
            "-d", str(self.max_depth),
            "-jsonl",
            "-silent",
            # "-or",  # Removed - we do our own same-origin filtering
        ]

        if self.js_crawl:
            cmd.extend(["-jc"])  # JavaScript crawling
            cmd.extend(["-js-crawl"])  # Crawl JS files

        if self.headless:
            cmd.extend(["-headless"])  # Internal headless mode

        # Add cookies as headers (Katana uses -H for cookies, not -c)
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            cmd.extend(["-H", f"Cookie: {cookie_str}"])

        # Add custom headers if provided
        if self.headers:
            for key, value in self.headers.items():
                cmd.extend(["-H", f"{key}: {value}"])

        # Add output file if specified
        if output_file:
            cmd.extend(["-o", output_file])

        return cmd

    def _parse_katana_output(self, output: str) -> List[KatanaEndpoint]:
        """Parse JSON output from Katana."""
        endpoints = []

        for line in output.strip().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)

                # Handle Katana's JSONL format
                # {"timestamp":"...", "request":{"method":"GET","endpoint":"..."}, "response":{...}}
                if "request" in data:
                    request = data.get("request", {})
                    response = data.get("response", {})

                    endpoint = KatanaEndpoint(
                        url=request.get("endpoint", ""),
                        method=request.get("method", "GET"),
                        status_code=response.get("status_code"),
                        content_type=response.get("headers", {}).get("Content-Type"),
                        content_length=len(response.get("body", "")),
                        source="katana",
                    )
                else:
                    # Fallback for other formats
                    endpoint = KatanaEndpoint(
                        url=data.get("url", data.get("endpoint", "")),
                        method=data.get("method", "GET"),
                        status_code=data.get("status_code"),
                        content_type=data.get("content_type"),
                        content_length=data.get("content_length", 0),
                        source=data.get("source", "unknown"),
                    )
                endpoints.append(endpoint)
            except json.JSONDecodeError:
                # Handle non-JSON lines (shouldn't happen with -jsonl flag)
                continue

        return endpoints

    def _deduplicate_endpoints(self, endpoints: List[KatanaEndpoint]) -> List[KatanaEndpoint]:
        """Deduplicate endpoints by URL and filter to same-origin only."""
        seen = set()
        unique = []

        # Static file extensions to filter out
        static_extensions = {
            '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.wav', '.avi',
            '.mov', '.wmv', '.flv', '.mkv', '.webp', '.bmp', '.tiff', '.tif',
            '.map', '.txt', '.xml', 'robots.txt', 'favicon.ico', '.swf'
        }

        for ep in endpoints:
            # Filter for same-origin only
            parsed_url = urlparse(ep.url)
            if parsed_url.netloc != self.base_domain:
                continue

            # Filter out static files
            if self.filter_static:
                url_lower = ep.url.lower()
                if any(url_lower.endswith(ext) for ext in static_extensions):
                    continue
                # Also filter common static paths
                if any(x in url_lower for x in ['/assets/', '/static/', '/images/', '/fonts/', '/media/', '/_next/static/', '/__webpack__/']):
                    continue

            # Interesting only filter
            if self.interesting_only:
                ep_type = ep._classify_type()
                if ep_type not in ('api', 'auth', 'admin') and not ep._is_interesting():
                    continue

            # Normalize URL (remove fragments, sort query params)
            url = ep.url.split("#")[0]
            # Remove query string for deduplication
            url_without_query = url.split("?")[0]

            if url_without_query not in seen:
                seen.add(url_without_query)
                unique.append(ep)
        return unique

    async def _verify_endpoints(self, endpoints: List[KatanaEndpoint]) -> List[KatanaEndpoint]:
        """Verify endpoints by making HTTP requests."""
        verified = []

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            for endpoint in endpoints[:100]:  # Limit to first 100 for speed
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
                    # Keep endpoint even if verification failed
                    verified.append(endpoint)

        # Add remaining endpoints without verification
        verified.extend(endpoints[100:])
        return verified

    def _extract_forms_from_html(self, html: str, url: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML using regex."""
        forms = []

        # Simple regex-based form extraction
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\'].*?>'
        for match in re.finditer(form_pattern, html, re.IGNORECASE):
            action = match.group(1)
            method = match.group(2).upper() or "GET"

            if not action.startswith("http"):
                from urllib.parse import urljoin
                action = urljoin(url, action)

            forms.append({
                "action": action,
                "method": method,
                "fields": [],  # Would need more complex parsing
            })

        return forms

    async def crawl(self, verify: bool = False) -> SimpleCrawlerReport:
        """
        Run the Katana crawler.

        Args:
            verify: Whether to verify endpoints with HTTP requests

        Returns:
            SimpleCrawlerReport with discovered data
        """
        import time

        start_time = time.time()

        try:
            # Build and run Katana command
            cmd = self._build_katana_command()

            print(f"Running: {' '.join(cmd)}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Run with timeout
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

            # Parse output
            raw_endpoints = self._parse_katana_output(output)
            self.endpoints = self._deduplicate_endpoints(raw_endpoints)

            # Optionally verify endpoints
            if verify:
                self.endpoints = await self._verify_endpoints(self.endpoints)

            # Update statistics
            self.stats.total_requests = len(raw_endpoints)
            self.stats.successful_requests = sum(1 for e in self.endpoints if e.status_code and 200 <= e.status_code < 400)
            self.stats.failed_requests = sum(1 for e in self.endpoints if e.status_code and e.status_code >= 400)
            self.stats.unique_urls = len(self.endpoints)
            self.stats.unique_domains = 1  # Current target domain
            self.stats.api_endpoints = sum(1 for e in self.endpoints if "api" in e.to_dict()["type"])
            self.stats.html_pages = sum(1 for e in self.endpoints if e.to_dict()["type"] == "page")
            self.stats.forms_discovered = len(self.forms)
            self.stats.interesting_endpoints = sum(1 for e in self.endpoints if e.to_dict()["interesting"])
            self.stats.javascript_files = sum(1 for e in self.endpoints if e.url.endswith(".js"))

            # Build report
            self.stats.end_time = datetime.utcnow().isoformat()
            self.stats.duration_seconds = time.time() - start_time

            return self._generate_report()

        except FileNotFoundError:
            raise RuntimeError(
                "Katana binary not found. Install with:\n"
                "  go install github.com/projectdiscovery/katana/cmd/katana@latest\n"
                "Or download from: https://github.com/projectdiscovery/katana/releases"
            )

    def _generate_report(self) -> "SimpleCrawlerReport":
        """Generate a simple crawler report from collected data."""
        # Count by type
        api_count = sum(1 for e in self.endpoints if e._classify_type() == "api")
        auth_count = sum(1 for e in self.endpoints if e._classify_type() == "auth")
        admin_count = sum(1 for e in self.endpoints if e._classify_type() == "admin")
        page_count = sum(1 for e in self.endpoints if e._classify_type() == "page")

        # Build simple endpoints list
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
        )


async def crawl_with_katana(
    url: str,
    max_depth: int = 3,
    js_crawl: bool = False,
    headless: bool = False,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    verify: bool = False,
    output_file: Optional[str] = None,
    filter_static: bool = True,
    interesting_only: bool = False,
) -> SimpleCrawlerReport:
    """
    Convenience function to run the Katana crawler.

    Args:
        url: The base URL to crawl
        max_depth: Maximum crawl depth
        js_crawl: Enable JavaScript crawling
        headless: Use headless browser
        cookies: Cookies for authentication
        headers: Custom headers
        verify: Verify endpoints with HTTP requests
        output_file: Optional file to save the report
        filter_static: Filter out static files
        interesting_only: Only keep interesting endpoints

    Returns:
        SimpleCrawlerReport with discovered data
    """
    crawler = KatanaCrawler(
        base_url=url,
        max_depth=max_depth,
        js_crawl=js_crawl,
        headless=headless,
        cookies=cookies,
        headers=headers,
        filter_static=filter_static,
        interesting_only=interesting_only,
    )

    report = await crawler.crawl(verify=verify)

    if output_file:
        report.save_yaml(output_file)

    return report


def parse_cookies_string(cookies_str: str) -> Dict[str, str]:
    """Parse cookies from string format.

    Supports:
    - "key1=value1; key2=value2"
    - "key1=value1"
    - JSON string: '{"key1": "value1"}'
    """
    cookies_str = cookies_str.strip()

    # Try JSON first
    if cookies_str.startswith("{"):
        try:
            return json.loads(cookies_str)
        except json.JSONDecodeError:
            pass

    # Parse "key=value; key2=value2" format
    cookies = {}
    for part in cookies_str.split(";"):
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            cookies[key.strip()] = value.strip()

    return cookies


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        url = sys.argv[1]
        cookies = {}
        if len(sys.argv) > 2:
            cookies = parse_cookies_string(sys.argv[2])

        report = asyncio.run(crawl_with_katana(
            url=url,
            cookies=cookies,
            max_depth=3,
        ))

        print(f"\nCrawled {url}")
        print(f"Discovered {len(report.endpoints)} endpoints")
        print(f"API endpoints: {report.statistics.get('api_endpoints', 0)}")
        print(f"Interesting endpoints: {report.statistics.get('interesting_endpoints', 0)}")
    else:
        print("Usage: python -m dast.katana_crawler <url> [cookies]")
        print("Example: python -m dast.katana_crawler http://localhost:3000 'session=abc123'")
