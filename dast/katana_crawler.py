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
import os
import re
import subprocess
import tempfile
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
    CrawlerReport,
    EndpointsConfig,
    TargetConfig,
)


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
    unique_endpoints: int = 0
    api_endpoints: int = 0
    auth_endpoints: int = 0
    interesting_endpoints: int = 0
    forms_found: int = 0
    javascript_files: int = 0
    start_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    end_time: Optional[str] = None
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_requests": self.total_requests,
            "unique_endpoints": self.unique_endpoints,
            "api_endpoints": self.api_endpoints,
            "auth_endpoints": self.auth_endpoints,
            "interesting_endpoints": self.interesting_endpoints,
            "forms_found": self.forms_found,
            "javascript_files": self.javascript_files,
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
        js_crawl: bool = True,
        headless: bool = True,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        katana_path: str = "katana",
        timeout: int = 300,
    ):
        """Initialize the Katana crawler.

        Args:
            base_url: The base URL to crawl
            max_depth: Maximum crawl depth (default: 3)
            js_crawl: Enable JavaScript crawling (default: True)
            headless: Use headless browser (default: True)
            cookies: Dictionary of cookies for authentication
            headers: Custom headers to send
            katana_path: Path to Katana binary (default: "katana")
            timeout: Maximum time for crawl in seconds (default: 300)
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
            "-json",
            "-silent",
            "-or",  # Only same-origin URLs
        ]

        if self.js_crawl:
            cmd.extend(["-jc"])  # JavaScript crawling
            cmd.extend(["-js-crawl"])  # Crawl JS files

        if self.headless:
            cmd.extend(["-headless"])  # Internal headless mode

        # Add cookies if provided
        if self.cookies:
            cookie_file = self._create_cookie_file()
            cmd.extend(["-c", cookie_file])

        # Add custom headers if provided
        if self.headers:
            header_file = self._create_header_file()
            cmd.extend(["-hdr", header_file])

        # Add output file if specified
        if output_file:
            cmd.extend(["-o", output_file])

        return cmd

    def _create_cookie_file(self) -> str:
        """Create a temporary cookie file for Katana."""
        # Format: domain\tkey\tvalue (Katana expects a specific format)
        # Or use JSON format for newer Katana versions
        cookies_list = []
        for name, value in self.cookies.items():
            cookies_list.append({
                "domain": self.base_domain,
                "name": name,
                "value": value,
            })

        cookie_file = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
        )
        json.dump(cookies_list, cookie_file)
        cookie_file.close()
        return cookie_file.name

    def _create_header_file(self) -> str:
        """Create a temporary header file for Katana."""
        header_file = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            delete=False,
        )
        for key, value in self.headers.items():
            header_file.write(f"{key}: {value}\n")
        header_file.close()
        return header_file.name

    def _parse_katana_output(self, output: str) -> List[KatanaEndpoint]:
        """Parse JSON output from Katana."""
        endpoints = []

        for line in output.strip().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
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
                # Handle non-JSON lines (shouldn't happen with -json flag)
                continue

        return endpoints

    def _deduplicate_endpoints(self, endpoints: List[KatanaEndpoint]) -> List[KatanaEndpoint]:
        """Deduplicate endpoints by URL."""
        seen = set()
        unique = []
        for ep in endpoints:
            # Normalize URL (remove fragments, sort query params)
            url = ep.url.split("#")[0]
            if url not in seen:
                seen.add(url)
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

    async def crawl(self, verify: bool = False) -> CrawlerReport:
        """
        Run the Katana crawler.

        Args:
            verify: Whether to verify endpoints with HTTP requests

        Returns:
            CrawlerReport with all discovered data
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
            self.stats.unique_endpoints = len(self.endpoints)
            self.stats.api_endpoints = sum(1 for e in self.endpoints if "api" in e.to_dict()["type"])
            self.stats.auth_endpoints = sum(1 for e in self.endpoints if "auth" in e.to_dict()["type"])
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

    def _generate_report(self) -> CrawlerReport:
        """Generate a crawler report from collected data."""
        # Convert endpoints to dict format
        endpoints_list = [ep.to_dict() for ep in self.endpoints]

        # Build target config
        custom_endpoints = {}
        for endpoint in self.endpoints:
            path = urlparse(endpoint.url).path
            key = path.strip("/").replace("/", "_").replace("-", "_") or "root"
            original_key = key
            counter = 1
            while key in custom_endpoints:
                key = f"{original_key}_{counter}"
                counter += 1
            custom_endpoints[key] = endpoint.url

        # Build auth config
        auth_config = AuthConfig(
            type=AuthType.NONE,
            headers=self.headers.copy(),
        )

        if self.cookies:
            auth_config.type = AuthType.FORM
            # Format cookies as header
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            auth_config.headers["Cookie"] = cookie_str

        target_config = TargetConfig(
            name=f"katana_crawled_{self.base_domain}",
            base_url=self.base_url,
            authentication=auth_config,
            endpoints=EndpointsConfig(base="", custom=custom_endpoints),
        )

        # Build auth data dict
        auth_data = {
            "type": "cookie" if self.cookies else "none",
            "cookies": self.cookies.copy(),
        }

        return CrawlerReport(
            target=self.base_url,
            base_url=self.base_url,
            timestamp=datetime.utcnow().isoformat(),
            target_config=target_config,
            endpoints=endpoints_list,
            forms=self.forms,
            statistics=self.stats.to_dict(),
            auth_data=auth_data,
            storage_data={},
            discovered_cookies=self.cookies.copy(),
        )


async def crawl_with_katana(
    url: str,
    max_depth: int = 3,
    js_crawl: bool = True,
    headless: bool = True,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    verify: bool = False,
    output_file: Optional[str] = None,
) -> CrawlerReport:
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

    Returns:
        CrawlerReport with discovered data
    """
    crawler = KatanaCrawler(
        base_url=url,
        max_depth=max_depth,
        js_crawl=js_crawl,
        headless=headless,
        cookies=cookies,
        headers=headers,
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


def extract_cookies_from_browser(target_domain: str) -> Dict[str, str]:
    """
    Extract cookies for a domain from the browser.

    This is a placeholder - actual implementation would read browser
    cookie databases from Chrome/Firefox/Safari.

    For now, users should manually copy cookies from DevTools.
    """
    # TODO: Implement actual browser cookie extraction
    # Chrome: ~/Library/Application Support/Google/Chrome/Default/Cookies
    # Firefox: ~/Library/Application Support/Firefox/Profiles/*.cookies.sqlite
    # Safari: ~/Library/Cookies/Cookies.binarycookies
    return {}


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
