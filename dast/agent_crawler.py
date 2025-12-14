"""
Intelligent Agent Crawler for DAST.

Uses AI-powered decision making to intelligently discover endpoints,
analyze application behavior, and extract security-relevant data.
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse, urljoin, urlunparse

from playwright.async_api import Page, Request, Response
from pydantic import BaseModel

from dast.config import (
    AuthConfig,
    AuthType,
    CrawlerReport,
    EndpointsConfig,
    TargetConfig,
)


class DiscoveryMethod(str, Enum):
    """How an endpoint was discovered."""

    LINK = "link"
    FORM = "form"
    API = "api"
    JAVASCRIPT = "javascript"
    REDIRECT = "redirect"
    HEADERS = "headers"
    AI_SUGGESTED = "ai_suggested"
    FUZZING = "fuzzing"
    AUTH_FLOW = "auth_flow"


class EndpointType(str, Enum):
    """Type of endpoint discovered."""

    PAGE = "page"
    API = "api"
    STATIC = "static"
    AUTH = "auth"
    ADMIN = "admin"
    UPLOAD = "upload"
    DOWNLOAD = "download"
    WEBSOCKET = "websocket"
    UNKNOWN = "unknown"


@dataclass
class DiscoveredEndpoint:
    """A discovered endpoint with metadata."""

    url: str
    method: str
    endpoint_type: EndpointType
    discovery_method: DiscoveryMethod
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    response_time: float = 0.0
    params: Dict[str, List[str]] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    form_fields: List[Dict[str, Any]] = field(default_factory=list)
    auth_required: bool = False
    interesting: bool = False
    vulnerability_hints: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "url": self.url,
            "method": self.method,
            "type": self.endpoint_type.value,
            "discovery_method": self.discovery_method.value,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "response_time": self.response_time,
            "params": self.params,
            "headers": self.headers,
            "form_fields": self.form_fields,
            "auth_required": self.auth_required,
            "interesting": self.interesting,
            "vulnerability_hints": self.vulnerability_hints,
            "timestamp": self.timestamp,
        }


@dataclass
class AuthFlowData:
    """Data extracted from authentication flow."""

    login_url: str
    logout_url: Optional[str] = None
    session_token_name: Optional[str] = None
    session_token_value: Optional[str] = None
    jwt_token: Optional[str] = None
    auth_type: Optional[str] = None  # jwt, session, basic, oauth, etc
    csrf_token: Optional[str] = None
    csrf_param_name: Optional[str] = None
    additional_headers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "login_url": self.login_url,
            "logout_url": self.logout_url,
            "session_token_name": self.session_token_name,
            "session_token_value": self.session_token_value,
            "jwt_token": self.jwt_token,
            "auth_type": self.auth_type,
            "csrf_token": self.csrf_token,
            "csrf_param_name": self.csrf_param_name,
            "additional_headers": self.additional_headers,
        }


@dataclass
class CrawlerStatistics:
    """Statistics collected during crawling."""

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    unique_endpoints: int = 0
    forms_discovered: int = 0
    api_endpoints: int = 0
    javascript_files: int = 0
    js_endpoints_extracted: int = 0
    auth_endpoints: int = 0
    interesting_endpoints: int = 0
    start_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    end_time: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "unique_endpoints": self.unique_endpoints,
            "forms_discovered": self.forms_discovered,
            "api_endpoints": self.api_endpoints,
            "javascript_files": self.javascript_files,
            "js_endpoints_extracted": self.js_endpoints_extracted,
            "auth_endpoints": self.auth_endpoints,
            "interesting_endpoints": self.interesting_endpoints,
            "start_time": self.start_time,
            "end_time": self.end_time,
        }


class AgentCrawler:
    """
    Intelligent agent crawler for DAST.

    Features:
    - AI-powered decision making for exploration
    - Form detection and field analysis
    - API endpoint discovery from JavaScript
    - Authentication flow tracking
    - Header and cookie analysis
    - Intelligent prioritization of interesting endpoints
    """

    # Patterns for discovering API endpoints
    API_PATTERNS = [
        r"/api/v?\d*/?[a-z_]+",
        r"/rest/[a-z_]+",
        r"/graphql",
        r"/ws/[a-z_]+",
        r"/webhook",
    ]

    # Patterns for discovering interesting endpoints
    INTERESTING_PATTERNS = [
        r"admin",
        r"dashboard",
        r"config",
        r"settings",
        r"upload",
        r"download",
        r"export",
        r"import",
        r"backup",
        r"debug",
        r"test",
        r"dev",
        r"api",
        r"auth",
        r"login",
        r"logout",
        r"reset",
        r"forgot",
    ]

    # Patterns for discovering potential vulnerabilities
    VULN_HINT_PATTERNS = {
        "sql_injection": [r"error.*sql", r"mysql", r"postgresql", r"ORA-", r"sqlite"],
        "xss": [r"reflect", r"<script>", r"javascript:"],
        "ssrf": [r"url=", r"fetch=", r"endpoint="],
        "path_traversal": [r"\.\./", r"\.\.\\"],
        "info_disclosure": [r"stack trace", r"debug", r"exception", r"error at"],
        "id_or": [r"user/\d+", r"product/\d+", r"account/\d+"],
    }

    def __init__(
        self,
        base_url: str,
        max_pages: int = 500,
        max_depth: int = 5,
        headless: bool = True,
        follow_redirects: bool = True,
        extract_javascript: bool = True,
        discover_apis: bool = True,
        analyze_forms: bool = True,
    ):
        """Initialize the agent crawler.

        Args:
            base_url: The base URL to crawl
            max_pages: Maximum number of pages to visit
            max_depth: Maximum depth to crawl
            headless: Run browser in headless mode
            follow_redirects: Follow HTTP redirects
            extract_javascript: Extract endpoints from JavaScript files
            discover_apis: Discover API endpoints
            analyze_forms: Analyze forms for input fields
        """
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.headless = headless
        self.follow_redirects = follow_redirects
        self.extract_javascript = extract_javascript
        self.discover_apis = discover_apis
        self.analyze_forms = analyze_forms

        # State
        self.discovered_endpoints: Dict[str, DiscoveredEndpoint] = {}
        self.visited_urls: Set[str] = set()
        self.url_queue: List[Tuple[str, int]] = []  # (url, depth)
        self.forms_found: List[Dict[str, Any]] = []
        self.api_endpoints: Set[str] = set()
        self.js_files: Set[str] = set()
        self.auth_flows: List[AuthFlowData] = []
        self.cookies: Dict[str, str] = {}
        self.storage: Dict[str, Any] = {}

        # Statistics
        self.stats = CrawlerStatistics()

        # Browser
        self._playwright = None
        self._browser = None
        self._page = None
        self._context = None

    async def _init_browser(self) -> None:
        """Initialize Playwright browser."""
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=self.headless)
        self._context = await self._browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (compatible; DAST-Agent-Crawler/1.0)",
        )
        self._page = await self._context.new_page()

        # Set up request/response handlers
        self._page.on("request", self._on_request)
        self._page.on("response", self._on_response)

    async def _close_browser(self) -> None:
        """Close Playwright browser."""
        if self._page:
            await self._page.close()
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()

    def _on_request(self, request: Request) -> None:
        """Handle outgoing requests."""
        url = request.url
        method = request.method
        headers = request.headers

        # Track API endpoints
        if self.discover_apis:
            for pattern in self.API_PATTERNS:
                if re.search(pattern, url, re.IGNORECASE):
                    self.api_endpoints.add(url)
                    break

        # Track JavaScript files
        if url.endswith(".js"):
            self.js_files.add(url)

    async def _on_response(self, response: Response) -> None:
        """Handle incoming responses."""
        self.stats.total_requests += 1

        url = response.url
        status = response.status
        headers = response.headers

        if status >= 200 and status < 400:
            self.stats.successful_requests += 1
        else:
            self.stats.failed_requests += 1

        # Check for interesting headers
        server = headers.get("server", "").lower()
        x_powered_by = headers.get("x-powered-by", "").lower()

        # Discover endpoint
        parsed = urlparse(url)
        if parsed.netloc == self.base_domain:
            endpoint_type = self._classify_endpoint(url, headers)
            discovery_method = DiscoveryMethod.LINK
            interesting = self._is_interesting(url)

            # Check vulnerability hints - only for non-redirects
            hints = []
            if status < 300:  # Only check body for non-redirects
                try:
                    body = await response.text()
                    hints = self._check_vulnerability_hints_text(body)
                except Exception:
                    pass  # Some responses don't have bodies

            endpoint = DiscoveredEndpoint(
                url=url,
                method="GET",  # Default, can be updated
                endpoint_type=endpoint_type,
                discovery_method=discovery_method,
                status_code=status,
                content_type=headers.get("content-type"),
                interesting=interesting,
                vulnerability_hints=hints,
            )

            key = self._make_endpoint_key(url, "GET")
            if key not in self.discovered_endpoints:
                self.discovered_endpoints[key] = endpoint
                self.stats.unique_endpoints += 1

        # Extract and analyze JavaScript (skip redirects)
        if self.extract_javascript and url.endswith(".js") and status < 300:
            await self._analyze_javascript(response)

    def _classify_endpoint(self, url: str, headers: Dict[str, str]) -> EndpointType:
        """Classify the type of endpoint."""
        url_lower = url.lower()

        if any(pattern in url_lower for pattern in ["login", "signin", "auth", "oauth"]):
            return EndpointType.AUTH
        if any(pattern in url_lower for pattern in ["admin", "dashboard", "panel"]):
            return EndpointType.ADMIN
        if any(pattern in url_lower for pattern in ["upload", "attach"]):
            return EndpointType.UPLOAD
        if any(pattern in url_lower for pattern in ["download", "export", "file"]):
            return EndpointType.DOWNLOAD
        if any(
            re.search(pattern, url_lower, re.IGNORECASE)
            for pattern in self.API_PATTERNS
        ):
            return EndpointType.API
        if url.endswith((".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico")):
            return EndpointType.STATIC

        # Check by content type
        content_type = headers.get("content-type", "").lower()
        if "application/json" in content_type or "application/api" in content_type:
            return EndpointType.API

        return EndpointType.PAGE

    def _is_interesting(self, url: str) -> bool:
        """Check if an endpoint might be interesting for security testing."""
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in self.INTERESTING_PATTERNS)

    def _check_vulnerability_hints_text(self, body: str) -> List[str]:
        """Check response body text for hints of vulnerabilities."""
        hints = []
        try:
            body_lower = body.lower()

            for vuln_type, patterns in self.VULN_HINT_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, body_lower, re.IGNORECASE):
                        hints.append(vuln_type)
                        break
        except Exception:
            pass

        return hints

    def _make_endpoint_key(self, url: str, method: str) -> str:
        """Create a unique key for an endpoint."""
        parsed = urlparse(url)
        path = parsed.path or "/"
        query = parsed.query

        # For endpoints with query params, include them if they look like
        # parameterized endpoints (e.g., ?id=123)
        if query:
            params = parse_qs(query)
            # Only include params that have values that look like IDs
            interesting_params = {
                k: v for k, v in params.items() if re.match(r"^\d+$", str(v[0]))
            }
            if interesting_params:
                return f"{method}:{path}?{list(interesting_params.keys())[0]}"

        return f"{method}:{path}"

    async def _analyze_javascript(self, response: Response) -> None:
        """Extract endpoints from JavaScript file."""
        try:
            content = await response.text()

            # Extract URLs using regex
            url_pattern = r'["\']([/a-zA-Z0-9\-_.~=?&]+)["\']'
            urls = re.findall(url_pattern, content)

            for url in urls:
                # Make absolute URL
                if url.startswith("/"):
                    full_url = urljoin(self.base_url, url)
                elif not url.startswith("http"):
                    full_url = urljoin(self.base_url, "/" + url)
                else:
                    full_url = url

                # Only same-origin
                if urlparse(full_url).netloc == self.base_domain:
                    self._enqueue_url(full_url, depth=0)

            # Extract API endpoint patterns
            api_patterns = [
                r'["\'](/api/[^"\']+)["\']',
                r'["\'](/rest/[^"\']+)["\']',
                r'["\'](/v\d+/[^"\']+)["\']',
                r'fetch\(["\']([^"\']+)["\']',
                r'axios\.[get|post|put|delete]+\(["\']([^"\']+)["\']',
            ]

            for pattern in api_patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    full_url = urljoin(self.base_url, match)
                    if urlparse(full_url).netloc == self.base_domain:
                        endpoint_key = self._make_endpoint_key(full_url, "GET")
                        if endpoint_key not in self.discovered_endpoints:
                            endpoint = DiscoveredEndpoint(
                                url=full_url,
                                method="GET",
                                endpoint_type=EndpointType.API,
                                discovery_method=DiscoveryMethod.JAVASCRIPT,
                            )
                            self.discovered_endpoints[endpoint_key] = endpoint
                            self.stats.js_endpoints_extracted += 1

            self.stats.javascript_files += 1

        except Exception as e:
            print(f"Error analyzing JavaScript: {e}")

    async def _analyze_page(self, url: str, depth: int) -> None:
        """Analyze a page and extract information."""
        if depth > self.max_depth or len(self.visited_urls) >= self.max_pages:
            return

        if url in self.visited_urls:
            return

        self.visited_urls.add(url)

        try:
            await self._page.goto(url, wait_until="networkidle", timeout=30000)

            # Wait for potential dynamic content
            await asyncio.sleep(1)

            # Extract forms
            if self.analyze_forms:
                forms = await self._extract_forms()
                self.forms_found.extend(forms)
                self.stats.forms_discovered += len(forms)

            # Extract links
            links = await self._extract_links()
            for link in links:
                self._enqueue_url(link, depth + 1)

            # Extract API calls from network
            if self.discover_apis:
                # Give time for XHR/fetch calls
                await asyncio.sleep(0.5)

            # Extract headers/cookies
            await self._extract_auth_data()

        except Exception as e:
            print(f"Error analyzing page {url}: {e}")

    async def _extract_forms(self) -> List[Dict[str, Any]]:
        """Extract forms from current page."""
        forms = []

        try:
            form_elements = await self._page.query_selector_all("form")

            for form in form_elements:
                action = await form.get_attribute("action")
                method = await form.get_attribute("method") or "GET"

                if action:
                    action_url = urljoin(self._page.url, action)
                else:
                    action_url = self._page.url

                # Extract fields
                fields = []
                inputs = await form.query_selector_all("input, textarea, select")

                for inp in inputs:
                    field = await inp.evaluate("el => ({"
                        "name: el.name || el.id || '', "
                        "type: el.type || 'text', "
                        "value: el.value || '', "
                        "required: el.required || false"
                        "})")
                    if field["name"]:
                        fields.append(field)

                form_data = {
                    "action": action_url,
                    "method": method.upper(),
                    "fields": fields,
                }

                forms.append(form_data)

                # Also create a discovered endpoint for the form
                endpoint_key = self._make_endpoint_key(action_url, method.upper())
                if endpoint_key not in self.discovered_endpoints:
                    endpoint = DiscoveredEndpoint(
                        url=action_url,
                        method=method.upper(),
                        endpoint_type=EndpointType.PAGE,
                        discovery_method=DiscoveryMethod.FORM,
                        form_fields=fields,
                    )
                    self.discovered_endpoints[endpoint_key] = endpoint

        except Exception as e:
            print(f"Error extracting forms: {e}")

        return forms

    async def _extract_links(self) -> List[str]:
        """Extract links from current page."""
        links = []

        try:
            # Get all links
            link_elements = await self._page.query_selector_all("a[href]")

            for link in link_elements:
                href = await link.get_attribute("href")
                if href:
                    full_url = urljoin(self._page.url, href)
                    parsed = urlparse(full_url)

                    # Only same-origin
                    if parsed.netloc == self.base_domain:
                        links.append(full_url)

        except Exception as e:
            print(f"Error extracting links: {e}")

        return links

    async def _extract_auth_data(self) -> None:
        """Extract authentication data from current state."""
        try:
            # Get cookies
            cookies = await self._context.cookies()
            for cookie in cookies:
                self.cookies[cookie["name"]] = cookie["value"]

                # Look for session/JWT cookies
                name_lower = cookie["name"].lower()
                if "session" in name_lower or "token" in name_lower:
                    if "jwt" in name_lower or "." in cookie["value"]:
                        # JWT token
                        self.storage["jwt_token"] = cookie["value"]
                        self.storage["jwt_cookie_name"] = cookie["name"]

            # Get local storage
            local_storage = await self._page.evaluate("() => Object.assign({}, localStorage)")
            for key, value in local_storage.items():
                if "token" in key.lower() or "auth" in key.lower():
                    self.storage[f"local_{key}"] = value
                    if "jwt" in key.lower() or "." in value:
                        self.storage["jwt_token"] = value
                        self.storage["jwt_storage_key"] = key

            # Get session storage
            session_storage = await self._page.evaluate("() => Object.assign({}, sessionStorage)")
            for key, value in session_storage.items():
                if "token" in key.lower() or "auth" in key.lower():
                    self.storage[f"session_{key}"] = value

        except Exception as e:
            print(f"Error extracting auth data: {e}")

    def _enqueue_url(self, url: str, depth: int) -> None:
        """Add URL to the queue if not already visited."""
        if url not in self.visited_urls and url not in [q[0] for q in self.url_queue]:
            self.url_queue.append((url, depth))

    async def _process_queue(self) -> None:
        """Process the URL queue."""
        while self.url_queue and len(self.visited_urls) < self.max_pages:
            url, depth = self.url_queue.pop(0)
            await self._analyze_page(url, depth)

    async def crawl(self) -> CrawlerReport:
        """
        Run the intelligent crawler.

        Returns:
            CrawlerReport with all discovered data
        """
        await self._init_browser()

        try:
            # Start with base URL
            self._enqueue_url(self.base_url, 0)

            # Process queue
            await self._process_queue()

            # Final statistics
            self.stats.end_time = datetime.utcnow().isoformat()

            # Build report
            report = self._generate_report()

            return report

        finally:
            await self._close_browser()

    def _generate_report(self) -> CrawlerReport:
        """Generate a crawler report from collected data."""
        # Convert endpoints to the format expected by CrawlerReport
        endpoints_list = []
        for endpoint in self.discovered_endpoints.values():
            endpoints_list.append(endpoint.to_dict())

        # Count interesting endpoints
        for endpoint in self.discovered_endpoints.values():
            if endpoint.interesting:
                self.stats.interesting_endpoints += 1
            if endpoint.endpoint_type == EndpointType.API:
                self.stats.api_endpoints += 1
            if endpoint.endpoint_type == EndpointType.AUTH:
                self.stats.auth_endpoints += 1

        # Build target config from discovered endpoints
        custom_endpoints = {}
        for endpoint in self.discovered_endpoints.values():
            key = self._url_to_endpoint_key(endpoint.url)
            custom_endpoints[key] = endpoint.url

        target_config = TargetConfig(
            name=f"agent_crawled_{self.base_domain}",
            base_url=self.base_url,
            authentication=self._build_auth_config(),
            endpoints=EndpointsConfig(base="", custom=custom_endpoints),
        )

        return CrawlerReport(
            target=self.base_url,
            base_url=self.base_url,
            timestamp=datetime.utcnow().isoformat(),
            target_config=target_config,
            endpoints=endpoints_list,
            forms=self.forms_found,
            statistics=self.stats.to_dict(),
            auth_data=self._build_auth_dict(),
            storage_data=self.storage,
            discovered_cookies=self.cookies,
        )

    def _url_to_endpoint_key(self, url: str) -> str:
        """Convert URL to endpoint key format."""
        parsed = urlparse(url)
        path = parsed.path

        if not path or path == "/":
            return "root"

        # Convert path to key format
        return path.strip("/").replace("/", "_").replace("-", "_")

    def _build_auth_config(self) -> AuthConfig:
        """Build AuthConfig from discovered auth data."""
        auth_type = AuthType.NONE

        # Determine auth type from discovered data
        if self.storage.get("jwt_token"):
            auth_type = AuthType.BEARER
        elif self.storage.get("auth_type") == "session":
            auth_type = AuthType.FORM
        elif self.storage.get("auth_type") == "basic":
            auth_type = AuthType.BASIC

        # Build headers
        headers = {}
        if self.storage.get("jwt_token"):
            headers["Authorization"] = f"Bearer {self.storage['jwt_token']}"

        return AuthConfig(
            type=auth_type,
            token=self.storage.get("jwt_token"),
            headers=headers,
        )

    def _build_auth_dict(self) -> Dict[str, Any]:
        """Build auth data dictionary."""
        auth_data: Dict[str, Any] = {
            "type": self.storage.get("auth_type", "unknown"),
        }

        if self.storage.get("jwt_token"):
            auth_data["jwt_token"] = self.storage.get("jwt_token")

        if self.storage.get("jwt_cookie_name"):
            auth_data["cookie_name"] = self.storage.get("jwt_cookie_name")

        if self.cookies:
            auth_data["cookies"] = self.cookies

        return auth_data


class AIGuidedCrawler(AgentCrawler):
    """
    AI-guided crawler that uses an LLM to make intelligent decisions.

    Can use z.ai, OpenAI, or any LLM API to:
    - Decide which endpoints to explore
    - Generate test payloads
    - Analyze responses for vulnerabilities
    - Suggest attack paths
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        api_provider: str = "openai",  # openai, anthropic, zai, etc
        model: str = "gpt-4",
        **kwargs,
    ):
        """Initialize AI-guided crawler.

        Args:
            base_url: The base URL to crawl
            api_key: API key for the LLM provider
            api_provider: The LLM provider (openai, anthropic, zai, etc)
            model: The model to use
            **kwargs: Additional arguments passed to AgentCrawler
        """
        super().__init__(base_url, **kwargs)

        self.api_key = api_key
        self.api_provider = api_provider
        self.model = model
        self.ai_context: List[Dict[str, Any]] = []

    async def _get_ai_suggestions(self, context: str) -> Dict[str, Any]:
        """Get AI suggestions for next actions."""
        # This is a placeholder for AI integration
        # In production, this would call the actual LLM API

        prompt = f"""You are a security testing assistant. Given the following context
from a web application crawl, suggest:

1. Which endpoints to explore next
2. What test cases to run
3. Potential vulnerabilities to check

Context:
{context}

Respond in JSON format with:
{{
    "suggested_endpoints": ["url1", "url2"],
    "test_suggestions": ["test1", "test2"],
    "vulnerability_hints": ["hint1", "hint2"]
}}
"""

        # Placeholder for actual API call
        # Implementation depends on the API provider

        return {
            "suggested_endpoints": [],
            "test_suggestions": [],
            "vulnerability_hints": [],
        }

    async def _analyze_with_ai(self, response_data: str) -> List[str]:
        """Analyze response with AI for vulnerability hints."""
        prompt = f"""Analyze this HTTP response for security vulnerabilities.
Look for: SQL injection, XSS, authentication issues, data exposure, etc.

Response:
{response_data[:5000]}

Return a JSON list of vulnerability findings.
"""

        # Placeholder for actual API call
        return []


async def crawl_with_agent(
    url: str,
    max_pages: int = 500,
    headless: bool = True,
    output_file: Optional[str] = None,
) -> CrawlerReport:
    """
    Convenience function to run the agent crawler.

    Args:
        url: The base URL to crawl
        max_pages: Maximum pages to visit
        headless: Run in headless mode
        output_file: Optional file to save the report

    Returns:
        CrawlerReport with discovered data
    """
    crawler = AgentCrawler(
        base_url=url,
        max_pages=max_pages,
        headless=headless,
    )

    report = await crawler.crawl()

    if output_file:
        import yaml

        with open(output_file, "w") as f:
            yaml.dump(report.model_dump(), f, default_flow_style=False)

    return report


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        url = sys.argv[1]
        output = sys.argv[2] if len(sys.argv) > 2 else None

        report = asyncio.run(crawl_with_agent(url, output_file=output))

        print(f"Crawled {report.target.name}")
        print(f"Discovered {len(report.endpoints)} endpoints")
        print(f"Found {len(report.forms)} forms")
        print(f"Statistics: {report.statistics}")
    else:
        print("Usage: python -m dast.agent_crawler <url> [output_file]")
