"""Data models for Katana crawler."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class KatanaEndpoint:
    """An endpoint discovered by Katana."""

    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    content_length: int = 0
    source: str = "unknown"  
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    query_params: Dict[str, str] = field(default_factory=dict)  

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
            "query_params": self.query_params,
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
            "checkout", "payment", "order", "basket", "manage"
        ]
        return any(pattern in url_lower for pattern in interesting)

    def _extract_query_params(self) -> Dict[str, str]:
        """Extract query parameters from the URL."""
        if "?" not in self.url:
            return {}
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        return {k: v[0] if len(v) == 1 else v for k, v in params.items()}


@dataclass
class KatanaStatistics:
    """Statistics from Katana crawl."""

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
