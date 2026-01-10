import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field as PDField

from squeezer.utils import load_static_files_config, load_keywords_config

_STATIC_CONFIG = load_static_files_config()
_KEYWORDS_CONFIG = load_keywords_config()
_STATIC_EXTENSIONS = set(ext.lstrip('.') for ext in _STATIC_CONFIG["extensions"])


@dataclass
class KatanaEndpoint:
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    content_length: int = 0
    source: str = "unknown"
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    query_params: Dict[str, str] = field(default_factory=dict)

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
        if any(url_lower.endswith(f".{ext}") for ext in _STATIC_EXTENSIONS):
            return "static"
        if any(p in url_lower for p in _KEYWORDS_CONFIG["auth"]):
            return "auth"
        if any(p in url_lower for p in _KEYWORDS_CONFIG["admin"]):
            return "admin"
        return "page"

    def _is_interesting(self) -> bool:
        url_lower = self.url.lower()
        return any(pattern in url_lower for pattern in _KEYWORDS_CONFIG["interesting"])

    def _extract_query_params(self) -> Dict[str, str]:
        if "?" not in self.url:
            return {}
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        return {k: v[0] if len(v) == 1 else v for k, v in params.items()}


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