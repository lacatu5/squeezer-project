"""Crawlers for DAST.

Supports:
- Katana: Fast external binary crawler for endpoint discovery
- DOMXSSValidator: Browser-based XSS validation
"""

from dast.crawler.katana import (
    KatanaCrawler,
    crawl_with_katana,
    parse_cookies_string,
)
from dast.crawler.models import KatanaEndpoint, KatanaStatistics
from dast.crawler.playwright import (
    DOMXSSFinding,
    DOMXSSValidator,
    validate_dom_xss,
)
from dast.crawler.report import SimpleCrawlerReport

__all__ = [
    "KatanaCrawler",
    "crawl_with_katana",
    "parse_cookies_string",
    "KatanaEndpoint",
    "KatanaStatistics",
    "SimpleCrawlerReport",
    "DOMXSSValidator",
    "DOMXSSFinding",
    "validate_dom_xss",
]
