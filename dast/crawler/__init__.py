"""Katana crawler for DAST.

Uses Katana (ProjectDiscovery) for intelligent endpoint discovery.
"""

from dast.crawler.katana import (
    KatanaCrawler,
    crawl_with_katana,
    parse_cookies_string,
)
from dast.crawler.models import KatanaEndpoint, KatanaStatistics
from dast.crawler.report import SimpleCrawlerReport

__all__ = [
    "KatanaCrawler",
    "crawl_with_katana",
    "parse_cookies_string",
    "KatanaEndpoint",
    "KatanaStatistics",
    "SimpleCrawlerReport",
]
