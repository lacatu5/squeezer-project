"""Crawlers for DAST.

Supports:
- Katana: Fast external binary crawler for endpoint discovery
"""

from dast.crawler.katana import (
    KatanaCrawler,
    crawl_with_katana,
)
from dast.crawler.models import KatanaEndpoint, KatanaStatistics
from dast.crawler.report import SimpleCrawlerReport

__all__ = [
    "KatanaCrawler",
    "crawl_with_katana",
    "KatanaEndpoint",
    "KatanaStatistics",
    "SimpleCrawlerReport",
]
