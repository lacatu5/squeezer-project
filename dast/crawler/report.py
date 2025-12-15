"""Crawler report models for Katana."""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from pydantic import BaseModel, Field as PDField

from dast.config import (
    AuthConfig,
    AuthType,
    EndpointsConfig,
    TargetConfig,
)
from dast.crawler.models import KatanaEndpoint, KatanaStatistics


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
        name: Optional[str] = None,
        prioritize: bool = True,
        exclude_static: bool = True,
    ) -> TargetConfig:
        """Convert crawler report to TargetConfig for vulnerability scanning.

        Args:
            name: Optional name for the target (defaults to "crawled_target")
            prioritize: Sort endpoints by priority (high-value targets first)
            exclude_static: Filter out static assets (.css, .png, etc.)

        Returns:
            TargetConfig ready for vulnerability scanning
        """
        # Parse base URL from report
        parsed_base = urlparse(self.target)
        if parsed_base.netloc:
            target_name = name or f"crawled_{parsed_base.netloc.replace('.', '_')}"
        else:
            target_name = name or "crawled_target"

        # Filter and process endpoints
        filtered_endpoints: List[Dict[str, Any]] = []

        for ep in self.endpoints:
            url = ep.get('full_url', ep.get('url', ''))

            # Skip static assets if enabled
            if exclude_static and self._is_static_asset(url):
                continue

            filtered_endpoints.append(ep)

        # Log warning if no endpoints after filtering
        if not filtered_endpoints:
            from dast.utils import logger
            logger.warning("Crawler report has no endpoints after filtering")

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
        # Note: cookies in report are just names (no values)
        # User should provide actual cookie values via --cookies flag
        if self.cookies:
            auth_config = AuthConfig(
                type=AuthType.NONE,
                headers={"Cookie": "; ".join(self.cookies)},
            )
        else:
            auth_config = AuthConfig()

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
