from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from dast.config import TargetConfig
from dast.utils import logger


async def discover_and_add_json_endpoints(
    target: TargetConfig,
    endpoints: list,
    cookies: Optional[Dict[str, str]] = None,
) -> None:
    _add_fallback_endpoints(target, endpoints)


def _add_fallback_endpoints(target: TargetConfig, endpoints: list) -> None:
    """Add common JSON injection endpoints as fallback.

    Args:
        target: TargetConfig to modify
        endpoints: List of discovered endpoints
    """
    from rich.console import Console

    console = Console()

    common_endpoints = {
        "xss_stored": "JSON:/rest/feedback:comment",
        "xss_reflected": "JSON:/rest/products/search:q",
        "command_injection": "JSON:/rest/products/search:q",
    }

    count = 0
    for var, spec in common_endpoints.items():
        path = spec.split(":")[1]
        if any(path in ep.get("url", "") for ep in endpoints):
            target.endpoints.custom[var] = spec
            count += 1

    if count > 0:
        console.print(f"[dim]  → {count} JSON injection endpoints added (fallback)[/dim]")

    has_api = any(
        ep.get("url", "").startswith("/api/") or ep.get("url", "").startswith("/rest/")
        for ep in endpoints
    )

    if has_api:
        target.endpoints.custom.setdefault("ssti", "JSON:/rest/products:input")
        target.endpoints.custom.setdefault("xxe", "XML:/rest/data")
        count += 2
        console.print(f"[dim]  → Added SSTI and XXE endpoints for testing[/dim]")


def add_json_injection_endpoints(
    target: TargetConfig,
    endpoints: list,
) -> None:
    """Add JSON injection endpoints based on discovered paths.

    Simple version that maps discovered paths to known injection points
    without making additional HTTP requests.

    Args:
        target: TargetConfig to modify
        endpoints: List of discovered endpoint dictionaries
    """
    paths = set()
    for ep in endpoints:
        path = ep.get("url", "").strip("/")
        if path:
            paths.add(f"/{path}")

    json_injection_points = {
        "xss_json_post": ("/rest/feedback", "comment"),
        "xss_json_search": ("/rest/products/search", "q"),
        "xss_json_comment": ("/rest/comments", "comment"),
        "command_search": ("/rest/products/search", "q"),
        "sqli_basket": ("/rest/basket/", "quantity"),
        "sqli_products": ("/rest/products/", "quantity"),
    }

    added_count = 0
    for var_name, (path, field) in json_injection_points.items():
        for discovered_path in paths:
            if discovered_path.startswith(path.rstrip("/")) or path.startswith(discovered_path.rstrip("/")):
                target._endpoints_custom[var_name] = f"{path}?{field}="
                added_count += 1
                break

    if added_count > 0:
        logger.info(f"Added {added_count} JSON injection endpoints for testing")


def build_auto_target_config(
    endpoints: List[Any],
    templates: List[Any],
    base_url: str,
) -> Dict[str, str]:
    """Build automatic target configuration from discovered endpoints.

    Maps common endpoint patterns to template variables for automated
    vulnerability scanning.

    Args:
        endpoints: List of discovered endpoint objects
        templates: List of available templates (unused but kept for interface)
        base_url: Base URL of the target

    Returns:
        Dictionary mapping template variable names to endpoint URLs
    """
    auto_endpoints = {}

    for ep in endpoints:
        path = getattr(ep, "path", urlparse(getattr(ep, "url", "")).path)
        method = getattr(ep, "method", "GET")

        if "/rest/user/login" in path or "/api/user/login" in path:
            auto_endpoints["login"] = f"{base_url}{path}"
        elif "/rest/products/search" in path or "/api/products/search" in path:
            auto_endpoints["search"] = f"{base_url}{path}"
        elif "/rest/basket" in path or "/api/basket" in path:
            auto_endpoints["basket"] = f"{base_url}{path}"
        elif "/rest/feedback" in path or "/api/feedback" in path:
            auto_endpoints["feedback"] = f"{base_url}{path}"

    return auto_endpoints
