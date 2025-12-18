"""Parameter classification for vulnerability detection.

Identifies potentially injectable parameters based on naming patterns.
This helps prioritize which endpoints and parameters to test first.
"""

from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse


INJECTABLE_PATTERNS = {
    "sqli": [
        "id", "search", "query", "q", "filter", "find", "item",
        "product", "user", "category", "email", "username", "name",
    ],
    "xss": [
        "name", "comment", "message", "text", "content", "input",
        "desc", "feedback", "review", "callback", "redirect",
    ],
    "path_traversal": [
        "file", "path", "folder", "document", "image",
        "download", "include", "template", "lang", "filename",
    ],
    "ssrf": [
        "url", "link", "redirect", "next", "dest", "target",
        "callback", "return", "feed", "site", "uri", "forward",
    ],
    "command": [
        "host", "hostname", "ip", "port", "cmd", "exec",
        "command", "ping", "traceroute",
    ],
}


def classify_parameter(param_name: str) -> List[str]:
    """Classify a parameter name by potential vulnerability types.

    Args:
        param_name: The parameter name to classify

    Returns:
        List of vulnerability types that this parameter may be susceptible to.
        Returns ["generic"] if no specific pattern matches.
    """
    vuln_types = []
    param_lower = param_name.lower()

    for vuln_type, patterns in INJECTABLE_PATTERNS.items():
        for pattern in patterns:
            if pattern in param_lower:
                vuln_types.append(vuln_type)
                break

    return vuln_types or ["generic"]


def extract_parameters_from_url(url: str, method: str = "GET") -> List[Dict[str, Any]]:
    """Extract query parameters from a URL.

    Args:
        url: The URL to parse
        method: HTTP method (for future extensibility)

    Returns:
        List of parameter dictionaries with name, value, and location
    """
    parsed = urlparse(url)
    params = []

    if parsed.query:
        for name, values in parse_qs(parsed.query).items():
            params.append({
                "name": name,
                "value": values[0] if values else "",
                "location": "query",
            })

    return params
