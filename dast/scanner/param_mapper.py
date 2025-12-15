"""Automatic parameter detection and template mapping.

This module analyzes discovered endpoints to extract parameters and maps them
to appropriate vulnerability templates based on parameter names and patterns.
"""

import re
from collections import defaultdict
from typing import Dict, List, Optional, Set
from urllib.parse import parse_qs, urlparse

from dast.config import EndpointInfo, ParameterInfo, Template


# Parameter name patterns that suggest vulnerability types
PARAMETER_PATTERNS = {
    # SQL Injection - search, id, filter parameters
    "sqli": {
        "patterns": [r"id", r"search", r"query", r"q", r"filter", r"find", r"lookup",
                    r"item", r"product", r"user", r"category", r"sort", r"order",
                    r"where", r"limit", r"offset", r"email", r"username", r"name",
                    r"keyword", r"searchterm", r"input", r"value", r"data"],
        "methods": ["GET", "POST"],
        "confidence": "high",
    },
    # XSS - input, text, comment fields
    "xss": {
        "patterns": [r"name", r"comment", r"message", r"text", r"content", r"input",
                    r"desc", r"description", r"feedback", r"review", r"search"],
        "methods": ["GET", "POST"],
        "confidence": "medium",
    },
    # Command Injection - host, port, url parameters
    "command": {
        "patterns": [r"host", r"hostname", r"ip", r"port", r"url", r"dest", r"target",
                    r"file", r"path", r"filename", r"cmd", r"exec"],
        "methods": ["GET", "POST"],
        "confidence": "high",
    },
    # Path Traversal - file, path parameters
    "path_traversal": {
        "patterns": [r"file", r"path", r"folder", r"directory", r"document", r"image",
                    r"download", r"include", r"require", r"template", r"lang"],
        "methods": ["GET", "POST"],
        "confidence": "high",
    },
    # SSRF - url, dest parameters
    "ssrf": {
        "patterns": [r"url", r"link", r"redirect", r"next", r"dest", r"target", r"to",
                    r"callback", r"return", r"feed", r"site", r"uri", r"link",
                    r"forward", r"goto"],
        "methods": ["GET", "POST"],
        "confidence": "high",
    },
    # IDOR - id, user_id parameters
    "idor": {
        "patterns": [r"\bid\b", r"user_id", r"user", r"account", r"profile", r"order_id",
                    r"order", r"basket_id", r"cart_id", r"item_id", r"document_id"],
        "methods": ["GET", "POST", "PUT", "DELETE", "PATCH"],
        "confidence": "medium",
    },
}


def extract_parameters_from_url(url: str, method: str = "GET") -> List[ParameterInfo]:
    """Extract query parameters from a URL.

    Args:
        url: The URL to parse
        method: HTTP method

    Returns:
        List of ParameterInfo objects
    """
    params = []
    parsed = urlparse(url)

    if parsed.query:
        # Parse query string, keeping empty values (like "to=" or "q=")
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        for param_name, values in query_dict.items():
            # Even if empty, record the parameter name
            example_vals = values[:3] if values and any(values) else []
            params.append(ParameterInfo(
                name=param_name,
                type="query",
                location="url",
                example_values=example_vals,
            ))

    return params


def extract_path_parameters(path: str) -> List[str]:
    """Extract potential path parameters from a URL path.

    For example: /api/users/123/items/456 -> ['123', '456']

    Args:
        path: URL path

    Returns:
        List of potential path parameter values
    """
    segments = path.strip("/").split("/")
    path_params = []

    for segment in segments:
        # Skip if segment looks like a word (likely a resource name)
        if re.match(r"^[a-z_]+(/[a-z_]+)*$", segment):
            continue
        # If segment contains numbers or mixed chars, it might be a parameter
        if re.search(r"\d", segment) or len(segment) > 20:
            path_params.append(segment)

    return path_params


def classify_parameter(param_name: str, method: str = "GET") -> Dict[str, int]:
    """Classify a parameter name by vulnerability type.

    Args:
        param_name: The parameter name to classify
        method: HTTP method

    Returns:
        Dict mapping vuln type to confidence score (0-100)
    """
    param_lower = param_name.lower()
    scores = {}

    for vuln_type, config in PARAMETER_PATTERNS.items():
        # Check method compatibility
        if method.upper() not in config["methods"]:
            continue

        # Check if any pattern matches
        for pattern in config["patterns"]:
            if re.search(pattern, param_lower, re.IGNORECASE):
                base_score = 50
                # Exact match gets higher score
                if re.match(f"^{pattern}$", param_lower, re.IGNORECASE):
                    base_score = 90
                # Parameter contains the pattern
                elif pattern in param_lower:
                    base_score = 70

                confidence_mult = {"high": 1.2, "medium": 1.0, "low": 0.8}
                scores[vuln_type] = min(100, int(base_score * confidence_mult[config["confidence"]]))
                break

    return scores


def map_endpoints_to_templates(
    endpoints: List[EndpointInfo],
    templates: List[Template],
) -> Dict[str, List[Dict]]:
    """Map discovered endpoints to appropriate templates.

    Args:
        endpoints: List of discovered endpoints
        templates: List of available templates

    Returns:
        Dict mapping template_id to list of {endpoint, parameter, method} tuples
    """
    # Build template lookup by tags
    template_by_tag: Dict[str, List[Template]] = defaultdict(list)
    for template in templates:
        for tag in template.info.tags:
            template_by_tag[tag].append(template)

    # Map endpoints to parameters
    mappings: Dict[str, List[Dict]] = defaultdict(list)

    for endpoint in endpoints:
        # Extract parameters from URL if not already present
        if not endpoint.query_params and endpoint.url:
            params = extract_parameters_from_url(endpoint.url, endpoint.method)
        else:
            params = endpoint.query_params

        for param in params:
            # Classify this parameter
            scores = classify_parameter(param.name, endpoint.method)

            # Map to templates based on scores
            for vuln_type, score in scores.items():
                if score >= 50:  # Only include confident matches
                    # Find matching templates
                    matching_templates = [
                        t for t in templates
                        if vuln_type in t.info.tags or
                        any(vuln_type in tag for tag in t.info.tags)
                    ]

                    for template in matching_templates:
                        mappings[template.id].append({
                            "endpoint": endpoint.url,
                            "path": endpoint.path,
                            "method": endpoint.method,
                            "parameter": param.name,
                            "param_type": param.type,
                            "confidence": score,
                        })

    return mappings


def build_auto_target_config(
    endpoints: List[EndpointInfo],
    templates: List[Template],
    base_url: str,
) -> Dict[str, str]:
    """Build an auto-generated endpoint mapping for templates.

    This creates endpoint mappings like:
    {
        "sqli": "/rest/products/search?q=",
        "idor": "/api/baskets/{id}",
        ...
    }

    Args:
        endpoints: List of discovered endpoints
        templates: List of templates
        base_url: Base URL for the target

    Returns:
        Dict mapping endpoint variable names to paths
    """
    mappings = map_endpoints_to_templates(endpoints, templates)

    # For each template, pick the best endpoint
    auto_endpoints: Dict[str, str] = {}

    # Template ID to variable name mapping
    template_to_var = {
        "generic-sqli-get": "sqli",
        "generic-sqli-post-json": "sqli_post",
        "generic-xss-reflected": "xss_reflected",
        "generic-xss-stored": "xss_stored",
        "generic-command-injection": "command_injection",
        "generic-path-traversal": "path_traversal",
        "generic-ssrf": "ssrf",
    }

    for template_id, targets in mappings.items():
        # Sort by confidence and pick the best
        targets_sorted = sorted(targets, key=lambda x: x["confidence"], reverse=True)
        if targets_sorted:
            best = targets_sorted[0]
            var_name = template_to_var.get(template_id)

            if var_name:
                # Build the endpoint path with parameter
                if best["method"] == "GET" and best["parameter"]:
                    # Add parameter placeholder
                    if "?" in best["endpoint"]:
                        auto_endpoints[var_name] = best["endpoint"].replace(
                            f"{best['parameter']}=", f"{best['parameter']}="
                        )
                    else:
                        auto_endpoints[var_name] = f"{best['path']}?{best['parameter']}="
                else:
                    auto_endpoints[var_name] = best["path"]

    return auto_endpoints


def get_injectable_parameters(endpoints: List[EndpointInfo]) -> Dict[str, List[Dict]]:
    """Get all parameters that might be injectable from discovered endpoints.

    Args:
        endpoints: List of discovered endpoints

    Returns:
        Dict mapping endpoint path to list of injectable parameters
    """
    injectable: Dict[str, List[Dict]] = defaultdict(list)

    for endpoint in endpoints:
        # Extract parameters from URL
        if endpoint.url:
            params = extract_parameters_from_url(endpoint.url, endpoint.method)

            for param in params:
                scores = classify_parameter(param.name, endpoint.method)

                if scores:  # If any vulnerability type matched
                    injectable[endpoint.path].append({
                        "name": param.name,
                        "type": param.type,
                        "method": endpoint.method,
                        "vuln_types": list(scores.keys()),
                        "max_confidence": max(scores.values()),
                    })

    return injectable


def summarize_parameters(endpoints: List[EndpointInfo]) -> Dict[str, int]:
    """Summarize discovered parameters by type.

    Args:
        endpoints: List of discovered endpoints

    Returns:
        Dict with counts of each parameter type
    """
    summary = defaultdict(int)

    for endpoint in endpoints:
        # Extract parameters if not already present
        if not endpoint.query_params and endpoint.url:
            params = extract_parameters_from_url(endpoint.url, endpoint.method)
        else:
            params = endpoint.query_params + endpoint.form_fields + endpoint.json_params

        for param in params:
            scores = classify_parameter(param.name, endpoint.method)
            for vuln_type in scores:
                summary[vuln_type] += 1

    return dict(summary)
