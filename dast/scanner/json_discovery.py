"""JSON body parameter discovery for API endpoints.

This module probes API endpoints to discover what JSON fields they accept,
enabling the scanner to test POST/JSON endpoints for injection vulnerabilities.
"""

import asyncio
import json
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx

from dast.utils import logger


# Common JSON field names that suggest vulnerability types
JSON_FIELD_PATTERNS = {
    "sqli": {
        "patterns": [r"id", r"search", r"query", r"q", r"filter", r"find", r"lookup",
                    r"item", r"product", r"user", r"category", r"sort", r"order",
                    r"email", r"username", r"name", r"keyword", r"value"],
    },
    "xss": {
        "patterns": [r"name", r"comment", r"message", r"text", r"content", r"input",
                    r"desc", r"description", r"feedback", r"review", r"bio", r"note"],
    },
    "command": {
        "patterns": [r"host", r"hostname", r"ip", r"port", r"url", r"dest", r"target",
                    r"file", r"path", r"filename", r"cmd", r"exec", r"command"],
    },
    "path_traversal": {
        "patterns": [r"file", r"path", r"folder", r"directory", r"document", r"image",
                    r"download", r"include", r"template", r"lang", r"filename"],
    },
    "ssrf": {
        "patterns": [r"url", r"link", r"redirect", r"next", r"dest", r"target", r"to",
                    r"callback", r"return", r"feed", r"site", r"uri", r"forward", r"link"],
    },
}


# Sample payloads to discover JSON fields
DISCOVERY_PAYLOADS = {
    # Generic API payloads that will cause the server to reject with field validation errors
    "rest_api": {
        "id": "1",
        "name": "test",
        "email": "test@example.com",
        "username": "testuser",
        "password": "Test123!",
        "comment": "test comment",
        "message": "test message",
        "content": "test content",
        "feedback": "test feedback",
        "review": "test review",
        "query": "test",
        "search": "test",
        "q": "test",
        "filter": "test",
        "url": "http://example.com",
        "link": "http://example.com",
        "file": "/etc/passwd",
        "path": "/tmp/test",
        "filename": "test.txt",
        "ip": "127.0.0.1",
        "host": "localhost",
        "port": "8080",
        "quantity": 1,
        "price": 9.99,
        "basketId": 1,
        "productId": 1,
        "couponCode": "TEST",
        "rating": 5,
    },
    # GraphQL payload
    "graphql": {
        "query": "query { __typename }",
    },
}


async def probe_endpoint_for_json_fields(
    url: str,
    method: str,
    client: httpx.AsyncClient,
    headers: Optional[Dict[str, str]] = None,
) -> Set[str]:
    """Probe a single endpoint to discover JSON field names.

    Tries sending a discovery payload and parses the error response
    to extract field names.

    Args:
        url: The endpoint URL
        method: HTTP method (POST, PUT, PATCH, etc.)
        client: HTTP client
        headers: Optional headers (will include Content-Type: application/json)

    Returns:
        Set of discovered field names
    """
    fields = set()

    if method.upper() not in ("POST", "PUT", "PATCH"):
        return fields

    # Prepare headers
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)

    # Try the REST API discovery payload
    payload = DISCOVERY_PAYLOADS["rest_api"]

    try:
        response = await client.post(url, json=payload, headers=req_headers, timeout=10)

        # Check response for field information
        text = response.text

        # Parse JSON response
        try:
            resp_json = response.json()

            # Extract field names from various error response formats
            # Format 1: { "errors": [{ "param": "fieldName" }] }
            if "errors" in resp_json and isinstance(resp_json["errors"], list):
                for error in resp_json["errors"]:
                    if isinstance(error, dict):
                        for key in ["param", "field", "property", "name"]:
                            if key in error and isinstance(error[key], str):
                                fields.add(error[key])

            # Format 2: { "message": "field X is required", "details": {...} }
            if "message" in resp_json:
                msg = str(resp_json["message"]).lower()
                # Look for patterns like "field 'email' is required"
                import re
                field_matches = re.findall(r"['\"]([\w_]+)['\"]", msg)
                fields.update(field_matches)

            # Format 3: Validation errors object { "validation": { "email": "required" } }
            if "validation" in resp_json and isinstance(resp_json["validation"], dict):
                fields.update(resp_json["validation"].keys())

            # Format 4: Direct field listing { "fields": ["email", "name"] }
            if "fields" in resp_json:
                if isinstance(resp_json["fields"], list):
                    fields.update(resp_json["fields"])
                elif isinstance(resp_json["fields"], dict):
                    fields.update(resp_json["fields"].keys())

            # Format 5: Axios/Express style { "errors": { "email": "required" } }
            if isinstance(resp_json.get("errors"), dict):
                fields.update(resp_json["errors"].keys())

        except (json.JSONDecodeError, ValueError):
            # Response isn't JSON, try regex on text
            import re
            # Look for field names in error messages
            field_matches = re.findall(r"['\"]([\w_]+)['\"]", text)
            fields.update(field_matches)

    except Exception as e:
        logger.debug(f"Probe failed for {url}: {e}")

    return fields


async def discover_json_fields_from_responses(
    url: str,
    client: httpx.AsyncClient,
    headers: Optional[Dict[str, str]] = None,
) -> Set[str]:
    """Discover JSON fields by analyzing GET response structure.

    Many APIs return the expected schema in their responses.

    Args:
        url: The endpoint URL
        client: HTTP client
        headers: Optional headers

    Returns:
        Set of discovered field names
    """
    fields = set()

    try:
        response = await client.get(url, headers=headers or {}, timeout=10)

        if not response.headers.get("content-type", "").startswith("application/json"):
            return fields

        resp_json = response.json()

        # Extract field names from response
        def extract_keys(obj, prefix=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    fields.add(key)
                    if isinstance(value, (dict, list)):
                        extract_keys(value, f"{prefix}.{key}" if prefix else key)
            elif isinstance(obj, list) and obj:
                for item in obj[:3]:  # Check first 3 items
                    extract_keys(item, prefix)

        extract_keys(resp_json)

    except Exception as e:
        logger.debug(f"Response analysis failed for {url}: {e}")

    return fields


def classify_json_field(field_name: str) -> Dict[str, int]:
    """Classify a JSON field name by vulnerability type.

    Args:
        field_name: The field name to classify

    Returns:
        Dict mapping vuln type to confidence score (0-100)
    """
    import re

    field_lower = field_name.lower()
    scores = {}

    for vuln_type, config in JSON_FIELD_PATTERNS.items():
        for pattern in config["patterns"]:
            if re.search(pattern, field_lower, re.IGNORECASE):
                base_score = 50
                if re.match(f"^{pattern}$", field_lower, re.IGNORECASE):
                    base_score = 90
                elif pattern in field_lower:
                    base_score = 70
                scores[vuln_type] = base_score
                break

    return scores


async def discover_json_parameters(
    endpoints: List[Dict[str, Any]],
    client: Optional[httpx.AsyncClient] = None,
    headers: Optional[Dict[str, str]] = None,
    max_probes: int = 20,
) -> Dict[str, List[Dict]]:
    """Discover JSON body parameters from API endpoints.

    Args:
        endpoints: List of endpoint dicts with 'url', 'method', 'path'
        client: Optional HTTP client (creates one if not provided)
        headers: Optional headers
        max_probes: Maximum number of endpoints to probe (for speed)

    Returns:
        Dict mapping endpoint path to list of discovered parameter dicts
    """
    import random

    results = {}
    if not client:
        should_close = True
        client = httpx.AsyncClient(timeout=10.0, follow_redirects=True)
    else:
        should_close = False

    try:
        # Filter to POST/PUT/PATCH endpoints
        mutation_endpoints = [
            ep for ep in endpoints
            if ep.get("method", "GET").upper() in ("POST", "PUT", "PATCH")
        ]

        # Also include some GET endpoints that might return JSON schemas
        schema_endpoints = [
            ep for ep in endpoints
            if ep.get("method", "GET") == "GET" and "/api/" in ep.get("url", "")
        ]

        # Sample if too many
        if len(mutation_endpoints) > max_probes:
            mutation_endpoints = random.sample(mutation_endpoints, max_probes)

        if len(schema_endpoints) > max_probes:
            schema_endpoints = random.sample(schema_endpoints, max_probes)

        # Probe mutation endpoints
        probe_tasks = []
        for ep in mutation_endpoints:
            url = ep.get("full_url", ep.get("url", ""))
            if url:
                probe_tasks.append(
                    probe_endpoint_for_json_fields(url, ep.get("method", "POST"), client, headers)
                )

        # Analyze schema endpoints
        schema_tasks = []
        for ep in schema_endpoints:
            url = ep.get("full_url", ep.get("url", ""))
            if url:
                schema_tasks.append(
                    discover_json_fields_from_responses(url, client, headers)
                )

        # Run all tasks
        all_fields = await asyncio.gather(
            *(probe_tasks + schema_tasks),
            return_exceptions=True
        )

        # Combine results
        for i, ep in enumerate(mutation_endpoints):
            path = urlparse(ep.get("full_url", ep.get("url", ""))).path
            if path:
                if path not in results:
                    results[path] = []

                field_result = all_fields[i]
                if isinstance(field_result, Exception):
                    continue

                if isinstance(field_result, set):
                    for field_name in field_result:
                        classifications = classify_json_field(field_name)
                        if classifications:
                            results[path].append({
                                "name": field_name,
                                "type": "json",
                                "location": "body",
                                "vuln_types": list(classifications.keys()),
                                "max_confidence": max(classifications.values()),
                            })

        # Add schema endpoint results
        for i, ep in enumerate(schema_endpoints):
            path = urlparse(ep.get("full_url", ep.get("url", ""))).path
            if path:
                field_result = all_fields[len(mutation_endpoints) + i]
                if isinstance(field_result, Exception):
                    continue

                if isinstance(field_result, set):
                    for field_name in field_result:
                        classifications = classify_json_field(field_name)
                        if classifications and path not in results:
                            results[path] = []
                            results[path].append({
                                "name": field_name,
                                "type": "json",
                                "location": "body",
                                "vuln_types": list(classifications.keys()),
                                "max_confidence": max(classifications.values()),
                            })

    finally:
        if should_close:
            await client.aclose()

    # Log summary
    total_fields = sum(len(params) for params in results.values())
    logger.info(f"Discovered {total_fields} JSON fields across {len(results)} endpoints")

    return results


async def quick_discover(
    base_url: str,
    endpoint_paths: List[str],
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, List[str]]:
    """Quick discovery of JSON fields for common API endpoints.

    Uses known patterns for common REST APIs to guess likely fields.

    Args:
        base_url: Base URL
        endpoint_paths: List of endpoint paths
        headers: Optional headers

    Returns:
        Dict mapping endpoint path to list of likely field names
    """
    results = {}

    # Known field mappings for common endpoints
    common_fields = {
        # User/account endpoints
        "/rest/user/login": ["email", "password"],
        "/rest/user/registration": ["email", "password", "username", "name"],
        "/rest/user/security-question": ["securityQuestion", "answer"],
        "/rest/user/security-answer": ["securityQuestion", "answer"],
        "/rest/user/password": ["currentPassword", "newPassword", "repeatNewPassword"],
        "/rest/user/password-reset": ["email"],
        "/rest/user/data": ["email"],
        # Feedback/comments (both /rest/ and /api/ variants)
        "/rest/feedback": ["comment", "rating"],
        "/rest/feedbacks": ["comment", "rating"],
        "/rest/comments": ["comment", "message"],
        "/rest/reviews": ["review", "rating", "comment"],
        "/api/Feedback": ["comment", "rating"],
        "/api/Feedbacks": ["comment", "rating"],
        "/api/feedback": ["comment", "rating"],
        "/api/feedbacks": ["comment", "rating"],
        "/api/Comments": ["comment", "message"],
        "/api/comments": ["comment", "message"],
        # Basket/cart
        "/rest/basket": ["basketId", "productId", "quantity"],
        "/rest/basket/": ["quantity", "basketId", "productId"],
        "/api/Basket": ["quantity", "basketId", "productId"],
        "/api/Baskets": ["quantity", "basketId", "productId"],
        # Products
        "/rest/products/search": ["q", "query", "search"],
        "/rest/products/": ["quantity", "basketId"],
        "/api/Products": ["quantity", "basketId"],
        "/api/products": ["quantity", "basketId"],
        # Orders
        "/rest/orders": ["orderDetails", "paymentMethod", "addressId"],
        "/rest/orders/": ["orderDetails", "paymentMethod", "addressId"],
        # File operations
        "/rest/file/upload": ["file", "filename", "caption"],
        "/rest/save-code": ["code", "solution"],
        # Security
        "/rest/security-question": ["question"],
        "/rest/security-answer": ["answer", "question"],
    }

    for path in endpoint_paths:
        # Try exact match first
        if path in common_fields:
            results[path] = common_fields[path]
            continue

        # Try prefix match
        for pattern, fields in common_fields.items():
            if path.startswith(pattern.rstrip("/")):
                results[path] = fields
                break
            elif "/" in path:
                parts = path.split("/")
                if len(parts) >= 3:
                    # Check for /rest/resource/ID pattern
                    base = f"/{parts[1]}/{parts[2]}/"
                    if pattern.startswith(base.rstrip("/")):
                        results[path] = fields
                        break

    return results
