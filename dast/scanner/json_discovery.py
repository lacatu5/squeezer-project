"""JSON body parameter discovery for API endpoints."""

import asyncio
import json
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx

from dast.utils import logger


def load_field_patterns(config_path: Optional[str] = None) -> Dict[str, Dict]:
    """Load field classification patterns from config or return defaults."""
    if config_path:
        try:
            import yaml
            with open(config_path) as f:
                return yaml.safe_load(f).get("field_patterns", {})
        except Exception:
            pass

    return {
        "sqli": {
            "patterns": [r"id", r"search", r"query", r"q", r"filter", r"find",
                        r"lookup", r"item", r"product", r"user", r"category",
                        r"sort", r"order", r"email", r"username", r"name",
                        r"keyword", r"value"],
        },
        "xss": {
            "patterns": [r"name", r"comment", r"message", r"text", r"content",
                        r"input", r"desc", r"description", r"feedback", r"review",
                        r"bio", r"note"],
        },
        "command": {
            "patterns": [r"host", r"hostname", r"ip", r"port", r"url", r"dest",
                        r"target", r"file", r"path", r"filename", r"cmd", r"exec",
                        r"command"],
        },
        "path_traversal": {
            "patterns": [r"file", r"path", r"folder", r"directory", r"document",
                        r"image", r"download", r"include", r"template", r"lang",
                        r"filename"],
        },
        "ssrf": {
            "patterns": [r"url", r"link", r"redirect", r"next", r"dest", r"target",
                        r"to", r"callback", r"return", r"feed", r"site", r"uri",
                        r"forward", r"link"],
        },
    }


def load_discovery_payloads(config_path: Optional[str] = None) -> Dict:
    """Load discovery payloads from config or return defaults."""
    if config_path:
        try:
            import yaml
            with open(config_path) as f:
                return yaml.safe_load(f).get("discovery_payloads", {})
        except Exception:
            pass

    return {
        "rest_api": {
            "id": "1",
            "name": "test",
            "email": "test@example.com",
            "username": "testuser",
            "password": "Test123!",
            "comment": "test comment",
            "message": "test message",
            "content": "test content",
            "query": "test",
            "search": "test",
            "q": "test",
            "filter": "test",
            "url": "http://example.com",
            "file": "/etc/passwd",
            "path": "/tmp/test",
            "filename": "test.txt",
            "ip": "127.0.0.1",
            "host": "localhost",
            "port": "8080",
            "quantity": 1,
            "price": 9.99,
        },
        "graphql": {
            "query": "query { __typename }",
        },
    }


JSON_FIELD_PATTERNS = load_field_patterns()
DISCOVERY_PAYLOADS = load_discovery_payloads()


async def probe_endpoint_for_json_fields(
    url: str,
    method: str,
    client: httpx.AsyncClient,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 10.0,
) -> Set[str]:
    """Probe an endpoint to discover JSON field names from error responses."""
    fields = set()

    if method.upper() not in ("POST", "PUT", "PATCH"):
        return fields

    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)

    payload = DISCOVERY_PAYLOADS.get("rest_api", {})

    try:
        response = await client.post(url, json=payload, headers=req_headers, timeout=timeout)
        resp_json = _try_parse_json(response.text)

        if resp_json:
            fields.update(_extract_fields_from_json(resp_json))
        else:
            fields.update(re.findall(r"['\"]([\w_]+)['\"]", response.text))

    except Exception as e:
        logger.debug(f"Probe failed for {url}: {e}")

    return fields


def _try_parse_json(text: str) -> Optional[Dict]:
    """Safely attempt to parse JSON."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _extract_fields_from_json(resp_json: Dict) -> Set[str]:
    """Extract field names from various JSON error response formats."""
    fields = set()

    if "errors" in resp_json and isinstance(resp_json["errors"], list):
        for error in resp_json["errors"]:
            if isinstance(error, dict):
                for key in ["param", "field", "property", "name"]:
                    if key in error and isinstance(error[key], str):
                        fields.add(error[key])

    if "message" in resp_json:
        msg = str(resp_json["message"]).lower()
        fields.update(re.findall(r"['\"]([\w_]+)['\"]", msg))

    if "validation" in resp_json and isinstance(resp_json["validation"], dict):
        fields.update(resp_json["validation"].keys())

    if "fields" in resp_json:
        if isinstance(resp_json["fields"], list):
            fields.update(resp_json["fields"])
        elif isinstance(resp_json["fields"], dict):
            fields.update(resp_json["fields"].keys())

    if isinstance(resp_json.get("errors"), dict):
        fields.update(resp_json["errors"].keys())

    return fields


async def discover_json_fields_from_responses(
    url: str,
    client: httpx.AsyncClient,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 10.0,
    sample_size: int = 3,
) -> Set[str]:
    """Discover JSON fields by analyzing GET response structure."""
    fields = set()

    try:
        response = await client.get(url, headers=headers or {}, timeout=timeout)

        if not response.headers.get("content-type", "").startswith("application/json"):
            return fields

        resp_json = response.json()

        def extract_keys(obj, _prefix=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    fields.add(key)
                    if isinstance(value, (dict, list)):
                        extract_keys(value, f"{_prefix}.{key}" if _prefix else key)
            elif isinstance(obj, list) and obj:
                for item in obj[:sample_size]:
                    extract_keys(item, _prefix)

        extract_keys(resp_json)

    except Exception as e:
        logger.debug(f"Response analysis failed for {url}: {e}")

    return fields


def classify_json_field(field_name: str, patterns: Optional[Dict] = None) -> Dict[str, int]:
    """Classify a JSON field name by vulnerability type."""
    patterns = patterns or JSON_FIELD_PATTERNS
    field_lower = field_name.lower()
    scores = {}

    for vuln_type, config in patterns.items():
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
    timeout: float = 10.0,
    api_path_hint: str = "/api/",
) -> Dict[str, List[Dict]]:
    """Discover JSON body parameters from API endpoints."""
    import random

    results = {}

    if not client:
        should_close = True
        client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
    else:
        should_close = False

    try:
        mutation_endpoints = [
            ep for ep in endpoints
            if ep.get("method", "GET").upper() in ("POST", "PUT", "PATCH")
        ]

        schema_endpoints = [
            ep for ep in endpoints
            if ep.get("method", "GET") == "GET" and api_path_hint in ep.get("url", "")
        ]

        if len(mutation_endpoints) > max_probes:
            mutation_endpoints = random.sample(mutation_endpoints, max_probes)

        if len(schema_endpoints) > max_probes:
            schema_endpoints = random.sample(schema_endpoints, max_probes)

        probe_tasks = [
            probe_endpoint_for_json_fields(
                ep.get("full_url", ep.get("url", "")),
                ep.get("method", "POST"),
                client,
                headers,
                timeout,
            )
            for ep in mutation_endpoints if ep.get("full_url", ep.get("url", ""))
        ]

        schema_tasks = [
            discover_json_fields_from_responses(
                ep.get("full_url", ep.get("url", "")),
                client,
                headers,
                timeout,
            )
            for ep in schema_endpoints if ep.get("full_url", ep.get("url", ""))
        ]

        all_fields = await asyncio.gather(*(probe_tasks + schema_tasks), return_exceptions=True)

        for i, ep in enumerate(mutation_endpoints):
            path = urlparse(ep.get("full_url", ep.get("url", ""))).path
            if not path:
                continue

            if path not in results:
                results[path] = []

            field_result = all_fields[i]
            if isinstance(field_result, Exception) or not isinstance(field_result, set):
                continue

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

        for i, ep in enumerate(schema_endpoints):
            path = urlparse(ep.get("full_url", ep.get("url", ""))).path
            if not path:
                continue

            field_result = all_fields[len(mutation_endpoints) + i]
            if isinstance(field_result, Exception) or not isinstance(field_result, set):
                continue

            for field_name in field_result:
                classifications = classify_json_field(field_name)
                if path not in results:
                    results[path] = []
                if classifications:
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

    total_fields = sum(len(params) for params in results.values())
    logger.info(f"Discovered {total_fields} JSON fields across {len(results)} endpoints")

    return results
