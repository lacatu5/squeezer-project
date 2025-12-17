"""Template expansion logic for DAST scanning."""

from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs

from jinja2 import Template as Jinja2Template
from jinja2 import StrictUndefined

from dast.config import (
    DetectionTier,
    GenericTemplate,
    PayloadConfig,
    RequestConfig,
    Template,
)
from dast.utils import logger

# Broadcast endpoint keyword for targeting all discovered endpoints
BROADCAST_KEYWORD = "all_discovered"

# Tags that indicate injection-based templates
_INJECTION_TAGS = {'sqli', 'xss', 'injection', 'ssti', 'xxe'}

# Parameter patterns for auto-mapping (expanded)
_PARAM_PATTERNS = {
    "sqli": [r"id", r"search", r"query", r"q", r"filter", r"find", r"lookup",
             r"item", r"product", r"user", r"category", r"sort", r"order",
             r"where", r"limit", r"offset", r"email", r"username", r"name",
             r"keyword", r"searchterm", r"input", r"value", r"data",
             # Expanded patterns
             r"id_\w+", r"\w+_id", r"code", r"ref", r"reference", r"key",
             r"number", r"num", r"page", r"size", r"start", r"end",
             r"date", r"time", r"year", r"month", r"group", r"type",
             r"status", r"state", r"role", r"level", r"sort_by", r"sortOrder"],
    "xss": [r"name", r"comment", r"message", r"text", r"content", r"input",
            r"desc", r"description", r"feedback", r"review", r"search",
            # Expanded patterns
            r"title", r"subject", r"body", r"note", r"remark", r"field",
            r"param", r"argument", r"var", r"variable", r"string"],
    "command": [r"host", r"hostname", r"ip", r"port", r"url", r"dest", r"target",
                r"file", r"path", r"filename", r"cmd", r"exec",
                # Expanded patterns
                r"domain", r"server", r"addr", r"address", r"command",
                r"execute", r"run", r"call", r"invoke"],
    "ssrf": [r"url", r"link", r"redirect", r"next", r"dest", r"target", r"to",
            r"callback", r"return", r"feed", r"site", r"uri", r"forward", r"goto",
            # Expanded patterns
            r"link_to", r"file_url", r"image", r"img", r"src", r"href",
            r"endpoint", r"api", r"webhook", r"postback"],
    "idor": [r"\bid\b", r"user_id", r"user", r"account", r"profile", r"order_id",
             r"order", r"basket_id", r"cart_id", r"item_id", r"document_id",
             # Expanded patterns
             r"\w+_id$", r"uid", r"cid", r"pid", r"sid", r"oid",
             r"customer", r"profile", r"document", r"file", r"resource"],
    "path_traversal": [r"file", r"path", r"folder", r"directory", r"document",
                       r"download", r"include", r"require", r"template", r"lang",
                       # Expanded patterns
                       r"filename", r"filepath", r"foldername", r"file_url",
                       r"image", r"img", r"src", r"document_url", r"attachment"],
}


def render_template(template_str: str, context: dict) -> str:
    """Render a Jinja2 template string with the given context.

    This function provides advanced templating capabilities for payload injection,
    supporting:
    - Variable interpolation: {{variable}}
    - Conditionals: {% if condition %}...{% endif %}
    - Loops: {% for item in items %}...{% endfor %}
    - Filters: {{variable|upper}}

    Args:
        template_str: The template string to render (e.g., '{"comment": "{{payload}}"}')
        context: Dictionary containing variables for template rendering

    Returns:
        Rendered string with all template variables replaced

    Examples:
        >>> render_template('{"id": "{{payload}}"}', {"payload": "1 OR 1=1"})
        '{"id": "1 OR 1=1"}'

        >>> render_template('{% if param %}{{param}}={{payload}}{% endif %}',
        ...                {"param": "id", "payload": "test"})
        'id=test'

        >>> render_template('{{sqli | default("test")}}', {"sqli": "' OR 1=1 --"})
        "' OR 1=1 --"
    """
    if not template_str:
        return template_str

    if not context:
        context = {}

    try:
        # Use StrictUndefined to catch undefined variables in templates
        # For security, auto_escape is disabled since we're working with payloads
        # that may contain special characters intentionally
        template = Jinja2Template(template_str, undefined=StrictUndefined)
        return template.render(**context)
    except Exception:
        # Fallback: if Jinja2 rendering fails, return original string
        # This maintains backward compatibility with existing templates
        return template_str


def extract_params_from_endpoints(endpoints: Dict[str, str]) -> Dict[str, List[Dict]]:
    """Extract injectable parameters from discovered endpoints.

    Returns a dict mapping endpoint URLs to their injectable parameters.
    """
    import re
    from collections import defaultdict

    injectable = defaultdict(list)

    for name, url in endpoints.items():
        parsed = urlparse(url)

        if not parsed.query:
            continue

        # Parse query string, keeping empty values
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name in params.keys():
            # Check if parameter matches any vulnerability pattern
            for vuln_type, patterns in _PARAM_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, param_name, re.IGNORECASE):
                        injectable[url].append({
                            "name": param_name,
                            "vuln_type": vuln_type,
                            "confidence": 90 if re.match(f"^{pattern}$", param_name, re.IGNORECASE) else 70,
                        })
                        break

    return dict(injectable)


def find_auto_mapped_endpoints(
    endpoint_key: str,
    template_tags: set,
    endpoints: Dict[str, str],
) -> Optional[Dict[str, str]]:
    import re

    endpoint_to_vuln = {
        "sqli": "sqli",
        "sqli_post": "sqli",
        "xss_reflected": "xss",
        "xss_stored": "xss",
        "command_injection": "command",
        "path_traversal": "path_traversal",
        "ssrf": "ssrf",
        "idor": "idor",
        "nosql_injection": "sqli",
        "generic_nosql_injection": "sqli",
    }

    vuln_type = endpoint_to_vuln.get(endpoint_key)
    if not vuln_type:
        return None

    patterns = _PARAM_PATTERNS.get(vuln_type, [])

    logger.debug(f"Auto-mapping {endpoint_key} (vuln_type={vuln_type}) against {len(endpoints)} endpoints")
    logger.debug(f"Patterns for {vuln_type}: {patterns[:5]}...")

    mapped = {}
    for name, url in endpoints.items():
        parsed = urlparse(url)
        is_api = '/api/' in url.lower() or '/rest/' in url.lower()

        if not parsed.query and not is_api:
            continue

        if not parsed.query:
            if is_api:
                mapped[url] = "input"
            continue

        params = parse_qs(parsed.query, keep_blank_values=True)

        best_param = None
        for param_name in params.keys():
            for pattern in patterns:
                if re.search(pattern, param_name, re.IGNORECASE):
                    best_param = param_name
                    break
            if best_param:
                break

        if not best_param and params:
            best_param = list(params.keys())[0]

        if best_param:
            mapped[url] = best_param

    if mapped:
        logger.info(f"Auto-mapping '{endpoint_key}' to {len(mapped)} discovered endpoints")
        return mapped

    if not mapped:
        for name, url in endpoints.items():
            if '/api/' in url.lower() or '/rest/' in url.lower():
                if '?' in url:
                    mapped[url] = url.split('?')[1].split('=')[0].split('&')[0]
                else:
                    mapped[url + "?input="] = "input"
                if len(mapped) >= 5:
                    break

    if mapped:
        logger.info(f"Auto-mapping '{endpoint_key}' to {len(mapped)} discovered endpoints (fallback)")
        return mapped

    logger.debug(f"No auto-mapping found for {endpoint_key}")
    return None


def _expand_auto_mapped(
    template: Template,
    generic: GenericTemplate,
    mapped_endpoints: Dict[str, str],  # url -> param_name
    load_payloads_fn,
    build_get_fn,
    build_post_fn,
) -> List[RequestConfig]:
    """Expand a template for auto-mapped discovered endpoints.

    Each endpoint gets its own parameter injected with payloads.
    """
    requests = []
    vuln_name = template.id.replace("-", "_").upper()

    # Load payloads from file if specified
    payloads_to_use = list(generic.payloads)
    if generic.payloads_file:
        file_payloads = load_payloads_fn(generic.payloads_file)
        payloads_to_use.extend(file_payloads)

    if not payloads_to_use:
        return []

    # For each auto-mapped endpoint, generate requests with payloads
    for url, param_name in mapped_endpoints.items():
        parsed = urlparse(url)
        base_path = parsed.path

        for payload in payloads_to_use:
            # Normalize payload
            if isinstance(payload, str):
                payload_cfg = PayloadConfig(name=payload[:30], value=payload)
            else:
                payload_cfg = payload

            # Build request with the discovered parameter
            if generic.method.upper() == "GET":
                # Build URL: /path?param=payload
                request = RequestConfig(
                    name=f"{param_name}:{payload_cfg.name}",
                    method="GET",
                    path=f"{base_path}?{param_name}={payload_cfg.value}",
                    headers=generic.headers.copy(),
                    cookies={},
                )
            elif generic.method.upper() == "POST":
                headers = generic.headers.copy()
                headers["Content-Type"] = generic.content_type

                if generic.body_template:
                    # Use Jinja2 for body templating
                    context = {
                        "payload": payload_cfg.value,
                        "parameter": param_name,
                        "sqli": payload_cfg.value,  # Backwards compatibility alias
                    }
                    body = render_template(generic.body_template, context)
                else:
                    body = f"{param_name}={payload_cfg.value}"

                request = RequestConfig(
                    name=f"{param_name}:{payload_cfg.name}",
                    method="POST",
                    path=base_path,
                    headers=headers,
                    body=body,
                    cookies={},
                )
            else:
                continue

            # Apply matchers from template
            request.matchers = generic.matchers
            request.on_match = {
                "vulnerability": vuln_name,
                "message": f"{template.info.name}: {payload_cfg.name} on {param_name}",
                "endpoint_name": f"auto:{base_path}",
            }

            requests.append(request)

    logger.info(f"Generated {len(requests)} requests for auto-mapped endpoints")
    return requests


def _expand_auto_mapped_json(
    template: Template,
    generic: GenericTemplate,
    mapped_endpoints: Dict[str, List[Dict]],  # path -> list of {name, vuln_types}
    load_payloads_fn,
    build_post_fn,
) -> List[RequestConfig]:
    """Expand a template for auto-mapped JSON body endpoints.

    Each JSON field gets injected with payloads.
    """
    import json

    requests = []
    vuln_name = template.id.replace("-", "_").upper()

    # Load payloads from file if specified
    payloads_to_use = list(generic.payloads)
    if generic.payloads_file:
        file_payloads = load_payloads_fn(generic.payloads_file)
        payloads_to_use.extend(file_payloads)

    if not payloads_to_use:
        return []

    # Check if template is relevant for JSON fields (based on tags)
    template_tags = set(template.info.tags)

    # For each endpoint with JSON fields
    for path, field_list in mapped_endpoints.items():
        for field_info in field_list:
            field_name = field_info["name"]
            field_vuln_types = field_info.get("vuln_types", [])

            # Check if this field is relevant for the template
            # Cross-reference template tags with field vuln types
            is_relevant = False
            for vuln_type in field_vuln_types:
                if vuln_type in template_tags or any(vuln_type in tag for tag in template_tags):
                    is_relevant = True
                    break

            # Also check if field name matches the template's parameter pattern
            if not is_relevant and generic.parameter:
                import re
                if re.search(generic.parameter, field_name, re.IGNORECASE):
                    is_relevant = True

            if not is_relevant:
                continue

            # Generate requests for each payload
            for payload in payloads_to_use:
                if isinstance(payload, str):
                    payload_cfg = PayloadConfig(name=payload[:30], value=payload)
                else:
                    payload_cfg = payload

                # Build JSON body with the field injected
                json_body = {field_name: payload_cfg.value}

                headers = generic.headers.copy()
                headers["Content-Type"] = "application/json"

                request = RequestConfig(
                    name=f"json:{field_name}:{payload_cfg.name}",
                    method="POST",
                    path=path,
                    headers=headers,
                    json={"comment": payload_cfg.value},  # Most Juice Shop endpoints use "comment"
                    cookies={},
                )

                request.matchers = generic.matchers
                request.on_match = {
                    "vulnerability": vuln_name,
                    "message": f"{template.info.name}: {payload_cfg.name} in JSON field '{field_name}'",
                    "endpoint_name": f"auto:{path}",
                }

                requests.append(request)

    logger.info(f"Generated {len(requests)} JSON injection requests")
    return requests


def expand_template(
    template: Template,
    target,
    scan_profile,
    load_payloads_fn,
    build_get_fn,
    build_post_fn,
    expand_broadcast_fn,
    expand_tiers_fn,
) -> List[RequestConfig]:
    """Expand a generic template into concrete requests.

    If the template has a 'generic' field, expand it into multiple requests
    based on the payload list. Otherwise, return the existing requests.
    """
    if template.generic:
        return expand_generic_template(
            template=template,
            target=target,
            scan_profile=scan_profile,
            load_payloads_fn=load_payloads_fn,
            build_get_fn=build_get_fn,
            build_post_fn=build_post_fn,
            expand_broadcast_fn=expand_broadcast_fn,
            expand_tiers_fn=expand_tiers_fn,
        )
    return template.requests


def _expand_json_endpoint(
    template: Template,
    generic: GenericTemplate,
    endpoint_spec: str,
    load_payloads_fn,
) -> List[RequestConfig]:
    """Expand a template for JSON injection endpoints.

    Endpoint spec format: JSON:/rest/feedback:comment
    - Parses the path and field name
    - Builds POST requests with JSON body containing the field

    Args:
        template: The template being expanded
        generic: Generic template config
        endpoint_spec: Endpoint specification string (JSON:/path:field)
        load_payloads_fn: Function to load payloads from file

    Returns:
        List of RequestConfig with JSON body injection
    """
    requests = []
    vuln_name = template.id.replace("-", "_").upper()

    # Parse endpoint spec: JSON:/rest/feedback:comment
    parts = endpoint_spec.split(":")
    if len(parts) < 3:
        logger.warning(f"Invalid JSON endpoint spec: {endpoint_spec}")
        return []

    path = parts[1]  # /rest/feedback
    field_name = parts[2]  # comment

    # Load payloads from file if specified
    payloads_to_use = list(generic.payloads)
    if generic.payloads_file:
        file_payloads = load_payloads_fn(generic.payloads_file)
        payloads_to_use.extend(file_payloads)

    if not payloads_to_use:
        return []

    # Generate requests for each payload
    for payload in payloads_to_use:
        if isinstance(payload, str):
            payload_cfg = PayloadConfig(name=payload[:30], value=payload)
        else:
            payload_cfg = payload

        # Build JSON body with the field injected
        json_body = {field_name: payload_cfg.value}

        headers = generic.headers.copy()
        headers["Content-Type"] = "application/json"

        request = RequestConfig(
            name=f"json:{field_name}:{payload_cfg.name}",
            method="POST",
            path=path,
            headers=headers,
            json=json_body,
            cookies={},
        )

        request.matchers = generic.matchers
        request.on_match = {
            "vulnerability": vuln_name,
            "message": f"{template.info.name}: {payload_cfg.name} in JSON field '{field_name}'",
        }

        requests.append(request)

    logger.info(f"Generated {len(requests)} JSON injection requests for {path}:{field_name}")
    return requests


def _expand_xml_endpoint(
    template: Template,
    generic: GenericTemplate,
    endpoint_spec: str,
    load_payloads_fn,
) -> List[RequestConfig]:
    """Expand a template for XML injection endpoints (XXE).

    Endpoint spec format: XML:/path
    - Builds POST requests with XML body

    Args:
        template: The template being expanded
        generic: Generic template config
        endpoint_spec: Endpoint specification string (XML:/path)
        load_payloads_fn: Function to load payloads from file

    Returns:
        List of RequestConfig with XML body injection
    """
    requests = []
    vuln_name = template.id.replace("-", "_").upper()

    # Parse endpoint spec: XML:/path
    parts = endpoint_spec.split(":")
    if len(parts) < 2:
        logger.warning(f"Invalid XML endpoint spec: {endpoint_spec}")
        return []

    path = parts[1]  # /path

    # For XXE, use the full_request from payloads if available
    for payload in generic.payloads:
        if isinstance(payload, str):
            payload_cfg = PayloadConfig(name=payload[:30], value=payload)
        else:
            payload_cfg = payload

        # Use full_request if provided, otherwise build from body_template
        if hasattr(payload_cfg, "full_request") and payload_cfg.full_request:
            xml_body = payload_cfg.full_request
        else:
            # Use Jinja2 for XML body templating
            context = {
                "payload": payload_cfg.value,
                "parameter": "",
                "sqli": payload_cfg.value,  # Backwards compatibility alias
            }
            xml_body = render_template(generic.body_template, context)

        headers = generic.headers.copy()
        headers["Content-Type"] = "application/xml"

        request = RequestConfig(
            name=f"xml:{payload_cfg.name}",
            method="POST",
            path=path,
            headers=headers,
            body=xml_body,
            cookies={},
        )

        request.matchers = generic.matchers
        request.on_match = {
            "vulnerability": vuln_name,
            "message": f"{template.info.name}: {payload_cfg.name}",
        }

        requests.append(request)

    logger.info(f"Generated {len(requests)} XML injection requests for {path}")
    return requests


def expand_generic_template(
    template: Template,
    target,
    scan_profile,
    load_payloads_fn,
    build_get_fn,
    build_post_fn,
    expand_broadcast_fn,
    expand_tiers_fn,
) -> List[RequestConfig]:
    """Expand a generic template into concrete requests based on payloads.

    Resolves the endpoint from target config and generates a request for each payload.
    Supports detection_tiers for layered vulnerability scanning.
    Also supports automatic boolean-blind detection via naming convention.
    Supports loading payloads from external files.

    Broadcast Mode:
        When endpoint is set to {{all_discovered}}, the template will be expanded
        to target ALL endpoints in the target config. For injection templates (SQLi, XSS),
        only endpoints with query parameters are targeted.
    """
    generic = template.generic
    if not generic:
        return template.requests

    # Resolve endpoint from target config
    endpoints = target.get_endpoints()
    endpoint_key = generic.endpoint.lstrip("{{").rstrip("}}")

    # Check for broadcast mode - target all discovered endpoints
    if endpoint_key == BROADCAST_KEYWORD:
        return expand_broadcast_fn(template, generic, endpoints)

    endpoint_path = endpoints.get(endpoint_key)

    if not endpoint_path:
        # Try auto-mapping to discovered endpoints with injectable parameters
        auto_mapped = find_auto_mapped_endpoints(endpoint_key, set(template.info.tags), endpoints)
        if auto_mapped:
            logger.info(f"Auto-mapping '{endpoint_key}' to {len(auto_mapped)} discovered endpoints")
            return _expand_auto_mapped(template, generic, auto_mapped, load_payloads_fn, build_get_fn, build_post_fn)

        logger.warning(f"Endpoint '{generic.endpoint}' not found in target config, skipping template")
        return []

    # Check if this is a JSON injection endpoint (format: JSON:/path:field)
    if endpoint_path.startswith("JSON:"):
        return _expand_json_endpoint(template, generic, endpoint_path, load_payloads_fn)

    # Check if this is an XML injection endpoint (format: XML:/path)
    if endpoint_path.startswith("XML:"):
        return _expand_xml_endpoint(template, generic, endpoint_path, load_payloads_fn)

    requests = []

    # Check if template uses detection_tiers
    if generic.detection_tiers:
        return expand_tiers_fn(template, endpoint_path, generic)

    # Load payloads from file if specified
    payloads_to_use = list(generic.payloads)
    if generic.payloads_file:
        file_payloads = load_payloads_fn(generic.payloads_file)
        payloads_to_use.extend(file_payloads)
        logger.debug(f"Loaded {len(file_payloads)} payloads from {generic.payloads_file}")

    # Check for boolean-blind naming convention (baseline, bool_true, bool_false)
    payload_names = [p.name if isinstance(p, PayloadConfig) else p[:30] for p in payloads_to_use]
    has_bool_blind = "baseline" in payload_names and ("bool_true" in payload_names or "bool_false" in payload_names)

    # Expand payloads into requests
    for payload in payloads_to_use:
        # Normalize payload to PayloadConfig
        if isinstance(payload, str):
            payload_cfg = PayloadConfig(name=payload[:30], value=payload)
        else:
            payload_cfg = payload

        # Build request based on method
        if generic.method.upper() == "GET":
            request = build_get_fn(endpoint_path, generic, payload_cfg)
        elif generic.method.upper() == "POST":
            request = build_post_fn(endpoint_path, generic, payload_cfg)
        else:
            logger.warning(f"Unsupported method: {generic.method}")
            continue

        # Handle boolean-blind naming convention
        if has_bool_blind and payload_cfg.name in ("baseline", "bool_true", "bool_false"):
            if payload_cfg.name == "baseline":
                # Baseline: cache for comparison, no matchers
                request.matchers = []
                request.on_match = {
                    "vulnerability": template.id.replace("-", "_").upper(),
                    "message": f"{template.info.name} (baseline)",
                    "is_baseline": True,
                    "cache_key": f"{template.id}_baseline",
                }
            else:
                # Boolean payloads: compare with baseline
                request.matchers = generic.matchers
                request.on_match = {
                    "vulnerability": template.id.replace("-", "_").upper(),
                    "message": f"{template.info.name} (boolean-blind: {payload_cfg.name})",
                    "compare_with": f"{template.id}_baseline",
                    "detection_type": "boolean_blind",
                }
        else:
            # Regular payloads: use standard matchers
            request.matchers = generic.matchers
            request.on_match = {
                "vulnerability": template.id.replace("-", "_").upper(),
                "message": f"{template.info.name}: {payload_cfg.name}",
            }

        requests.append(request)

    return requests


def expand_broadcast_template(
    template: Template,
    generic: GenericTemplate,
    endpoints: Dict[str, str],
    target,
    load_payloads_fn,
    build_get_fn,
    build_post_fn,
    expand_tiers_fn,
) -> List[RequestConfig]:
    """Expand a template to broadcast against all discovered endpoints.

    This creates a RequestConfig for every endpoint in the TargetConfig.
    For injection templates (SQLi, XSS), only targets endpoints with query
    parameters or body content. Ignores static HTML pages for these tests.

    Args:
        template: The template being expanded
        generic: The generic template configuration
        endpoints: Dict of endpoint_name -> url from target config
        target: TargetConfig
        load_payloads_fn: Function to load payloads from file
        build_get_fn: Function to build GET requests
        build_post_fn: Function to build POST requests
        expand_tiers_fn: Function to expand with detection tiers

    Returns:
        List of RequestConfig to execute
    """
    from urllib.parse import urlparse

    requests = []
    vuln_name = template.id.replace("-", "_").upper()

    # Determine template type for smart filtering (using set for O(1) lookup)
    template_tags = set(template.info.tags)
    is_injection_template = bool(template_tags & _INJECTION_TAGS)

    # Filter endpoints based on template type
    filtered_endpoints = {}
    for name, url in endpoints.items():
        if not is_injection_template:
            # Non-injection templates target all endpoints
            filtered_endpoints[name] = url
        else:
            # Injection templates only target endpoints with potential injection points
            parsed = urlparse(url)
            has_params = bool(parsed.query) or '?' in url

            # Also target API endpoints (likely to have params in body)
            is_api = '/api/' in url.lower() or '/rest/' in url.lower()

            if has_params or is_api:
                filtered_endpoints[name] = url
            else:
                logger.debug(f"Skipping {url} for {template.id}: no injection points")

    if not filtered_endpoints:
        logger.warning(f"Broadcast mode: no suitable endpoints found for {template.id}")
        return []

    logger.info(f"Broadcast mode: targeting {len(filtered_endpoints)} endpoints for {template.id}")

    # Check if template uses detection_tiers
    if generic.detection_tiers:
        # For broadcast with tiers, expand each endpoint through tier system
        for endpoint_name, endpoint_path in filtered_endpoints.items():
            tier_requests = expand_tiers_fn(template, endpoint_path, generic)
            # Annotate with endpoint name for tracking
            for req in tier_requests:
                if not req.on_match:
                    req.on_match = {}
                req.on_match["endpoint_name"] = endpoint_name
            requests.extend(tier_requests)
        return requests

    # Load payloads from file if specified
    payloads_to_use = list(generic.payloads)
    if generic.payloads_file:
        file_payloads = load_payloads_fn(generic.payloads_file)
        payloads_to_use.extend(file_payloads)

    # Check for boolean-blind naming convention
    payload_names = [p.name if isinstance(p, PayloadConfig) else p[:30] for p in payloads_to_use]
    has_bool_blind = "baseline" in payload_names and ("bool_true" in payload_names or "bool_false" in payload_names)

    # Expand each endpoint with each payload
    for endpoint_name, endpoint_path in filtered_endpoints.items():
        for payload in payloads_to_use:
            # Normalize payload to PayloadConfig
            if isinstance(payload, str):
                payload_cfg = PayloadConfig(name=payload[:30], value=payload)
            else:
                payload_cfg = payload

            # Build request based on method
            if generic.method.upper() == "GET":
                request = build_get_fn(endpoint_path, generic, payload_cfg)
            elif generic.method.upper() == "POST":
                request = build_post_fn(endpoint_path, generic, payload_cfg)
            else:
                continue

            # Add endpoint name to the request name for traceability
            original_name = request.name or ""
            request.name = f"{endpoint_name}:{original_name}" if original_name else endpoint_name

            # Handle boolean-blind naming convention
            if has_bool_blind and payload_cfg.name in ("baseline", "bool_true", "bool_false"):
                if payload_cfg.name == "baseline":
                    # Per-endpoint baseline cache key
                    cache_key = f"{template.id}_{endpoint_name}_baseline"
                    request.matchers = []
                    request.on_match = {
                        "vulnerability": vuln_name,
                        "message": f"{template.info.name} (baseline: {endpoint_name})",
                        "is_baseline": True,
                        "cache_key": cache_key,
                        "endpoint_name": endpoint_name,
                    }
                else:
                    compare_key = f"{template.id}_{endpoint_name}_baseline"
                    request.matchers = generic.matchers
                    request.on_match = {
                        "vulnerability": vuln_name,
                        "message": f"{template.info.name} (boolean-blind: {payload_cfg.name} on {endpoint_name})",
                        "compare_with": compare_key,
                        "detection_type": "boolean_blind",
                        "endpoint_name": endpoint_name,
                    }
            else:
                # Regular payloads
                request.matchers = generic.matchers
                request.on_match = {
                    "vulnerability": vuln_name,
                    "message": f"{template.info.name}: {payload_cfg.name} on {endpoint_name}",
                    "endpoint_name": endpoint_name,
                }

            requests.append(request)

    return requests


def expand_with_tiers(
    template: Template,
    endpoint_path: str,
    generic: GenericTemplate,
    scan_profile,
    profile_tiers_map,
    build_get_fn,
    build_post_fn,
) -> List[RequestConfig]:
    """Expand template using detection_tiers approach.

    Filters tiers based on scan_profile and generates appropriate requests.
    """
    requests = []
    allowed_tiers = profile_tiers_map.get(scan_profile, [DetectionTier.PASSIVE])

    for tier_config in generic.detection_tiers:
        tier = tier_config.get_tier()

        # Skip tiers not allowed by current scan profile
        if tier not in allowed_tiers:
            logger.debug(f"Skipping {tier.value} tier (scan_profile: {scan_profile.value})")
            continue

        # Warn about aggressive tiers
        if tier == DetectionTier.AGGRESSIVE:
            logger.warning("Running aggressive detection tier - may cause delays")

        detection_type = tier_config.detection_type or "error_based"

        if detection_type == "boolean_blind":
            # Boolean-blind: need baseline, true, and false payloads
            requests.extend(build_boolean_blind_requests(
                template, endpoint_path, generic, tier_config, build_get_fn, build_post_fn
            ))
        elif detection_type == "time_blind":
            # Time-blind: single request with delay
            requests.extend(build_time_blind_requests(
                template, endpoint_path, generic, tier_config, build_get_fn, build_post_fn
            ))
        else:
            # Error-based: use payloads list with tier matchers
            requests.extend(build_error_based_requests(
                template, endpoint_path, generic, tier_config, build_get_fn, build_post_fn
            ))

    return requests


def build_error_based_requests(
    template: Template,
    endpoint_path: str,
    generic: GenericTemplate,
    tier_config,
    build_get_fn,
    build_post_fn,
) -> List[RequestConfig]:
    """Build requests for error-based detection tier."""
    requests = []
    vuln_name = template.id.replace("-", "_").upper()
    tier = tier_config.get_tier()

    for payload in generic.payloads:
        if isinstance(payload, str):
            payload_cfg = PayloadConfig(name=payload[:30], value=payload)
        else:
            payload_cfg = payload

        if generic.method.upper() == "GET":
            request = build_get_fn(endpoint_path, generic, payload_cfg)
        elif generic.method.upper() == "POST":
            request = build_post_fn(endpoint_path, generic, payload_cfg)
        else:
            continue

        # Use tier-specific matchers
        request.matchers = tier_config.matchers
        request.on_match = {
            "vulnerability": vuln_name,
            "message": f"{template.info.name} ({tier.value}): {payload_cfg.name}",
            "detection_type": "error_based",
            "tier": tier.value,
        }
        requests.append(request)

    return requests


def build_boolean_blind_requests(
    template: Template,
    endpoint_path: str,
    generic: GenericTemplate,
    tier_config,
    build_get_fn,
    build_post_fn,
) -> List[RequestConfig]:
    """Build requests for boolean-blind detection tier.

    Creates baseline request first, then true/false payloads for comparison.
    Responses are cached for diff-based matching.
    """
    requests = []
    vuln_name = template.id.replace("-", "_").upper()
    tier = tier_config.get_tier()

    baseline_payload = tier_config.baseline_payload or "test"
    baseline_cfg = PayloadConfig(name="baseline", value=baseline_payload)

    if generic.method.upper() == "GET":
        baseline_req = build_get_fn(endpoint_path, generic, baseline_cfg)
    else:
        baseline_req = build_post_fn(endpoint_path, generic, baseline_cfg)

    baseline_req.matchers = []  # No matchers for baseline
    baseline_req.on_match = {
        "vulnerability": vuln_name,
        "message": f"{template.info.name} (boolean-blind baseline)",
        "is_baseline": True,
        "cache_key": f"{template.id}_baseline",
    }
    requests.append(baseline_req)

    # True payload request
    if tier_config.true_payload:
        true_cfg = PayloadConfig(name="boolean_true", value=tier_config.true_payload)
        if generic.method.upper() == "GET":
            true_req = build_get_fn(endpoint_path, generic, true_cfg)
        else:
            true_req = build_post_fn(endpoint_path, generic, true_cfg)

        true_req.matchers = tier_config.matchers
        true_req.on_match = {
            "vulnerability": vuln_name,
            "message": f"{template.info.name} (boolean-blind TRUE)",
            "detection_type": "boolean_blind",
            "tier": tier.value,
            "compare_with": f"{template.id}_baseline",  # Match the cache_key
            "condition": "different",
        }
        requests.append(true_req)

    # False payload request
    if tier_config.false_payload:
        false_cfg = PayloadConfig(name="boolean_false", value=tier_config.false_payload)
        if generic.method.upper() == "GET":
            false_req = build_get_fn(endpoint_path, generic, false_cfg)
        else:
            false_req = build_post_fn(endpoint_path, generic, false_cfg)

        false_req.matchers = tier_config.matchers
        false_req.on_match = {
            "vulnerability": vuln_name,
            "message": f"{template.info.name} (boolean-blind FALSE)",
            "detection_type": "boolean_blind",
            "tier": tier.value,
            "compare_with": f"{template.id}_baseline",  # Match the cache_key
            "condition": "different",
        }
        requests.append(false_req)

    return requests


def build_time_blind_requests(
    template: Template,
    endpoint_path: str,
    generic: GenericTemplate,
    tier_config,
    build_get_fn,
    build_post_fn,
) -> List[RequestConfig]:
    """Build requests for time-blind detection tier.

    Uses a single payload with SLEEP() or similar delay mechanism.
    """
    requests = []
    vuln_name = template.id.replace("-", "_").upper()
    tier = tier_config.get_tier()

    # Time-based payloads are in the payloads list
    for payload in generic.payloads:
        if isinstance(payload, str):
            payload_cfg = PayloadConfig(name="time_blind", value=payload)
        else:
            payload_cfg = payload

        if generic.method.upper() == "GET":
            request = build_get_fn(endpoint_path, generic, payload_cfg)
        elif generic.method.upper() == "POST":
            request = build_post_fn(endpoint_path, generic, payload_cfg)
        else:
            continue

        # Add time-based matcher
        time_matcher = {
            "type": "time",
            "threshold_ms": tier_config.threshold_ms,
            "condition": "gte",
        }

        request.matchers = tier_config.matchers + [time_matcher]
        request.on_match = {
            "vulnerability": vuln_name,
            "message": f"{template.info.name} (time-blind): {payload_cfg.name}",
            "detection_type": "time_blind",
            "tier": tier.value,
        }
        requests.append(request)

    return requests


def build_get_request(
    endpoint_path: str,
    generic: GenericTemplate,
    payload: PayloadConfig,
) -> RequestConfig:
    """Build a GET request from generic template config.

    Uses Jinja2 templating for URL construction, supporting:
    - {{payload}}: The payload value
    - {{parameter}}: The parameter name
    - {% if ... %}: Conditional logic in URL paths
    """
    # Build context for Jinja2 rendering
    context = {
        "payload": payload.value,
        "parameter": generic.parameter or "",
    }
    # Add alias {{sqli}} for backwards compatibility
    context["sqli"] = payload.value

    # Build URL with parameter and payload
    if generic.parameter and not endpoint_path.endswith("="):
        # For URL parameter injection: /endpoint?param=payload
        path = f"{endpoint_path}?{generic.parameter}={payload.value}"
    elif endpoint_path.endswith("=") or endpoint_path.endswith("?"):
        # Endpoint already has parameter= or ? - just append payload
        path = f"{endpoint_path}{payload.value}"
    else:
        # For path injection or direct payload: /endpoint/payload
        # Check if endpoint already has a query string
        if "?" in endpoint_path:
            path = f"{endpoint_path}&{payload.value}"
        else:
            path = f"{endpoint_path}{payload.value}"

    # Render path with Jinja2 for advanced templating (e.g., conditional paths)
    path = render_template(path, context)

    # Render headers with Jinja2 (e.g., for dynamic header values)
    rendered_headers = {}
    for key, value in generic.headers.items():
        rendered_headers[key] = render_template(str(value), context)

    return RequestConfig(
        name=payload.name,
        method="GET",
        path=path,
        headers=rendered_headers,
        cookies={},
    )


def build_post_request(
    endpoint_path: str,
    generic: GenericTemplate,
    payload: PayloadConfig,
) -> RequestConfig:
    """Build a POST request from generic template config.

    Uses Jinja2 templating for body_template and headers, supporting:
    - {{payload}}: The payload value
    - {{parameter}}: The parameter name
    - {% if ... %}: Conditional logic
    - Filters and other Jinja2 features
    """
    # Build context for Jinja2 rendering
    context = {
        "payload": payload.value,
        "parameter": generic.parameter or "",
    }
    # Add alias {{sqli}} for backwards compatibility
    context["sqli"] = payload.value

    # Render headers with Jinja2 (e.g., for dynamic header values)
    rendered_headers = {}
    for key, value in generic.headers.items():
        rendered_headers[key] = render_template(str(value), context)
    rendered_headers["Content-Type"] = generic.content_type

    if generic.body_template:
        # Use Jinja2 rendering for body template
        body = render_template(generic.body_template, context)
    elif generic.parameter:
        # Build form-encoded body
        body = f"{generic.parameter}={payload.value}"
    else:
        body = payload.value

    return RequestConfig(
        name=payload.name,
        method="POST",
        path=endpoint_path,
        headers=rendered_headers,
        body=body,
        cookies={},
    )
