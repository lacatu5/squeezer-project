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

BROADCAST_KEYWORD = "all_discovered"
_INJECTION_TAGS = {'sqli', 'xss', 'injection', 'ssti', 'xxe'}

_PARAM_PATTERNS = {
    "sqli": [r"id", r"search", r"query", r"q", r"filter", r"find", r"lookup",
             r"item", r"product", r"user", r"category", r"sort", r"order",
             r"where", r"limit", r"offset", r"email", r"username", r"name",
             r"keyword", r"searchterm", r"input", r"value", r"data",
             r"id_\w+", r"\w+_id", r"code", r"ref", r"reference", r"key",
             r"number", r"num", r"page", r"size", r"start", r"end",
             r"date", r"time", r"year", r"month", r"group", r"type",
             r"status", r"state", r"role", r"level", r"sort_by", r"sortOrder"],
    "xss": [r"name", r"comment", r"message", r"text", r"content", r"input",
            r"desc", r"description", r"feedback", r"review", r"search",
            r"title", r"subject", r"body", r"note", r"remark", r"field",
            r"param", r"argument", r"var", r"variable", r"string"],
    "command": [r"host", r"hostname", r"ip", r"port", r"url", r"dest", r"target",
                r"file", r"path", r"filename", r"cmd", r"exec",
                r"domain", r"server", r"addr", r"address", r"command",
                r"execute", r"run", r"call", r"invoke"],
    "ssrf": [r"url", r"link", r"redirect", r"next", r"dest", r"target", r"to",
            r"callback", r"return", r"feed", r"site", r"uri", r"forward", r"goto",
            r"link_to", r"file_url", r"image", r"img", r"src", r"href",
            r"endpoint", r"api", r"webhook", r"postback"],
    "idor": [r"\bid\b", r"user_id", r"user", r"account", r"profile", r"order_id",
             r"order", r"basket_id", r"cart_id", r"item_id", r"document_id",
             r"\w+_id$", r"uid", r"cid", r"pid", r"sid", r"oid",
             r"customer", r"document", r"file", r"resource"],
    "path_traversal": [r"file", r"path", r"folder", r"directory", r"document",
                       r"download", r"include", r"require", r"template", r"lang",
                       r"filename", r"filepath", r"foldername", r"file_url",
                       r"image", r"img", r"src", r"document_url", r"attachment"],
    "ssti": [r"name", r"title", r"template", r"view", r"render", r"display",
             r"content", r"body", r"text", r"message", r"description",
             r"subject", r"header", r"footer", r"format", r"output",
             r"page", r"layout", r"skin", r"theme", r"style"],
    "xxe": [r"xml", r"data", r"config", r"file", r"document", r"content",
            r"upload", r"import", r"export", r"payload", r"request"],
}


def render_template(template_str: str, context: dict) -> str:
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
        "ssti": "ssti",
        "xxe": "xxe",
        "cors": "ssrf",
        "redirect": "ssrf",
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
    mapped_endpoints: Dict[str, str],
    load_payloads_fn,
    build_get_fn,
    build_post_fn,
) -> List[RequestConfig]:
    requests = []
    vuln_name = template.id.replace("-", "_").upper()

    payloads_to_use = list(generic.payloads)
    if generic.payloads_file:
        file_payloads = load_payloads_fn(generic.payloads_file)
        payloads_to_use.extend(file_payloads)

    if not payloads_to_use:
        return []

    for url, param_name in mapped_endpoints.items():
        parsed = urlparse(url)
        base_path = parsed.path

        for payload in payloads_to_use:
            if isinstance(payload, str):
                payload_cfg = PayloadConfig(name=payload[:30], value=payload)
            else:
                payload_cfg = payload

            if generic.method.upper() == "GET":
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
                    context = {
                        "payload": payload_cfg.value,
                        "parameter": param_name,
                        "sqli": payload_cfg.value,
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

            request.matchers = generic.matchers
            request.on_match = {
                "vulnerability": vuln_name,
                "message": f"{template.info.name}: {payload_cfg.name} on {param_name}",
                "endpoint_name": f"auto:{base_path}",
            }

            requests.append(request)

    logger.info(f"Generated {len(requests)} requests for auto-mapped endpoints")
    return requests


def expand_template(
    template: Template,
    target,
    load_payloads_fn,
    build_get_fn,
    build_post_fn,
    expand_broadcast_fn,
    expand_tiers_fn,
) -> List[RequestConfig]:
    if template.generic:
        return expand_generic_template(
            template=template,
            target=target,
            load_payloads_fn=load_payloads_fn,
            build_get_fn=build_get_fn,
            build_post_fn=build_post_fn,
            expand_broadcast_fn=expand_broadcast_fn,
            expand_tiers_fn=expand_tiers_fn,
        )
    return template.requests


def expand_generic_template(
    template: Template,
    target,
    load_payloads_fn,
    build_get_fn,
    build_post_fn,
    expand_broadcast_fn,
    expand_tiers_fn,
) -> List[RequestConfig]:
    generic = template.generic
    if not generic:
        return template.requests

    endpoints = target.get_endpoints()
    endpoint_key = generic.endpoint.lstrip("{{").rstrip("}}")

    if endpoint_key == BROADCAST_KEYWORD:
        return expand_broadcast_fn(template, generic, endpoints)

    endpoint_path = endpoints.get(endpoint_key)

    if not endpoint_path:
        auto_mapped = find_auto_mapped_endpoints(endpoint_key, set(template.info.tags), endpoints)
        if auto_mapped:
            logger.info(f"Auto-mapping '{endpoint_key}' to {len(auto_mapped)} discovered endpoints")
            return _expand_auto_mapped(template, generic, auto_mapped, load_payloads_fn, build_get_fn, build_post_fn)

        logger.warning(f"Endpoint '{generic.endpoint}' not found in target config, skipping template")
        return []

    requests = []

    if generic.detection_tiers:
        return expand_tiers_fn(template, endpoint_path, generic)

    payloads_to_use = list(generic.payloads)
    if generic.payloads_file:
        file_payloads = load_payloads_fn(generic.payloads_file)
        payloads_to_use.extend(file_payloads)
        logger.debug(f"Loaded {len(file_payloads)} payloads from {generic.payloads_file}")

    for payload in payloads_to_use:
        if isinstance(payload, str):
            payload_cfg = PayloadConfig(name=payload[:30], value=payload)
        else:
            payload_cfg = payload

        if generic.method.upper() == "GET":
            request = build_get_fn(endpoint_path, generic, payload_cfg)
        elif generic.method.upper() == "POST":
            request = build_post_fn(endpoint_path, generic, payload_cfg)
        else:
            logger.warning(f"Unsupported method: {generic.method}")
            continue

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
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    requests = []
    vuln_name = template.id.replace("-", "_").upper()

    template_tags = set(template.info.tags)
    is_injection_template = bool(template_tags & _INJECTION_TAGS)

    filtered_endpoints = {}
    for name, url in endpoints.items():
        if not is_injection_template:
            filtered_endpoints[name] = url
        else:
            parsed = urlparse(url)
            has_params = bool(parsed.query) or '?' in url
            is_api = '/api/' in url.lower() or '/rest/' in url.lower()

            if has_params or is_api:
                filtered_endpoints[name] = url
            else:
                logger.debug(f"Skipping {url} for {template.id}: no injection points")

    if not filtered_endpoints:
        logger.warning(f"Broadcast mode: no suitable endpoints found for {template.id}")
        return []

    logger.info(f"Broadcast mode: targeting {len(filtered_endpoints)} endpoints for {template.id}")

    if generic.detection_tiers:
        for endpoint_name, endpoint_path in filtered_endpoints.items():
            tier_requests = expand_tiers_fn(template, endpoint_path, generic)
            for req in tier_requests:
                if not req.on_match:
                    req.on_match = {}
                req.on_match["endpoint_name"] = endpoint_name
            requests.extend(tier_requests)
        return requests

    payloads_to_use = list(generic.payloads)
    if generic.payloads_file:
        file_payloads = load_payloads_fn(generic.payloads_file)
        payloads_to_use.extend(file_payloads)

    for endpoint_name, endpoint_path in filtered_endpoints.items():
        parsed = urlparse(endpoint_path)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        if params and is_injection_template:
            for param_name in params.keys():
                for payload in payloads_to_use:
                    if isinstance(payload, str):
                        payload_cfg = PayloadConfig(name=payload[:30], value=payload)
                    else:
                        payload_cfg = payload

                    modified_params = params.copy()
                    modified_params[param_name] = [payload_cfg.value]
                    
                    new_query = urlencode(modified_params, doseq=True)
                    new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
                    new_path = new_url.replace(f"{parsed.scheme}://{parsed.netloc}", "") if parsed.scheme else parsed.path + "?" + new_query

                    request = RequestConfig(
                        name=f"{endpoint_name}:{param_name}:{payload_cfg.name}",
                        method="GET",
                        path=new_path,
                        headers=generic.headers.copy(),
                        cookies={},
                    )

                    request.matchers = generic.matchers
                    request.on_match = {
                        "vulnerability": vuln_name,
                        "message": f"{template.info.name}: {payload_cfg.name} in parameter '{param_name}' on {endpoint_name}",
                        "endpoint_name": endpoint_name,
                    }

                    requests.append(request)
        
        if is_injection_template:
            import re
            path_segments = parsed.path.split('/')
            for i, segment in enumerate(path_segments):
                if segment and (segment.isdigit() or re.match(r'^[0-9a-f-]+$', segment)):
                    for payload in payloads_to_use:
                        if isinstance(payload, str):
                            payload_cfg = PayloadConfig(name=payload[:30], value=payload)
                        else:
                            payload_cfg = payload

                        new_segments = path_segments.copy()
                        new_segments[i] = segment + payload_cfg.value
                        new_path = '/'.join(new_segments)
                        if parsed.query:
                            new_path += '?' + parsed.query

                        request = RequestConfig(
                            name=f"{endpoint_name}:path[{i}]:{payload_cfg.name}",
                            method="GET",
                            path=new_path,
                            headers=generic.headers.copy(),
                            cookies={},
                        )

                        request.matchers = generic.matchers
                        request.on_match = {
                            "vulnerability": vuln_name,
                            "message": f"{template.info.name}: {payload_cfg.name} in path segment '{segment}' on {endpoint_name}",
                            "endpoint_name": endpoint_name,
                        }

                        requests.append(request)
        
        if not is_injection_template or (not params and is_injection_template):
            for payload in payloads_to_use:
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

                original_name = request.name or ""
                request.name = f"{endpoint_name}:{original_name}" if original_name else endpoint_name

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
    build_get_fn,
    build_post_fn,
) -> List[RequestConfig]:
    requests = []

    for tier_config in generic.detection_tiers:
        tier = tier_config.get_tier()

        if tier == DetectionTier.AGGRESSIVE:
            logger.warning("Running aggressive detection tier - may cause delays")

        detection_type = tier_config.detection_type or "error_based"

        if detection_type == "time_blind":
            requests.extend(build_time_blind_requests(
                template, endpoint_path, generic, tier_config, build_get_fn, build_post_fn
            ))
        else:
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

        request.matchers = tier_config.matchers
        request.on_match = {
            "vulnerability": vuln_name,
            "message": f"{template.info.name} ({tier.value}): {payload_cfg.name}",
            "detection_type": "error_based",
            "tier": tier.value,
        }
        requests.append(request)

    return requests


def build_time_blind_requests(
    template: Template,
    endpoint_path: str,
    generic: GenericTemplate,
    tier_config,
    build_get_fn,
    build_post_fn,
) -> List[RequestConfig]:
    requests = []
    vuln_name = template.id.replace("-", "_").upper()
    tier = tier_config.get_tier()

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
    context = {
        "payload": payload.value,
        "parameter": generic.parameter or "",
    }
    context["sqli"] = payload.value

    if generic.parameter and not endpoint_path.endswith("="):
        path = f"{endpoint_path}?{generic.parameter}={payload.value}"
    elif endpoint_path.endswith("=") or endpoint_path.endswith("?"):
        path = f"{endpoint_path}{payload.value}"
    else:
        if "?" in endpoint_path:
            path = f"{endpoint_path}&{payload.value}"
        else:
            path = f"{endpoint_path}{payload.value}"

    path = render_template(path, context)

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
    context = {
        "payload": payload.value,
        "parameter": generic.parameter or "",
    }
    context["sqli"] = payload.value

    rendered_headers = {}
    for key, value in generic.headers.items():
        rendered_headers[key] = render_template(str(value), context)
    rendered_headers["Content-Type"] = generic.content_type

    if generic.body_template:
        body = render_template(generic.body_template, context)
    elif generic.parameter:
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
