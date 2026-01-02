from typing import Dict, List
from urllib.parse import urlparse, parse_qs

from jinja2 import Template as Jinja2Template
from jinja2 import StrictUndefined

from dast.config import (
    GenericTemplate,
    PayloadConfig,
    RequestConfig,
    Template,
)
from dast.utils import logger

BROADCAST_KEYWORD = "all_discovered"
_INJECTION_TAGS = {'sqli', 'xss', 'injection', 'ssti', 'xxe'}


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


def expand_template(
    template: Template,
    target,
    load_payloads_fn,
    build_get_fn,
    build_post_fn,
    expand_broadcast_fn,
) -> List[RequestConfig]:
    if template.generic:
        return expand_generic_template(
            template=template,
            target=target,
            load_payloads_fn=load_payloads_fn,
            build_get_fn=build_get_fn,
            build_post_fn=build_post_fn,
            expand_broadcast_fn=expand_broadcast_fn,
        )
    return template.requests


def expand_generic_template(
    template: Template,
    target,
    load_payloads_fn,
    build_get_fn,
    build_post_fn,
    expand_broadcast_fn,
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
        logger.warning(f"Endpoint '{generic.endpoint}' not found in target config, skipping template")
        return []

    requests = []
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
