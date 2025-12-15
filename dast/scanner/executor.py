"""Request execution logic for DAST scanning."""

import json
from typing import Any, Dict, List, Optional

import httpx

from dast.config import EvidenceStrength, Finding, RequestConfig, Template
from dast.extractors import create_extractor
from dast.matchers import MatchResult, create_matcher, evaluate_matchers
from dast.scanner.context import ExecutionContext
from dast.utils import logger


async def execute_request(
    config: RequestConfig,
    context: ExecutionContext,
    template: Template,
    target,
    auth_context,
    get_client_fn,
    response_cache: Dict[str, httpx.Response],
) -> Optional[Finding]:
    """Execute a single HTTP request with concurrency control.

    Args:
        config: Request configuration
        context: Execution context for variables and interpolation
        template: Template being executed
        target: TargetConfig
        auth_context: AuthContext for authentication
        get_client_fn: Function to get HTTP client
        response_cache: Cache for boolean-blind baseline responses

    Returns:
        Finding if vulnerability detected, None otherwise
    """
    # Prepare request
    method = config.method
    path = context.interpolate(config.path)
    headers = prepare_headers(config, context)
    body = prepare_body(config, context)

    # Build kwargs
    kwargs: Dict[str, Any] = {"headers": headers}
    if body:
        if config.json_body:
            kwargs["json"] = body
        else:
            kwargs["content"] = body

    # Add auth headers and cookies
    if auth_context:
        kwargs["headers"].update(auth_context.headers)
        if auth_context.cookies:
            kwargs["cookies"] = auth_context.cookies.copy()

    if config.cookies:
        if "cookies" not in kwargs:
            kwargs["cookies"] = {}
        kwargs["cookies"].update(config.cookies)

    try:
        # Execute request
        client = get_client_fn()
        response = await client.request(method, path, **kwargs)

        context.responses.append(response)
        context.request_count += 1

        # Extract data using the new extractors module
        if config.extractors:
            # Convert ExtractorConfig to dict for the extractor factory
            for extractor_config in config.extractors:
                extractor_dict = {
                    "type": "json" if extractor_config.selector else "regex",
                    "name": extractor_config.name,
                    "selector": extractor_config.selector,
                    "regex": extractor_config.regex,
                    "group": extractor_config.group,
                    "part": extractor_config.location,
                }
                try:
                    extractor = create_extractor(extractor_dict)
                    result = extractor.extract(response)
                    if result and result.success:
                        context.set(result.name, result.value)
                except Exception:
                    # Continue on extraction errors
                    pass

        # Save response if named (for IDOR/diff matching)
        if config.name:
            context.save_response(config.name, response)

        # Cache response for boolean-blind comparison
        on_match = config.on_match or {}
        if on_match.get("cache_key"):
            response_cache[on_match["cache_key"]] = response
            # Baseline requests don't trigger findings
            if on_match.get("is_baseline"):
                return None

        # Handle boolean-blind detection (compare with baseline)
        if on_match.get("compare_with"):
            cache_key = on_match["compare_with"]
            if cache_key in response_cache:
                baseline_response = response_cache[cache_key]
                # Compare responses - they must be different for boolean-blind SQLi
                if responses_differ(baseline_response, response, target):
                    # Responses differ - possible SQLi
                    # For boolean-blind, only check negative matchers (to exclude false positives)
                    negative_matchers = [m for m in config.matchers if getattr(m, 'negative', False)]
                    if negative_matchers:
                        # Check if negative matchers pass
                        matchers = [create_matcher(m) for m in negative_matchers]
                        result = evaluate_matchers(matchers, response, "and")
                        # For negative matchers: matched=True means patterns NOT found (good)
                        if not result.matched:
                            return None
                    result = MatchResult(
                        matched=True,
                        evidence={
                            "baseline_length": len(baseline_response.text),
                            "response_length": len(response.text),
                            "difference": abs(len(baseline_response.text) - len(response.text)),
                            "detection_type": "boolean_blind",
                        },
                        message="Boolean-blind: response differs from baseline",
                    )
                    return create_finding(config, template, response, result)
            return None  # No baseline to compare

        # Check matchers (standard detection)
        if config.matchers:
            # Check if we need to use diff matcher (requires base response)
            matchers = []
            for matcher_config in config.matchers:
                if matcher_config.type == "diff":
                    # Look for base response name in config
                    base_response_name = getattr(matcher_config, 'base_response', None)
                    base_response = None
                    if base_response_name:
                        base_response = context.get_response(base_response_name)
                    matchers.append(create_matcher(matcher_config, base_response=base_response))
                else:
                    matchers.append(create_matcher(matcher_config))

            result = evaluate_matchers(matchers, response, config.matchers[0].condition or "and")

            if result.matched:
                return create_finding(config, template, response, result)

    except httpx.HTTPError as e:
        logger.debug(f"HTTP error during request: {e}")

    except Exception as e:
        logger.debug(f"Unexpected error during request: {type(e).__name__}: {e}")

    return None


def responses_differ(
    response1: httpx.Response,
    response2: httpx.Response,
    target,
) -> bool:
    """Check if two responses differ significantly for boolean-blind detection.

    Uses the configured boolean_diff_threshold from target config.

    Returns True if responses have different:
    - Status codes
    - Content length (more than threshold difference)
    - JSON structure (for JSON responses)
    """
    # Different status codes = differ
    if response1.status_code != response2.status_code:
        return True

    # Check content length difference
    len1 = len(response1.text)
    len2 = len(response2.text)

    # If both are empty, they're the same
    if len1 == 0 and len2 == 0:
        return False

    # If one is empty and other isn't, they differ
    if len1 == 0 or len2 == 0:
        return True

    # Check for significant length difference (using configured threshold)
    threshold = target.boolean_diff_threshold
    length_diff = abs(len1 - len2)
    if length_diff > max(len1, len2) * threshold:
        return True

    # For JSON responses, check structure
    try:
        json1 = response1.json()
        json2 = response2.json()

        # For arrays, check count
        if isinstance(json1, dict) and isinstance(json2, dict):
            # Check for data array length
            data1 = json1.get("data", [])
            data2 = json2.get("data", [])
            if isinstance(data1, list) and isinstance(data2, list):
                if len(data1) != len(data2):
                    return True
    except Exception:
        # Not JSON or parsing failed, use text comparison
        pass

    # Responses are essentially the same
    return False


def prepare_headers(config: RequestConfig, context: ExecutionContext) -> Dict[str, str]:
    """Prepare request headers with interpolation."""
    headers = {}
    for key, value in config.headers.items():
        headers[key] = context.interpolate(value)
    return headers


def prepare_body(config: RequestConfig, context: ExecutionContext) -> Any:
    """Prepare request body with interpolation."""
    if config.json_body:
        # Interpolate JSON body
        json_str = json.dumps(config.json_body)
        json_str = context.interpolate(json_str)
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            return config.json_body

    if config.body:
        return context.interpolate(config.body)

    return None


def create_finding(
    config: RequestConfig,
    template: Template,
    response: httpx.Response,
    match_result: MatchResult,
) -> Finding:
    """Create a finding from a successful match."""
    on_match = config.on_match or {}

    # Use evidence_strength from match result, default to HEURISTIC
    evidence_strength = match_result.evidence_strength
    if on_match.get("evidence_strength"):
        # Allow template to override, but validate
        strength_str = on_match["evidence_strength"]
        try:
            evidence_strength = EvidenceStrength(strength_str)
        except ValueError:
            evidence_strength = EvidenceStrength.HEURISTIC

    # Get OWASP category from template
    owasp_category = template.info.get_owasp_category()

    return Finding(
        template_id=template.id,
        vulnerability_type=on_match.get("vulnerability") or template.id.replace("-", "_"),
        severity=template.info.severity,  # Keep legacy severity for backward compatibility
        owasp_category=owasp_category,  # Add OWASP category
        evidence_strength=evidence_strength,
        url=str(response.url),
        evidence={
            "status_code": response.status_code,
            "matcher_evidence": match_result.evidence,
        },
        message=on_match.get("message") or template.info.description or template.info.name,
        remediation=on_match.get("remediation") or "",
        request_details=f"{config.method} {config.path}",
        response_details=match_result.response_details,
    )
