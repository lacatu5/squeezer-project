import asyncio
import json
from typing import Any, Dict, Optional, Tuple

import httpx
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

from squeezer.config import EvidenceStrength, Finding, RequestConfig, SeverityLevel, Template
from squeezer.core.matchers import MatchResult, create_matcher, evaluate_matchers
from squeezer.scanner.context import ExecutionContext
from squeezer.utils import logger


DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAY = 0.1


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    retry=retry_if_exception_type((httpx.NetworkError, httpx.TimeoutException, OSError)),
    reraise=True,
)
async def _execute_single_request(
    client,
    method: str,
    path: str,
    **kwargs
) -> httpx.Response:
    return await client.request(method, path, **kwargs)


async def _execute_request_with_retry(
    method: str,
    path: str,
    kwargs: Dict[str, Any],
    get_client_fn,
    max_retries: int = DEFAULT_MAX_RETRIES,
    retry_delay: float = DEFAULT_RETRY_DELAY,
) -> Tuple[httpx.Response, bool]:
    responses = []
    client = get_client_fn()

    for _ in range(max_retries):
        response = await _execute_single_request(client, method, path, **kwargs)
        responses.append(response)
        if len(responses) < max_retries:
            await asyncio.sleep(retry_delay)

    if len(responses) > 1:
        from squeezer.core.validators import ConsistencyChecker
        is_consistent = ConsistencyChecker.are_consistent(responses)
        return responses[0], is_consistent

    return responses[0], True if responses else None


async def execute_request(
    config: RequestConfig,
    context: ExecutionContext,
    template: Template,
    target,
    auth_context,
    get_client_fn,
    max_retries: int = DEFAULT_MAX_RETRIES,
) -> Optional[Finding]:
    method = config.method
    path = context.interpolate(config.path)
    headers = prepare_headers(config, context)
    body = prepare_body(config, context)

    kwargs: Dict[str, Any] = {"headers": headers}
    if body:
        if config.json_body:
            kwargs["json"] = body
        else:
            kwargs["content"] = body

    if auth_context:
        kwargs["headers"].update(auth_context.headers)
        if auth_context.cookies:
            kwargs["cookies"] = auth_context.cookies.copy()

    if config.cookies:
        if "cookies" not in kwargs:
            kwargs["cookies"] = {}
        kwargs["cookies"].update(config.cookies)

    try:
        use_retry = (
            template.info.severity in ("critical", "high") and
            not config.on_match
        )

        if use_retry:
            response, is_consistent = await _execute_request_with_retry(
                method, path, kwargs, get_client_fn, max_retries=max_retries
            )
        else:
            client = get_client_fn()
            response = await client.request(method, path, **kwargs)
            is_consistent = True

        context.responses.append(response)

        if config.name:
            context.save_response(config.name, response)

        if config.matchers:
            matchers = []
            for matcher_config in config.matchers:
                if matcher_config.type == "diff":
                    base_response_name = getattr(matcher_config, 'base_response', None)
                    base_response = None
                    if base_response_name:
                        base_response = context.get_response(base_response_name)
                    matchers.append(create_matcher(matcher_config, base_response=base_response))
                else:
                    matchers.append(create_matcher(matcher_config))

            condition = config.matchers_condition if hasattr(config, 'matchers_condition') else (config.matchers[0].condition if config.matchers else "and")

            result = evaluate_matchers(matchers, response, condition)

            if result.matched:
                from squeezer.core.validators import ConfidenceCalculator
                confidence = ConfidenceCalculator.calculate(
                    result.evidence_strength,
                    sum(1 for m in matchers if m.matches(response).matched),
                    is_consistent=is_consistent,
                )
                return create_finding(config, template, response, result, confidence)

    except httpx.HTTPError as e:
        logger.debug(f"HTTP error during request: {e}")
    except Exception as e:
        logger.debug(f"Unexpected error during request: {type(e).__name__}: {e}")

    return None


def prepare_headers(config: RequestConfig, context: ExecutionContext) -> Dict[str, str]:
    headers = {}
    for key, value in config.headers.items():
        headers[key] = context.interpolate(value)
    return headers


def prepare_body(config: RequestConfig, context: ExecutionContext) -> Any:
    if config.json_body:
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
    confidence: str = "medium",
) -> Finding:
    on_match = config.on_match or {}

    evidence_strength = match_result.evidence_strength
    if on_match.get("evidence_strength"):
        strength_str = on_match["evidence_strength"]
        try:
            evidence_strength = EvidenceStrength(strength_str)
        except ValueError:
            evidence_strength = EvidenceStrength.HEURISTIC

    owasp_category = template.info.get_owasp_category()

    sev = template.info.severity
    if isinstance(sev, str):
        sev_lower = sev.lower()
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
        }
        sev = severity_map.get(sev_lower, SeverityLevel.MEDIUM)

    return Finding(
        template_id=template.id,
        vulnerability_type=on_match.get("vulnerability") or template.id.replace("-", "_"),
        severity=sev,
        owasp_category=owasp_category,
        evidence_strength=evidence_strength,
        url=str(response.url),
        evidence={
            "status_code": response.status_code,
            "matcher_evidence": match_result.evidence,
            "confidence": confidence,
        },
        message=on_match.get("message") or template.info.description or template.info.name,
        remediation=on_match.get("remediation") or "",
        request_details=f"{config.method} {config.path}",
        response_details=match_result.response_details,
        tags=list(template.info.tags) if template.info.tags else [],
    )
