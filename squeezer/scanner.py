import asyncio
import json
import random
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from squeezer.auth import AuthContext, Authenticator
from squeezer.jwt_utils import decode_jwt, forge_none_algorithm
from squeezer.matchers import MatchResult, create_matcher, evaluate_matchers, ConsistencyChecker, ConfidenceCalculator
from squeezer.models import (
    EvidenceStrength,
    Finding,
    RequestConfig,
    ScanReport,
    SeverityLevel,
    TargetConfig,
    Template,
    load_autodiscovery_patterns,
)
from squeezer.utils import TargetValidator, logger, sanitize_url

DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAY = 0.1

@dataclass
class ExecutionContext:
    variables: Dict[str, Any] = field(default_factory=dict)
    endpoints: Dict[str, str] = field(default_factory=dict)
    responses: List[httpx.Response] = field(default_factory=list)
    _named_responses: Dict[str, httpx.Response] = field(default_factory=dict)
    _jwt_cache: Dict[str, str] = field(default_factory=dict)

    def interpolate(self, text: str, max_iterations: int = 10) -> str:
        result = text
        prev_result = None
        for _ in range(max_iterations):
            prev_result = result
            result = self._interpolate_once(result)
            if result == prev_result:
                break
        return result

    def _jwt_none_forge(self, token: str) -> str:
        if token in self._jwt_cache:
            return self._jwt_cache[token]
        try:
            token_data = decode_jwt(token)
            forged = forge_none_algorithm(token_data)
            self._jwt_cache[token] = forged
            return forged
        except Exception as e:
            logger.debug(f"JWT forging failed: {e}")
            return token

    def _interpolate_once(self, text: str) -> str:
        result = text
        for name, value in self.endpoints.items():
            result = result.replace(f"{{{{endpoints.{name}}}}}", value)

        def replace_with_default(match):
            var_name = match.group(1)
            default_value = match.group(2)
            return str(self.variables.get(var_name, default_value))

        result = re.sub(r'\{\{\s*(\w+)\s*\|\s*([^}]+)\s*\}\}', replace_with_default, result)
        for name in sorted(self.variables.keys(), key=len, reverse=True):
            value = self.variables[name]
            result = result.replace(f"{{{{{name}}}}}", str(value))
            result = result.replace(f"{{{{ {name} }}}}", str(value))

        result = re.sub(r"rand_base\((\d+)\)", lambda m: self._rand_base(m.group(1)), result)
        result = re.sub(r"rand_int\((\d+)\,(\d+)\)", lambda m: str(random.randint(int(m.group(1)), int(m.group(2)))), result)
        result = re.sub(r"rand_int\(\)", lambda m: str(random.randint(10000, 99999)), result)
        result = re.sub(r"uuid\(\)", lambda m: str(uuid.uuid4()), result)
        result = re.sub(r"jwt_none\(([^)]+)\)", lambda m: self._jwt_none_forge(m.group(1)), result)
        return result

    def _rand_base(self, length: str) -> str:
        import string
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=int(length)))

    def save_response(self, name: str, response: httpx.Response) -> None:
        self._named_responses[name] = response

    def get_response(self, name: str) -> Optional[httpx.Response]:
        return self._named_responses.get(name)


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    retry=retry_if_exception_type((httpx.NetworkError, httpx.TimeoutException, OSError)),
    reraise=True,
)
async def _execute_single_request(client, method: str, path: str, **kwargs) -> httpx.Response:
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
        is_consistent = ConsistencyChecker.are_consistent(responses)
        return responses[0], is_consistent
    return responses[0], bool(responses)


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
        template_file=template.file_path,
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
    headers = {}
    if auth_context:
        headers.update(auth_context.headers)
    headers.update(prepare_headers(config, context))
    body = prepare_body(config, context)
    kwargs: Dict[str, Any] = {"headers": headers}
    if body:
        if config.json_body:
            kwargs["json"] = body
        else:
            kwargs["content"] = body
    if auth_context and auth_context.cookies:
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


class TemplateEngine:
    def __init__(self, target: TargetConfig, validate_target: bool = True):
        self.target = target
        self.authenticator = Authenticator()
        self._auth_context: Optional[AuthContext] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._validate_target = validate_target
        self._connectivity_check: Optional[Dict[str, Any]] = None
        self._semaphore = asyncio.Semaphore(max(1, target.parallel))
        self._request_delay = target.request_delay

    async def _acquire_slot(self):
        await self._semaphore.acquire()
        if self._request_delay > 0:
            await asyncio.sleep(self._request_delay)

    def _release_slot(self):
        self._semaphore.release()

    async def initialize(self) -> None:
        is_valid, error = TargetValidator.validate_url(self.target.base_url)
        if not is_valid:
            raise ValueError(f"Invalid target URL: {error}")
        if self._validate_target:
            logger.debug(f"Checking connectivity to {sanitize_url(self.target.base_url)}")
            self._connectivity_check = await TargetValidator.check_connectivity(
                self.target.base_url,
                timeout=min(self.target.timeout, 10.0)
            )
            if not self._connectivity_check["accessible"]:
                logger.warning(
                    f"Target may not be accessible: {self._connectivity_check.get('error', 'Unknown error')}"
                )
            else:
                logger.debug(
                    f"Target accessible: {self._connectivity_check['status_code']} "
                    f"({self._connectivity_check.get('server', 'Unknown server')}) "
                    f"in {self._connectivity_check.get('response_time_ms', 0):.0f}ms"
                )
        if self.target.authentication and self.target.authentication.type != "none":
            logger.debug(f"Authenticating with {self.target.authentication.type.value}")
            try:
                self._auth_context = await self.authenticator.authenticate(
                    self.target.authentication,
                    self.target.base_url,
                )
                if self._auth_context.error:
                    raise ValueError(self._auth_context.error)
                logger.debug("Authentication successful")
            except Exception as e:
                logger.error(f"Authentication failed: {e}")
                raise

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.target.base_url,
                timeout=self.target.timeout,
                follow_redirects=True,
            )
        return self._client

    async def execute_template(self, template: Template, report: ScanReport) -> None:
        logger.debug(f"Executing template: {template.id}")
        requests_to_execute = self._expand_template(template)
        variables = self.target.get_variables().copy()
        variables.update(self.target.get_endpoints())
        discovered_params = self.target.get_discovered_params()
        if discovered_params:
            variables["discovered_params"] = discovered_params
        if self._auth_context:
            if self._auth_context.token:
                variables["bearer_token"] = self._auth_context.token
        context = ExecutionContext(
            variables=variables,
            endpoints=self.target.get_endpoints(),
        )
        context.variables.update(template.variables)
        for i, request_config in enumerate(requests_to_execute, 1):
            request_name = request_config.name or f"Request {i}"
            logger.debug(f"  Executing: {request_name}")
            try:
                finding = await self._execute_request(request_config, context, template)
                if finding:
                    logger.debug(f"  [+] Finding: {finding.vulnerability_type}")
                    report.add_finding(finding)
            except httpx.TimeoutException:
                logger.warning(f"  [-] Request timeout: {request_name}")
                report.add_error(f"Template {template.id}: Request timeout - {request_name}")
            except httpx.ConnectError as e:
                logger.error(f"  [-] Connection error: {e}")
                report.add_error(f"Template {template.id}: Connection error - {request_name}")
                break
            except Exception as e:
                logger.debug(f"  [-] Request failed: {e}")
                report.add_error(f"Template {template.id}: {request_name} - {str(e)}")

    def _expand_template(self, template: Template) -> List[RequestConfig]:
        all_requests = []
        discovered_endpoints = self.target.endpoints.custom or {}
        autodiscovery_patterns = load_autodiscovery_patterns()

        from squeezer.endpoint_matcher import EndpointMatcher
        matcher = EndpointMatcher()

        def expand_autodiscover(req: RequestConfig) -> List[RequestConfig]:
            text = str(req.json_body) if req.json_body is not None else (req.body or "")

            match = re.search(r'\{\{autodiscover:(\w+)\}\}', text)
            if not match:
                return [req]

            pattern_type = match.group(1)
            field_names = autodiscovery_patterns.get(pattern_type, [])

            if not field_names:
                return [req]

            expanded = []
            for field_name in field_names:
                new_req = req.model_copy()
                new_req.name = f"{req.name} ({field_name})"

                if req.json_body:
                    json_str = json.dumps(req.json_body)
                    json_str = json_str.replace(f"{{{{autodiscover:{pattern_type}}}}}", field_name)
                    try:
                        new_req.json_body = json.loads(json_str)
                    except json.JSONDecodeError:
                        pass

                if req.body:
                    new_req.body = req.body.replace(f"{{{{autodiscover:{pattern_type}}}}}", field_name)

                expanded.append(new_req)

            return expanded

        for req in template.requests:
            original_path = req.path or ""
            path = original_path.strip('"')
            expanded_requests = []

            if path == "@all@":
                for endpoint_url in discovered_endpoints.keys():
                    parsed = urlparse(endpoint_url)
                    expanded_path = parsed.path or "/"
                    if '?' in original_path:
                        query_part = original_path.split('?')[1]
                        expanded_path = f"{expanded_path}?{query_part}"
                    expanded_req = req.model_copy(update={"path": expanded_path})
                    expanded_req.name = f"{req.name} - {expanded_path}"
                    expanded_requests.extend(expand_autodiscover(expanded_req))

            elif path.startswith("@api@"):
                suffix = path[5:].lstrip()
                query_suffix = ""
                path_suffix = ""
                id_suffix = ""

                if '?' in suffix:
                    path_part, query_part = suffix.split('?', 1)
                    suffix = path_part
                    query_suffix = f"?{query_part}"

                # Check for pattern@id format like cart@/1 or users@/2
                if '@' in suffix:
                    pattern_part, _, id_part = suffix.partition('@')
                    path_suffix = pattern_part
                    id_suffix = id_part or ''
                else:
                    path_suffix = suffix

                path_suffix_clean = path_suffix.strip("@")

                # Check if suffix is numeric (ID enumeration) - append to all API endpoints
                is_numeric_suffix = path_suffix_clean.lstrip('/').isdigit() if path_suffix_clean else False

                matched = False
                for endpoint_url in discovered_endpoints.keys():
                    parsed = urlparse(endpoint_url)
                    base_path = parsed.path.rstrip('/')

                    if is_numeric_suffix or not path_suffix_clean:
                        # Numeric suffix or no suffix - append to all API endpoints
                        if '/api/' in parsed.path or parsed.path.startswith('/api'):
                            matched = True
                            expanded_path = base_path + path_suffix + query_suffix
                            expanded_req = req.model_copy(update={"path": expanded_path})
                            expanded_req.name = f"{req.name} - {expanded_path}"
                            expanded_requests.extend(expand_autodiscover(expanded_req))
                    elif matcher.match_suffix(endpoint_url, path_suffix_clean):
                        # Named suffix - only match endpoints with that suffix
                        matched = True
                        expanded_path = base_path + id_suffix + query_suffix
                        expanded_req = req.model_copy(update={"path": expanded_path})
                        expanded_req.name = f"{req.name} - {expanded_path}"
                        expanded_requests.extend(expand_autodiscover(expanded_req))

                if not matched and path_suffix_clean and not is_numeric_suffix:
                    # Try synonym matching
                    for synonym in matcher.expand_with_synonyms(path_suffix_clean):
                        for endpoint_url in discovered_endpoints.keys():
                            parsed = urlparse(endpoint_url)
                            base_path = parsed.path.rstrip('/')

                            if synonym.lower() in parsed.path.lower():
                                matched = True
                                expanded_path = base_path + id_suffix + query_suffix
                                expanded_req = req.model_copy(update={"path": expanded_path})
                                expanded_req.name = f"{req.name} - {expanded_path}"
                                expanded_requests.extend(expand_autodiscover(expanded_req))

                if not matched:
                    # Fallback: append to all API endpoints
                    for endpoint_url in discovered_endpoints.keys():
                        parsed = urlparse(endpoint_url)
                        if '/api/' in parsed.path or parsed.path.startswith('/api'):
                            expanded_path = parsed.path.rstrip('/') + path_suffix + id_suffix + query_suffix
                            expanded_req = req.model_copy(update={"path": expanded_path})
                            expanded_req.name = f"{req.name} - {expanded_path}"
                            expanded_requests.extend(expand_autodiscover(expanded_req))

                if not expanded_requests:
                    expanded_requests.extend(expand_autodiscover(req))

            else:
                expanded_requests.extend(expand_autodiscover(req))

            all_requests.extend(expanded_requests)

        return all_requests if all_requests else template.requests

    async def _execute_request(self, config: RequestConfig, context: ExecutionContext, template: Template):
        await self._acquire_slot()
        try:
            return await execute_request(
                config=config,
                context=context,
                template=template,
                target=self.target,
                auth_context=self._auth_context,
                get_client_fn=self._get_client,
            )
        finally:
            self._release_slot()


def load_templates(template_dirs) -> List[Template]:
    templates = []
    skipped = 0
    if isinstance(template_dirs, (Path, str)):
        dirs_to_scan = [Path(template_dirs)]
    else:
        dirs_to_scan = [Path(d) for d in template_dirs]
    for template_dir in dirs_to_scan:
        if template_dir.is_file():
            yaml_files = [template_dir]
        else:
            yaml_files = list(template_dir.rglob("*.yaml"))
        for yaml_file in yaml_files:
            try:
                template = Template.from_yaml(yaml_file)
                templates.append(template)
                logger.debug(f"Loaded template: {template.id}")
            except Exception as e:
                skipped += 1
                logger.debug(f"Skipping invalid template {yaml_file.name}: {e}")
    logger.debug(f"Loaded {len(templates)} templates ({skipped} skipped)")
    return templates


async def run_scan(target: TargetConfig, templates: List[Template], validate_target: bool = True) -> ScanReport:
    start_time = time.time()
    target_url = sanitize_url(target.base_url)
    logger.info(f"Scanning {target_url} with {len(templates)} templates")
    report = ScanReport(target=target.base_url, templates_executed=len(templates))
    engine = TemplateEngine(target, validate_target=validate_target)
    try:
        await engine.initialize()
        for i, template in enumerate(templates, 1):
            logger.debug(f"[{i}/{len(templates)}] {template.id}")
            try:
                await engine.execute_template(template, report)
            except Exception as e:
                logger.debug(f"Template {template.id} failed: {e}")
                report.add_error(f"Template {template.id} failed: {e}")
    except KeyboardInterrupt:
        logger.warning("Scan interrupted")
        report.add_error("Scan interrupted")
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        report.add_error(f"Scan failed: {e}")
    finally:
        await engine.close()
    report.duration_seconds = time.time() - start_time
    return report
