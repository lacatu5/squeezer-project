"""Template execution engine for DAST scanning."""

import json
import logging
import random
import re
import string
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import httpx

from dast.auth import Authenticator, AuthContext
from dast.config import (
    ExtractorConfig,
    Finding,
    GenericTemplate,
    PayloadConfig,
    RequestConfig,
    ScanReport,
    TargetConfig,
    Template,
    EvidenceStrength,
)
from dast.extractors import create_extractor, extract_all
from dast.matchers import Matcher, create_matcher, evaluate_matchers, MatchResult
from dast.utils import TargetValidator, logger, sanitize_url


@dataclass
class ExecutionContext:
    """Execution context for template variables.

    Maintains state across multi-request workflows:
    - variables: Extracted values from previous requests
    - endpoints: Named endpoint URLs
    - responses: History of all responses for comparison
    - request_count: Total requests made in this workflow
    """

    variables: Dict[str, Any] = field(default_factory=dict)
    endpoints: Dict[str, str] = field(default_factory=dict)
    responses: List[httpx.Response] = field(default_factory=list)
    request_count: int = 0

    # Response references for diff matchers (for IDOR detection)
    _named_responses: Dict[str, httpx.Response] = field(default_factory=dict)

    def interpolate(self, text: str) -> str:
        """Replace variable placeholders in text."""
        if not isinstance(text, str):
            return str(text)

        result = text

        # Handle built-in functions
        result = re.sub(r"rand_base\((\d+)\)", lambda m: self._rand_base(m.group(1)), result)
        result = re.sub(r"rand_int\(\)", lambda m: str(random.randint(10000, 99999)), result)
        result = re.sub(r"uuid\(\)", lambda m: str(uuid.uuid4()), result)

        # Handle JWT manipulation functions
        result = self._interpolate_jwt(result)

        # Handle endpoints
        for name, value in self.endpoints.items():
            result = result.replace(f"{{{{endpoints.{name}}}}}", value)

        # Handle variables (process longer keys first to avoid partial replacements)
        for name in sorted(self.variables.keys(), key=len, reverse=True):
            value = self.variables[name]
            # Handle both {{name}} and {{ name }} formats
            result = result.replace(f"{{{{{name}}}}}", str(value))
            result = result.replace(f"{{{{ {name} }}}}", str(value))

        return result

    def _interpolate_jwt(self, text: str) -> str:
        """Handle JWT manipulation functions."""
        from dast.jwt import JWTForge

        # jwt_none(token) - Change algorithm to "none"
        result = re.sub(r"jwt_none\(([^)]+)\)", lambda m: self._jwt_none(m.group(1)), text)

        # jwt_admin(token) - Set role to admin
        result = re.sub(r"jwt_admin\(([^)]+)\)", lambda m: self._jwt_admin(m.group(1)), result)

        # jwt_claim(token, claim, value) - Modify specific claim
        # Note: This handles simple string values
        result = re.sub(
            r'jwt_claim\(([^,]+),\s*([^,]+),\s*([^)]+)\)',
            lambda m: self._jwt_claim(m.group(1), m.group(2), m.group(3)),
            result
        )

        # jwt_no_exp(token) - Remove expiration
        result = re.sub(r"jwt_no_exp\(([^)]+)\)", lambda m: self._jwt_no_exp(m.group(1)), result)

        # jwt_weak_sign(token, secret) - Re-sign with weak secret
        result = re.sub(
            r'jwt_weak_sign\(([^,]+),\s*([^)]+)\)',
            lambda m: self._jwt_weak_sign(m.group(1), m.group(2)),
            result
        )

        return result

    def _jwt_none(self, token_var: str) -> str:
        """Apply jwt_none transformation to a variable."""
        from dast.jwt import JWTForge

        # Get the actual token value
        token = self.variables.get(token_var.strip(), token_var)
        try:
            return JWTForge.change_algorithm(token, "none")
        except Exception:
            return token

    def _jwt_admin(self, token_var: str) -> str:
        """Apply jwt_admin transformation to a variable."""
        from dast.jwt import JWTForge

        token = self.variables.get(token_var.strip(), token_var)
        try:
            return JWTForge.set_admin_role(token, "role")
        except Exception:
            return token

    def _jwt_claim(self, token_var: str, claim: str, value: str) -> str:
        """Apply jwt_claim transformation to a variable."""
        from dast.jwt import JWTForge

        token = self.variables.get(token_var.strip(), token_var)
        # Clean up claim and value (remove quotes and whitespace)
        claim = claim.strip().strip('"\'')
        value = value.strip().strip('"\'')
        try:
            return JWTForge.modify_claim(token, claim, value)
        except Exception:
            return token

    def _jwt_no_exp(self, token_var: str) -> str:
        """Apply jwt_no_exp transformation to a variable."""
        from dast.jwt import JWTForge

        token = self.variables.get(token_var.strip(), token_var)
        try:
            return JWTForge.remove_expiration(token)
        except Exception:
            return token

    def _jwt_weak_sign(self, token_var: str, secret: str) -> str:
        """Apply jwt_weak_sign transformation to a variable."""
        from dast.jwt import JWTForge

        token = self.variables.get(token_var.strip(), token_var)
        secret = secret.strip().strip('"\'')
        try:
            return JWTForge.sign_with_key(token, secret, "HS256")
        except Exception:
            return token

    def _rand_base(self, length_str: str) -> str:
        length = int(length_str) if length_str else 16
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))

    def set(self, name: str, value: Any) -> None:
        """Set a variable value."""
        self.variables[name] = value

    def get(self, name: str, default: Any = None) -> Any:
        """Get a variable value."""
        return self.variables.get(name, default)

    def save_response(self, name: str, response: httpx.Response) -> None:
        """Save a response by name for later reference (useful for IDOR)."""
        self._named_responses[name] = response

    def get_response(self, name: str) -> Optional[httpx.Response]:
        """Get a previously saved response."""
        return self._named_responses.get(name)

    def get_last_response(self) -> Optional[httpx.Response]:
        """Get the most recent response."""
        return self.responses[-1] if self.responses else None


class TemplateEngine:
    """Engine for executing vulnerability scan templates."""

    def __init__(self, target: TargetConfig, validate_target: bool = True):
        self.target = target
        self.authenticator = Authenticator(target.base_url, target.timeout)
        self._auth_context: Optional[AuthContext] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._validate_target = validate_target
        self._connectivity_check: Optional[Dict[str, Any]] = None

    async def initialize(self) -> None:
        """Initialize authentication and validate target."""
        # Validate target URL format
        is_valid, error = TargetValidator.validate_url(self.target.base_url)
        if not is_valid:
            raise ValueError(f"Invalid target URL: {error}")

        # Check connectivity if enabled
        if self._validate_target:
            logger.info(f"Checking connectivity to {sanitize_url(self.target.base_url)}")
            self._connectivity_check = await TargetValidator.check_connectivity(
                self.target.base_url,
                timeout=min(self.target.timeout, 10.0)
            )

            if not self._connectivity_check["accessible"]:
                logger.warning(
                    f"Target may not be accessible: {self._connectivity_check.get('error', 'Unknown error')}"
                )
            else:
                logger.info(
                    f"Target accessible: {self._connectivity_check['status_code']} "
                    f"({self._connectivity_check.get('server', 'Unknown server')}) "
                    f"in {self._connectivity_check.get('response_time_ms', 0):.0f}ms"
                )

        # Initialize authentication
        if self.target.authentication and self.target.authentication.type != "none":
            logger.info(f"Authenticating with {self.target.authentication.type.value}")
            try:
                self._auth_context = await self.authenticator.authenticate(
                    self.target.authentication
                )
                logger.info("Authentication successful")
            except Exception as e:
                logger.error(f"Authentication failed: {e}")
                raise

    async def close(self) -> None:
        """Close resources."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
        await self.authenticator.close()

    def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.target.base_url,
                timeout=self.target.timeout,
                follow_redirects=True,
            )
        return self._client

    async def execute_template(self, template: Template, report: ScanReport) -> None:
        """Execute a single vulnerability template."""
        logger.debug(f"Executing template: {template.id}")

        # Expand generic template if present
        requests_to_execute = self._expand_template(template)

        # Create execution context
        # Include endpoints in variables for direct interpolation {{endpoint_name}}
        variables = self.target.get_variables().copy()
        variables.update(self.target.get_endpoints())

        context = ExecutionContext(
            variables=variables,
            endpoints=self.target.get_endpoints(),
        )
        context.variables.update(template.variables)

        # Execute each request
        for i, request_config in enumerate(requests_to_execute, 1):
            request_name = request_config.name or f"Request {i}"
            logger.debug(f"  Executing: {request_name}")

            try:
                finding = await self._execute_request(request_config, context, template)
                if finding:
                    logger.info(f"  [+] Finding: {finding.vulnerability_type}")
                    report.add_finding(finding)
            except httpx.TimeoutException:
                logger.warning(f"  [-] Request timeout: {request_name}")
                report.add_error(f"Template {template.id}: Request timeout - {request_name}")
            except httpx.ConnectError as e:
                logger.error(f"  [-] Connection error: {e}")
                report.add_error(f"Template {template.id}: Connection error - {request_name}")
                break  # Stop processing this template on connection errors
            except Exception as e:
                logger.debug(f"  [-] Request failed: {e}")
                report.add_error(f"Template {template.id}: {request_name} - {str(e)}")

    def _expand_template(self, template: Template) -> List[RequestConfig]:
        """Expand a generic template into concrete requests.

        If the template has a 'generic' field, expand it into multiple requests
        based on the payload list. Otherwise, return the existing requests.
        """
        if template.generic:
            return self._expand_generic_template(template)
        return template.requests

    def _expand_generic_template(self, template: Template) -> List[RequestConfig]:
        """Expand a generic template into concrete requests based on payloads.

        Resolves the endpoint from target config and generates a request for each payload.
        """
        generic = template.generic
        if not generic:
            return template.requests

        # Resolve endpoint from target config
        endpoints = self.target.get_endpoints()
        endpoint_path = endpoints.get(generic.endpoint.lstrip("{{").rstrip("}}"))

        if not endpoint_path:
            logger.warning(f"Endpoint '{generic.endpoint}' not found in target config, skipping template")
            return []

        requests = []

        # Get base severity from template info
        base_severity = template.info.severity

        for payload in generic.payloads:
            # Normalize payload to PayloadConfig
            if isinstance(payload, str):
                payload_cfg = PayloadConfig(name=payload[:30], value=payload)
            else:
                payload_cfg = payload

            # Build request based on method
            if generic.method.upper() == "GET":
                request = self._build_get_request(endpoint_path, generic, payload_cfg)
            elif generic.method.upper() == "POST":
                request = self._build_post_request(endpoint_path, generic, payload_cfg)
            else:
                logger.warning(f"Unsupported method: {generic.method}")
                continue

            # Set matchers from generic config
            request.matchers = generic.matchers

            # Set on_match metadata
            request.on_match = {
                "vulnerability": template.id.replace("-", "_").upper(),
                "message": f"{template.info.name}: {payload_cfg.name}",
            }

            requests.append(request)

        return requests

    def _build_get_request(
        self,
        endpoint_path: str,
        generic: GenericTemplate,
        payload: PayloadConfig,
    ) -> RequestConfig:
        """Build a GET request from generic template config."""
        # Build URL with parameter and payload
        if generic.parameter:
            # For URL parameter injection: /endpoint?param=payload
            path = f"{endpoint_path}?{generic.parameter}={payload.value}"
        else:
            # For path injection or direct payload: /endpoint/payload
            # Check if endpoint already has a query string
            if "?" in endpoint_path:
                path = f"{endpoint_path}&{payload.value}"
            else:
                path = f"{endpoint_path}{payload.value}"

        return RequestConfig(
            name=payload.name,
            method="GET",
            path=path,
            headers=generic.headers.copy(),
            cookies={},
        )

    def _build_post_request(
        self,
        endpoint_path: str,
        generic: GenericTemplate,
        payload: PayloadConfig,
    ) -> RequestConfig:
        """Build a POST request from generic template config."""
        headers = generic.headers.copy()
        headers["Content-Type"] = generic.content_type

        if generic.body_template:
            # Use body template with {{payload}} placeholder
            body = generic.body_template.replace("{{payload}}", payload.value)
            # Also replace {{parameter}} if it exists
            if generic.parameter:
                body = body.replace("{{parameter}}", generic.parameter)
        elif generic.parameter:
            # Build form-encoded body
            body = f"{generic.parameter}={payload.value}"
        else:
            body = payload.value

        return RequestConfig(
            name=payload.name,
            method="POST",
            path=endpoint_path,
            headers=headers,
            body=body,
            cookies={},
        )

    def _get_endpoints_map(self) -> Dict[str, str]:
        """Get flattened endpoints map."""
        result = {}
        if self.target.endpoints:
            # Add custom endpoints
            for name, value in self.target.endpoints.custom.items():
                result[name] = value
        return result

    async def _execute_request(
        self,
        config: RequestConfig,
        context: ExecutionContext,
        template: Template,
    ) -> Optional[Finding]:
        """Execute a single HTTP request."""
        try:
            # Prepare request
            method = config.method
            path = context.interpolate(config.path)
            headers = self._prepare_headers(config, context)
            body = self._prepare_body(config, context)

            # Build kwargs
            kwargs: Dict[str, Any] = {"headers": headers}
            if body:
                if config.json:
                    kwargs["json"] = body
                else:
                    kwargs["content"] = body

            # Add auth headers and cookies
            if self._auth_context:
                kwargs["headers"].update(self._auth_context.headers)
                if self._auth_context.cookies:
                    kwargs["cookies"] = self._auth_context.cookies.copy()

            if config.cookies:
                if "cookies" not in kwargs:
                    kwargs["cookies"] = {}
                kwargs["cookies"].update(config.cookies)

            # Execute request
            client = self._get_client()
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

            # Check matchers
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
                    return self._create_finding(config, template, response, result)

        except httpx.HTTPError:
            pass  # Silently handle HTTP errors

        except Exception:
            pass  # Silently handle other errors

        return None

    def _prepare_headers(self, config: RequestConfig, context: ExecutionContext) -> Dict[str, str]:
        """Prepare request headers with interpolation."""
        headers = {}
        for key, value in config.headers.items():
            headers[key] = context.interpolate(value)
        return headers

    def _prepare_body(self, config: RequestConfig, context: ExecutionContext) -> Any:
        """Prepare request body with interpolation."""
        if config.json:
            # Interpolate JSON body
            json_str = json.dumps(config.json)
            json_str = context.interpolate(json_str)
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                return config.json

        if config.body:
            return context.interpolate(config.body)

        return None

    def _create_finding(
        self,
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

        return Finding(
            template_id=template.id,
            vulnerability_type=on_match.get("vulnerability") or template.id.replace("-", "_"),
            severity=template.info.severity,
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


def load_templates(template_dir: Path) -> List[Template]:
    """Load all templates from directory."""
    templates = []
    skipped = 0

    for yaml_file in template_dir.rglob("*.yaml"):
        try:
            template = Template.from_yaml(yaml_file)
            templates.append(template)
            logger.debug(f"Loaded template: {template.id}")
        except Exception as e:
            skipped += 1
            logger.warning(f"Skipping invalid template {yaml_file.name}: {e}")

    logger.info(f"Loaded {len(templates)} templates ({skipped} skipped)")
    return templates


async def run_scan(
    target: TargetConfig,
    templates: List[Template],
    validate_target: bool = True,
) -> ScanReport:
    """Run a complete vulnerability scan."""
    import time

    start_time = time.time()
    target_url = sanitize_url(target.base_url)

    logger.info(f"Starting scan against {target_url}")
    logger.info(f"Templates to execute: {len(templates)}")

    report = ScanReport(target=target.base_url, templates_executed=len(templates))

    engine = TemplateEngine(target, validate_target=validate_target)

    try:
        await engine.initialize()

        for i, template in enumerate(templates, 1):
            logger.info(f"[{i}/{len(templates)}] {template.id}: {template.info.name}")
            try:
                await engine.execute_template(template, report)
            except Exception as e:
                logger.error(f"Template {template.id} failed: {e}")
                report.add_error(f"Template {template.id} failed: {e}")

    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        report.add_error("Scan interrupted by user")
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        report.add_error(f"Scan failed: {e}")
    finally:
        await engine.close()

    report.duration_seconds = time.time() - start_time

    # Log summary
    logger.info(f"Scan completed in {report.duration_seconds:.1f}s")
    logger.info(f"Findings: {len(report.findings)} total "
                f"(Critical: {report.critical_count}, "
                f"High: {report.high_count}, "
                f"Medium: {report.medium_count}, "
                f"Low: {report.low_count})")

    if report.errors:
        logger.warning(f"Errors encountered: {len(report.errors)}")

    return report
