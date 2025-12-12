"""Template execution engine for DAST scanning."""

import json
import random
import re
import string
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from dast.auth import Authenticator, AuthContext
from dast.config import (
    ExtractorConfig,
    Finding,
    RequestConfig,
    ScanReport,
    TargetConfig,
    Template,
    EvidenceStrength,
)
from dast.extractors import create_extractor, extract_all
from dast.matchers import Matcher, create_matcher, evaluate_matchers, MatchResult


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

    def __init__(self, target: TargetConfig):
        self.target = target
        self.authenticator = Authenticator(target.base_url, target.timeout)
        self._auth_context: Optional[AuthContext] = None
        self._client: Optional[httpx.AsyncClient] = None

    async def initialize(self) -> None:
        """Initialize authentication."""
        if self.target.authentication:
            self._auth_context = await self.authenticator.authenticate(
                self.target.authentication
            )

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
        # Create execution context
        context = ExecutionContext(
            variables=self.target.variables.copy(),
            endpoints=self._get_endpoints_map(),
        )
        context.variables.update(template.variables)

        # Execute each request
        for request_config in template.requests:
            finding = await self._execute_request(request_config, context, template)
            if finding:
                report.add_finding(finding)

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

    for yaml_file in template_dir.rglob("*.yaml"):
        try:
            template = Template.from_yaml(yaml_file)
            templates.append(template)
        except Exception:
            pass  # Skip invalid templates

    return templates


async def run_scan(
    target: TargetConfig,
    templates: List[Template],
) -> ScanReport:
    """Run a complete vulnerability scan."""
    import time

    report = ScanReport(target=target.base_url, templates_executed=len(templates))
    start_time = time.time()

    engine = TemplateEngine(target)

    try:
        await engine.initialize()

        for template in templates:
            try:
                await engine.execute_template(template, report)
            except Exception as e:
                report.add_error(f"Template {template.id} failed: {e}")

    finally:
        await engine.close()

    report.duration_seconds = time.time() - start_time
    return report
