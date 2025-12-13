"""Template execution engine for DAST scanning."""

import asyncio
import json
import random
import re
import string
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from dast.auth import Authenticator, AuthContext
from dast.config import (
    DetectionTier,
    Finding,
    GenericTemplate,
    PayloadConfig,
    RequestConfig,
    ScanProfile,
    ScanReport,
    TargetConfig,
    Template,
    EvidenceStrength,
)
from dast.extractors import create_extractor
from dast.jwt import JWTForge
from dast.matchers import MatchResult, create_matcher, evaluate_matchers
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
        token = self.variables.get(token_var.strip(), token_var)
        try:
            return JWTForge.change_algorithm(token, "none")
        except Exception:
            return token

    def _jwt_admin(self, token_var: str) -> str:
        """Apply jwt_admin transformation to a variable."""
        token = self.variables.get(token_var.strip(), token_var)
        try:
            return JWTForge.set_admin_role(token, "role")
        except Exception:
            return token

    def _jwt_claim(self, token_var: str, claim: str, value: str) -> str:
        """Apply jwt_claim transformation to a variable."""
        token = self.variables.get(token_var.strip(), token_var)
        claim = claim.strip().strip('"\'')
        value = value.strip().strip('"\'')
        try:
            return JWTForge.modify_claim(token, claim, value)
        except Exception:
            return token

    def _jwt_no_exp(self, token_var: str) -> str:
        """Apply jwt_no_exp transformation to a variable."""
        token = self.variables.get(token_var.strip(), token_var)
        try:
            return JWTForge.remove_expiration(token)
        except Exception:
            return token

    def _jwt_weak_sign(self, token_var: str, secret: str) -> str:
        """Apply jwt_weak_sign transformation to a variable."""
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

    # Tier mapping: which tiers run for each profile
    PROFILE_TIERS = {
        ScanProfile.PASSIVE: [DetectionTier.PASSIVE],
        ScanProfile.STANDARD: [DetectionTier.PASSIVE, DetectionTier.ACTIVE],
        ScanProfile.THOROUGH: [DetectionTier.PASSIVE, DetectionTier.ACTIVE, DetectionTier.AGGRESSIVE],
        ScanProfile.AGGRESSIVE: [DetectionTier.PASSIVE, DetectionTier.ACTIVE, DetectionTier.AGGRESSIVE],
    }

    def __init__(
        self,
        target: TargetConfig,
        validate_target: bool = True,
        scan_profile: ScanProfile = ScanProfile.STANDARD,
    ):
        self.target = target
        self.scan_profile = scan_profile
        self.authenticator = Authenticator(target.base_url, target.timeout)
        self._auth_context: Optional[AuthContext] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._validate_target = validate_target
        self._connectivity_check: Optional[Dict[str, Any]] = None
        self._response_cache: Dict[str, httpx.Response] = {}
        self._semaphore = asyncio.Semaphore(max(1, target.parallel))
        self._request_delay = target.request_delay

    async def _acquire_slot(self):
        """Acquire a concurrency slot and apply delay if configured."""
        await self._semaphore.acquire()
        if self._request_delay > 0:
            await asyncio.sleep(self._request_delay)

    def _release_slot(self):
        """Release a concurrency slot."""
        self._semaphore.release()

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

        # Reset response cache for this template
        self._response_cache = {}

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

    def _load_payloads_from_file(self, file_path: str) -> List[str]:
        """Load payloads from an external text file.

        Each line is a payload. Lines starting with # are comments.
        Empty lines are ignored.

        Args:
            file_path: Path to the payload file (relative to project root or absolute)

        Returns:
            List of payload strings

        Raises:
            ValueError: If path attempts directory traversal
        """
        project_root = Path(__file__).parent.parent.resolve()
        payloads_dir = project_root / "payloads"

        path = Path(file_path)
        if not path.is_absolute():
            # Try relative to project root first
            path = (project_root / file_path).resolve()
        else:
            path = path.resolve()

        # Security: Validate path is within allowed directories
        # Allow: project_root/payloads/ OR project_root/ (for files in root)
        if not (path.is_relative_to(payloads_dir) or path.is_relative_to(project_root)):
            raise ValueError(
                f"Payload file path validation failed: {file_path} "
                f"(resolved to {path}) is outside allowed directories"
            )

        if not path.exists():
            logger.warning(f"Payload file not found: {file_path}")
            return []

        payloads = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if not line or line.startswith("#"):
                        continue
                    payloads.append(line)
            logger.debug(f"Loaded {len(payloads)} payloads from {file_path}")
        except Exception as e:
            logger.error(f"Failed to load payload file {file_path}: {e}")

        return payloads

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
        Supports detection_tiers for layered vulnerability scanning.
        Also supports automatic boolean-blind detection via naming convention.
        Supports loading payloads from external files.
        """
        generic = template.generic
        if not generic:
            return template.requests

        # Resolve endpoint from target config
        endpoints = self.target.get_endpoints()
        endpoint_key = generic.endpoint.lstrip("{{").rstrip("}}")
        endpoint_path = endpoints.get(endpoint_key)

        if not endpoint_path:
            logger.warning(f"Endpoint '{generic.endpoint}' not found in target config, skipping template")
            return []

        requests = []

        # Check if template uses detection_tiers
        if generic.detection_tiers:
            return self._expand_with_tiers(template, endpoint_path, generic)

        # Load payloads from file if specified
        payloads_to_use = list(generic.payloads)
        if generic.payloads_file:
            file_payloads = self._load_payloads_from_file(generic.payloads_file)
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
                request = self._build_get_request(endpoint_path, generic, payload_cfg)
            elif generic.method.upper() == "POST":
                request = self._build_post_request(endpoint_path, generic, payload_cfg)
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

    def _expand_with_tiers(
        self,
        template: Template,
        endpoint_path: str,
        generic: GenericTemplate,
    ) -> List[RequestConfig]:
        """Expand template using detection_tiers approach.

        Filters tiers based on scan_profile and generates appropriate requests.
        """
        requests = []
        allowed_tiers = self.PROFILE_TIERS.get(self.scan_profile, [DetectionTier.PASSIVE])

        for tier_config in generic.detection_tiers:
            tier = tier_config.get_tier()

            # Skip tiers not allowed by current scan profile
            if tier not in allowed_tiers:
                logger.debug(f"Skipping {tier.value} tier (scan_profile: {self.scan_profile.value})")
                continue

            # Warn about aggressive tiers
            if tier == DetectionTier.AGGRESSIVE:
                logger.warning("Running aggressive detection tier - may cause delays")

            detection_type = tier_config.detection_type or "error_based"

            if detection_type == "boolean_blind":
                # Boolean-blind: need baseline, true, and false payloads
                requests.extend(self._build_boolean_blind_requests(
                    template, endpoint_path, generic, tier_config
                ))
            elif detection_type == "time_blind":
                # Time-blind: single request with delay
                requests.extend(self._build_time_blind_requests(
                    template, endpoint_path, generic, tier_config
                ))
            else:
                # Error-based: use payloads list with tier matchers
                requests.extend(self._build_error_based_requests(
                    template, endpoint_path, generic, tier_config
                ))

        return requests

    def _build_error_based_requests(
        self,
        template: Template,
        endpoint_path: str,
        generic: GenericTemplate,
        tier_config,
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
                request = self._build_get_request(endpoint_path, generic, payload_cfg)
            elif generic.method.upper() == "POST":
                request = self._build_post_request(endpoint_path, generic, payload_cfg)
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

    def _build_boolean_blind_requests(
        self,
        template: Template,
        endpoint_path: str,
        generic: GenericTemplate,
        tier_config,
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
            baseline_req = self._build_get_request(endpoint_path, generic, baseline_cfg)
        else:
            baseline_req = self._build_post_request(endpoint_path, generic, baseline_cfg)

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
                true_req = self._build_get_request(endpoint_path, generic, true_cfg)
            else:
                true_req = self._build_post_request(endpoint_path, generic, true_cfg)

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
                false_req = self._build_get_request(endpoint_path, generic, false_cfg)
            else:
                false_req = self._build_post_request(endpoint_path, generic, false_cfg)

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

    def _build_time_blind_requests(
        self,
        template: Template,
        endpoint_path: str,
        generic: GenericTemplate,
        tier_config,
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
                request = self._build_get_request(endpoint_path, generic, payload_cfg)
            elif generic.method.upper() == "POST":
                request = self._build_post_request(endpoint_path, generic, payload_cfg)
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

    def _build_get_request(
        self,
        endpoint_path: str,
        generic: GenericTemplate,
        payload: PayloadConfig,
    ) -> RequestConfig:
        """Build a GET request from generic template config."""
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
        """Execute a single HTTP request with concurrency control."""
        await self._acquire_slot()
        try:
            # Prepare request
            method = config.method
            path = context.interpolate(config.path)
            headers = self._prepare_headers(config, context)
            body = self._prepare_body(config, context)

            # Build kwargs
            kwargs: Dict[str, Any] = {"headers": headers}
            if body:
                if config.json_body:
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

            # Cache response for boolean-blind comparison
            on_match = config.on_match or {}
            if on_match.get("cache_key"):
                self._response_cache[on_match["cache_key"]] = response
                # Baseline requests don't trigger findings
                if on_match.get("is_baseline"):
                    return None

            # Handle boolean-blind detection (compare with baseline)
            if on_match.get("compare_with"):
                cache_key = on_match["compare_with"]
                if cache_key in self._response_cache:
                    baseline_response = self._response_cache[cache_key]
                    # Compare responses - they must be different for boolean-blind SQLi
                    if self._responses_differ(baseline_response, response):
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
                        return self._create_finding(config, template, response, result)
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
                    return self._create_finding(config, template, response, result)

        except httpx.HTTPError as e:
            logger.debug(f"HTTP error during request: {e}")

        except Exception as e:
            logger.debug(f"Unexpected error during request: {type(e).__name__}: {e}")

        finally:
            # Always release the semaphore slot
            self._release_slot()

        return None

    def _responses_differ(self, response1: httpx.Response, response2: httpx.Response) -> bool:
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
        threshold = self.target.boolean_diff_threshold
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

    def _prepare_headers(self, config: RequestConfig, context: ExecutionContext) -> Dict[str, str]:
        """Prepare request headers with interpolation."""
        headers = {}
        for key, value in config.headers.items():
            headers[key] = context.interpolate(value)
        return headers

    def _prepare_body(self, config: RequestConfig, context: ExecutionContext) -> Any:
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
    """Load all templates from directory or single file."""
    templates = []
    skipped = 0

    # Handle single file vs directory
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
            logger.warning(f"Skipping invalid template {yaml_file.name}: {e}")

    logger.info(f"Loaded {len(templates)} templates ({skipped} skipped)")
    return templates


async def run_scan(
    target: TargetConfig,
    templates: List[Template],
    validate_target: bool = True,
    scan_profile: ScanProfile = ScanProfile.STANDARD,
    checkpoint_file: Optional[str] = None,
) -> ScanReport:
    """Run a complete vulnerability scan with optional resume capability."""
    start_time = time.time()
    target_url = sanitize_url(target.base_url)

    # Try to load from checkpoint if specified
    if checkpoint_file:
        report = ScanReport.load_checkpoint(checkpoint_file)
        if report:
            logger.info(f"Resuming scan from checkpoint: {checkpoint_file}")
            logger.info(f"Already completed {len(report.completed_templates)} templates")
        else:
            logger.info(f"Starting new scan with checkpoint: {checkpoint_file}")
            report = ScanReport(
                target=target.base_url,
                templates_executed=len(templates),
                checkpoint_file=checkpoint_file,
            )
    else:
        logger.info(f"Starting scan against {target_url} (profile: {scan_profile.value})")
        logger.info(f"Templates to execute: {len(templates)}")
        report = ScanReport(target=target.base_url, templates_executed=len(templates))

    engine = TemplateEngine(target, validate_target=validate_target, scan_profile=scan_profile)

    try:
        await engine.initialize()

        for i, template in enumerate(templates, 1):
            # Skip if already completed in checkpoint
            if report.is_template_completed(template.id):
                logger.debug(f"Skipping completed template: {template.id}")
                continue

            logger.info(f"[{i}/{len(templates)}] {template.id}: {template.info.name}")
            try:
                await engine.execute_template(template, report)
                # Mark template as completed and save checkpoint
                report.mark_template_completed(template.id)
            except Exception as e:
                logger.error(f"Template {template.id} failed: {e}")
                report.add_error(f"Template {template.id} failed: {e}")
                # Still save checkpoint on error
                report.mark_template_completed(template.id)

    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        report.add_error("Scan interrupted by user")
        report.save_checkpoint()  # Save on interrupt
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        report.add_error(f"Scan failed: {e}")
        report.save_checkpoint()  # Save on failure
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
